"""One command-line front end for the whole capstone system (plan step 3 in
docs/post-review-fixes.md, built 2026-11-20).

Everything here was already runnable by hand (docs/common-commands.md is the
manual version). The runner exists so a viewer (the student, the advisor, a
grader) can drive the system without knowing the commands, and still *see*
them: every subcommand prints each underlying shell command as a
copy-pasteable `$ ...` line before running it. `--dry-run` prints those lines
and stops, which is handy for slides and demos.

Design rules:
- Standard library only, so it runs with the system `python3`. It never
  imports a subproject; it calls each subproject's own venv Python as a
  separate process, the same pattern attacker-pipeline/harness/defender.py
  uses to launch the defensive agent.
- It doesn't change how any subproject works. It only calls them.
- Command *building* is kept separate from command *running*: the `*_steps()`
  functions return plain `Step` objects (argv + cwd + env), and only
  `execute()` touches the system. That split is what lets
  runner/tests/test_runner.py check every command offline.

Usage: python3 runner/runner.py --help
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime

# --- Paths -----------------------------------------------------------------
# Anchored to this file, not cwd, so the runner works from any directory.

RUNNER_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(RUNNER_DIR)
WAF_DIR = os.path.join(REPO_ROOT, "waf-defense")
MCP_DIR = os.path.join(REPO_ROOT, "mcp-server")
AGENT_DIR = os.path.join(REPO_ROOT, "defensive-agent")
ATTACKER_DIR = os.path.join(REPO_ROOT, "attacker-pipeline")
COMPOSE_FILE = os.path.join(WAF_DIR, "docker-compose.yml")
METRICS_DIR = os.path.join(ATTACKER_DIR, "metrics")

# Runner-owned files (gitignored): the background server's PID and log, and
# `run --tee` transcripts when no path is given.
STATE_DIR = os.path.join(RUNNER_DIR, "state")
SERVER_PID_FILE = os.path.join(STATE_DIR, "mcp-server.pid")
SERVER_LOG_FILE = os.path.join(STATE_DIR, "mcp-server.log")
TRANSCRIPT_DIR = os.path.join(STATE_DIR, "transcripts")

# Each subproject's venv interpreter. Relative form for display (paired with
# a `cd` into the subproject), absolute form for actually running it.
VENV_PYTHON_REL = ".venv/bin/python"

# Service endpoints. Defaults match the subprojects' own config.py files;
# the same env-var overrides are honoured so the runner never disagrees with
# them. (Duplicated rather than imported: importing a subproject's config
# would need that subproject's venv, which plain python3 doesn't have.)
MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", 8000))
MCP_URL = f"http://{MCP_HOST}:{MCP_PORT}/mcp"
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")
CONTAINERS = ("waf", "juice-shop")  # container_name values in docker-compose.yml

# Subprojects whose unit tests `test` runs, in the order it runs them.
TEST_SUITES = (("mcp-server", MCP_DIR), ("defensive-agent", AGENT_DIR),
               ("attacker-pipeline", ATTACKER_DIR))

# Custom (AI-written) rule IDs start here; mirrors CUSTOM_RULE_ID_MIN in
# mcp-server/config.py. Used only by `summary` to attribute 403s.
AI_RULE_ID_MIN = 1000000

SERVER_START_TIMEOUT = 20  # seconds to wait for the MCP port after `server start`
SERVER_STOP_TIMEOUT = 10


# --- Command model -----------------------------------------------------------

@dataclass
class Step:
    """One shell command the runner will show and then run.

    `argv` is what actually executes (absolute paths); `display` is the
    copy-pasteable line the viewer sees. The two are built together in
    `_step()` so they can't drift apart: the display is just argv with the
    cwd turned into a `cd ... &&` prefix and paths under $HOME shortened to ~.
    """
    why: str                 # one-line plain-English description, printed above the command
    argv: list[str]
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)  # extra env vars on top of os.environ
    display: str = ""
    tee: str | None = None   # also copy combined stdout/stderr to this file


def _short(path: str) -> str:
    """Shorten a path under $HOME to ~/..., which bash still expands, so the
    printed command stays both readable and runnable."""
    home = os.path.expanduser("~")
    if path == home or path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def _quote(arg: str) -> str:
    """shlex.quote, but leave a leading ~/ unquoted so bash still expands it."""
    if arg.startswith("~/"):
        rest = arg[2:]
        return "~/" + (rest if shlex.quote(rest) == rest else shlex.quote(rest))
    return shlex.quote(arg)


def _step(why: str, argv: list[str], cwd: str | None = None, env: dict | None = None,
          tee: str | None = None, display_argv: list[str] | None = None,
          suffix: str = "") -> Step:
    """Build a Step and its display line.

    display_argv lets a caller show a friendlier but equivalent spelling
    (e.g. `.venv/bin/python` after a `cd`, instead of the absolute path).
    suffix is appended verbatim (used for redirections like `> log 2>&1 &`).
    """
    env = env or {}
    shown = display_argv if display_argv is not None else argv
    parts = []
    if cwd:
        parts.append(f"cd {_quote(_short(cwd))} &&")
    parts += [f"{k}={shlex.quote(v)}" for k, v in env.items()]
    parts += [_quote(_short(a)) for a in shown]
    line = " ".join(parts) + suffix
    if tee:
        line += f" 2>&1 | tee {_quote(_short(tee))}"
    return Step(why=why, argv=argv, cwd=cwd, env=env, display=line, tee=tee)


def _venv_step(why: str, subdir: str, args: list[str], env: dict | None = None,
               tee: str | None = None, suffix: str = "") -> Step:
    """A command run with a subproject's own venv Python, from that subproject's root."""
    return _step(why, [os.path.join(subdir, VENV_PYTHON_REL), *args], cwd=subdir, env=env,
                 tee=tee, display_argv=[VENV_PYTHON_REL, *args], suffix=suffix)


# --- Output / execution --------------------------------------------------------

def say(tag: str, msg: str) -> None:
    print(f"[{tag}] {msg}", flush=True)


def show(step: Step, tag: str) -> None:
    say(tag, step.why)
    print(f"      $ {step.display}", flush=True)


def execute(step: Step, tag: str, dry_run: bool, capture: bool = False,
            check: bool = False) -> subprocess.CompletedProcess | None:
    """Print a step, then run it (unless dry_run). Returns None on dry runs.

    capture=True collects stdout as text (used by checks that parse output);
    otherwise output streams straight to the terminal, so interactive
    prompts (sudo's password prompt in `reset`) work normally.
    """
    show(step, tag)
    if dry_run:
        return None
    env = {**os.environ, **step.env}
    if step.tee:
        return _run_tee(step, env)
    try:
        return subprocess.run(step.argv, cwd=step.cwd, env=env, check=check,
                              capture_output=capture, text=capture)
    except FileNotFoundError as exc:
        # e.g. docker/curl not installed, or a subproject venv missing.
        say(tag, f"could not start: {exc}")
        return subprocess.CompletedProcess(step.argv, 127, "", str(exc))


def _run_tee(step: Step, env: dict) -> subprocess.CompletedProcess:
    """`cmd 2>&1 | tee file`, in Python: stream each line to the terminal and the file."""
    os.makedirs(os.path.dirname(step.tee) or ".", exist_ok=True)
    with open(step.tee, "w") as out, subprocess.Popen(
            step.argv, cwd=step.cwd, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1) as proc:
        # Header so a saved transcript records which command produced it: the
        # runner's own "$ ..." line goes to the screen, not through the child.
        out.write(f"# {datetime.now().isoformat(timespec='seconds')}\n")
        out.write(f"$ {step.display}\n\n")
        out.flush()
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            out.write(line)
        proc.wait()
    return subprocess.CompletedProcess(step.argv, proc.returncode)


# --- Builders: one per subcommand (pure, offline-testable) -------------------

def compose_steps(action: str) -> list[Step]:
    """`up` / `down` for the WAF + Juice Shop containers."""
    if action == "up":
        return [_step("start the WAF and Juice Shop containers (detached)",
                      ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"])]
    return [_step("stop and remove the containers + network (images kept, so the next `up` is fast)",
                  ["docker", "compose", "-f", COMPOSE_FILE, "down"])]


def docker_check_step() -> Step:
    fmt = "{{.Name}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}"
    return _step("are the WAF and Juice Shop containers running?",
                 ["docker", "inspect", "-f", fmt, *CONTAINERS])


def ollama_check_step() -> Step:
    return _step(f"is Ollama up, and is the `{OLLAMA_MODEL}` model pulled?",
                 ["curl", "-s", "-m", "5", f"{OLLAMA_HOST}/api/tags"])


def mcp_probe_step() -> Step:
    # Any HTTP status (the MCP endpoint answers a bare GET with a 4xx) means
    # something is listening; curl prints 000 when nothing answers.
    return _step(f"is the MCP server answering on {MCP_HOST}:{MCP_PORT}?",
                 ["curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", MCP_URL])


def reset_steps() -> list[Step]:
    """Mirror of docs/common-commands.md "Resetting to a clean slate"."""
    return [
        _venv_step("clear AI rules, truncate WAF logs (sudo will ask for your password), "
                   "delete the breach-tally state", MCP_DIR, ["reset_state.py"]),
        _step("reload nginx so the WAF drops the cleared rules",
              ["docker", "exec", "waf", "nginx", "-s", "reload"]),
    ]


def server_start_step() -> Step:
    # The display shows the shell equivalent of what start_server() does with
    # Popen: unbuffered (so startup lines reach the log immediately), detached,
    # output to the runner's log file.
    return _venv_step("start the MCP server in the background", MCP_DIR, ["server.py"],
                      env={"PYTHONUNBUFFERED": "1"},
                      suffix=f" > {_quote(_short(SERVER_LOG_FILE))} 2>&1 &")


def run_steps(waves: int | None = None, wave_size: int | None = None,
              pause: int | None = None, label: str | None = None, defend: bool = False,
              adaptive: bool = False, tee: str | None = None,
              adaptive_debug: bool = False) -> list[Step]:
    """Build the attacker-pipeline run.py invocation. Unset options are left
    off, so run.py falls back to config.py's defaults (5 waves x 50, 60 s pause)."""
    args = ["run.py"]
    if waves is not None:
        args += ["--waves", str(waves)]
    if wave_size is not None:
        args += ["--wave-size", str(wave_size)]
    if pause is not None:
        args += ["--pause", str(pause)]
    if label:
        args += ["--label", label]
    if defend:
        args.append("--defend")
    if adaptive:
        args.append("--adaptive")
    # Unbuffered so wave progress (and the agent subprocess's output, which
    # inherits this env) shows up live, including through tee.
    env = {"PYTHONUNBUFFERED": "1"}
    if adaptive_debug:
        env["ADAPTIVE_DEBUG"] = "1"
    mode = []
    if defend:
        mode.append("closed loop")
    if adaptive:
        mode.append("adaptive attacker")
    why = "fire attack waves" + (f" ({', '.join(mode)})" if mode else "") + \
          "; unset options use config.py defaults"
    return [_venv_step(why, ATTACKER_DIR, args, env=env, tee=tee)]


def default_tee_path(label: str | None, now: datetime | None = None) -> str:
    """Where `run --tee` (with no path) saves the console transcript."""
    stamp = (now or datetime.now()).strftime("%Y%m%d_%H%M%S")
    return os.path.join(TRANSCRIPT_DIR, f"{label or 'run'}-{stamp}.txt")


def test_steps() -> list[tuple[str, Step]]:
    """One unittest-discover step per subproject (each in its own venv), plus
    the runner's own tests, which need only plain python3."""
    steps = [(name, _venv_step(f"{name} unit tests (offline)", path,
                               ["-m", "unittest", "discover", "-s", "tests", "-t", "."]))
             for name, path in TEST_SUITES]
    steps.append(("runner", _step("runner unit tests (offline)",
                                  ["python3", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                                  cwd=RUNNER_DIR)))
    return steps


def analyze_step(csv_path: str) -> Step:
    return _venv_step("bypass-pattern analysis (attacker-pipeline/analyze.py)",
                      ATTACKER_DIR, ["analyze.py", csv_path])


# --- Pure helpers used by check / summary -------------------------------------

def parse_docker_inspect(stdout: str) -> dict[str, str]:
    """`/waf running healthy` lines -> {"waf": "running healthy"}."""
    out = {}
    for line in stdout.splitlines():
        parts = line.strip().split(None, 1)
        if parts:
            out[parts[0].lstrip("/")] = parts[1].strip() if len(parts) > 1 else ""
    return out


def ollama_has_model(tags_json: str, model: str) -> bool:
    """True if /api/tags lists `model` (tags come back as e.g. `llama3:latest`)."""
    try:
        names = [m.get("name", "") for m in json.loads(tags_json).get("models", [])]
    except (ValueError, AttributeError):
        return False
    return any(n == model or n.startswith(model + ":") for n in names)


def anthropic_key_status(environ: dict, env_file: str) -> tuple[bool, str]:
    """Is ANTHROPIC_API_KEY set, and where? Never returns the value itself.

    Checks the environment first, then defensive-agent/.env (where the agent's
    python-dotenv loads it from; a real environment variable wins there too).
    """
    if environ.get("ANTHROPIC_API_KEY", "").strip():
        return True, "environment"
    try:
        with open(env_file) as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep and key.strip().removeprefix("export ").strip() == "ANTHROPIC_API_KEY" \
                        and value.strip().strip("'\""):
                    return True, _short(env_file)
    except OSError:
        pass
    return False, "not in environment or " + _short(env_file)


def latest_metrics_csv(metrics_dir: str = METRICS_DIR) -> str | None:
    """Newest wave CSV by mtime (not by name: labels sort before timestamps),
    skipping the paired `_agent.csv` files, which have a different schema."""
    candidates = [p for p in glob.glob(os.path.join(metrics_dir, "*.csv"))
                  if not p.endswith("_agent.csv")]
    return max(candidates, key=os.path.getmtime) if candidates else None


def per_wave_summary(rows: list[dict]) -> list[dict]:
    """Per wave: payloads, bypassed, bypass rate, and how many 403s were
    attributed to an AI rule (matched_rule_id >= 1000000). That last count is
    the AI rules' *marginal* catch: when CRS also matches, the log shows 949110
    instead (docs/post-review-fixes.md, "Finding that matters for RGI")."""
    waves: dict[int, dict] = {}
    for r in rows:
        w = waves.setdefault(int(r["wave_id"]), {"wave": int(r["wave_id"]), "total": 0,
                                                "bypassed": 0, "ai_rule_403s": 0})
        w["total"] += 1
        if str(r.get("blocked", "")).strip().lower() != "true":
            w["bypassed"] += 1
        rid = str(r.get("matched_rule_id") or "").strip()
        if rid.isdigit() and int(rid) >= AI_RULE_ID_MIN:
            w["ai_rule_403s"] += 1
    out = sorted(waves.values(), key=lambda w: w["wave"])
    for w in out:
        w["bypass_rate"] = w["bypassed"] / w["total"] if w["total"] else 0.0
    return out


def _read_csv(path: str) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


# --- Subcommand handlers -----------------------------------------------------

def cmd_compose(args) -> int:
    result = None
    for step in compose_steps(args.command):
        result = execute(step, args.command, args.dry_run)
    return 0 if result is None else result.returncode


def mcp_is_up(dry_run: bool, tag: str, quiet: bool = False) -> bool | None:
    """Probe the MCP port. None on dry runs (nothing was checked)."""
    step = mcp_probe_step()
    if quiet:
        if dry_run:
            return None
        res = subprocess.run(step.argv, capture_output=True, text=True)
    else:
        res = execute(step, tag, dry_run, capture=True)
        if res is None:
            return None
    return res.returncode == 0 and res.stdout.strip() not in ("", "000")


def cmd_check(args) -> int:
    results: list[tuple[str, bool | None, str]] = []

    res = execute(docker_check_step(), "check", args.dry_run, capture=True)
    if res is not None:
        states = parse_docker_inspect(res.stdout)
        ok = all(states.get(c, "").startswith("running") for c in CONTAINERS)
        detail = ", ".join(f"{c}: {states.get(c, 'missing')}" for c in CONTAINERS)
        if res.returncode and not states:
            detail = (res.stderr or "").strip().splitlines()[-1:] or ["docker not reachable"]
            detail = detail[0]
        results.append(("Docker (WAF + Juice Shop)", ok, detail))

    res = execute(ollama_check_step(), "check", args.dry_run, capture=True)
    if res is not None:
        if res.returncode or not res.stdout:
            results.append((f"Ollama + {OLLAMA_MODEL}", False, f"no answer from {OLLAMA_HOST}"))
        else:
            has = ollama_has_model(res.stdout, OLLAMA_MODEL)
            results.append((f"Ollama + {OLLAMA_MODEL}", has,
                            "up, model pulled" if has else f"up, but `{OLLAMA_MODEL}` not pulled"))

    up = mcp_is_up(args.dry_run, "check")
    if up is not None:
        results.append(("MCP server", up, MCP_URL if up else
                        "not answering (start it: runner.py server start)"))

    env_file = os.path.join(AGENT_DIR, ".env")
    say("check", f"is ANTHROPIC_API_KEY set? (in-process: looks in the environment, then "
                 f"{_short(env_file)}; the value is never printed)")
    if not args.dry_run:
        is_set, where = anthropic_key_status(dict(os.environ), env_file)
        results.append(("Anthropic API key", is_set, f"set ({where})" if is_set else where))

    if args.dry_run:
        return 0
    print()
    for name, ok, detail in results:
        print(f"  {'OK  ' if ok else 'FAIL'}  {name:<28} {detail}")
    return 0 if all(ok for _, ok, _ in results) else 1


def _read_pid() -> int | None:
    try:
        with open(SERVER_PID_FILE) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # signal 0: existence check only, nothing is sent
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def server_start(args) -> int:
    step = server_start_step()
    if not args.dry_run:
        pid = _read_pid()
        if (pid and _pid_alive(pid)) or mcp_is_up(False, "server", quiet=True):
            say("server", "already running" + (f" (pid {pid})" if pid else
                                                 ", but not started by the runner") +
                ". Use `server restart` to pick up a reset.")
            return 1
    show(step, "server")
    if args.dry_run:
        return 0
    os.makedirs(STATE_DIR, exist_ok=True)
    log = open(SERVER_LOG_FILE, "w")
    # start_new_session detaches it from this terminal, like nohup ... &, so it
    # keeps running after the runner exits and Ctrl+C here doesn't reach it.
    proc = subprocess.Popen(step.argv, cwd=step.cwd, env={**os.environ, **step.env},
                            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                            start_new_session=True)
    log.close()
    with open(SERVER_PID_FILE, "w") as f:
        f.write(str(proc.pid))
    say("server", f"pid {proc.pid}; waiting up to {SERVER_START_TIMEOUT}s for {MCP_URL} ...")
    deadline = time.time() + SERVER_START_TIMEOUT
    up = False
    while time.time() < deadline and proc.poll() is None:
        if mcp_is_up(False, "server", quiet=True):
            up = True
            break
        time.sleep(0.5)
    # Show the startup lines: the per-log offset lines, and especially any
    # "file already has N bytes" warning, must stay visible (common-commands.md).
    say("server", f"startup output ({_short(SERVER_LOG_FILE)}):")
    with open(SERVER_LOG_FILE) as f:
        for line in f.read().splitlines()[:30]:
            print(f"      | {line}")
    if not up:
        say("server", "did NOT come up" + (f" (exited with code {proc.returncode})"
                                           if proc.poll() is not None else ""))
        return 1
    say("server", "up. Follow its log with: runner.py server log")
    return 0


def server_stop(args) -> int:
    pid = _read_pid()
    if pid is None or (not args.dry_run and not _pid_alive(pid)):
        if not args.dry_run and mcp_is_up(False, "server", quiet=True):
            say("server", "a server is answering but wasn't started by the runner; "
                          "stop it in its own terminal (Ctrl+C)")
            return 1
        say("server", "not running (no live pid in " + _short(SERVER_PID_FILE) + ")")
        if pid is not None and not args.dry_run:
            os.remove(SERVER_PID_FILE)
        return 0
    execute(_step("stop the background MCP server", ["kill", str(pid)]), "server", args.dry_run)
    if args.dry_run:
        return 0
    deadline = time.time() + SERVER_STOP_TIMEOUT
    while time.time() < deadline and _pid_alive(pid):
        time.sleep(0.25)
    if _pid_alive(pid):
        say("server", f"still alive after {SERVER_STOP_TIMEOUT}s; sending SIGKILL")
        os.kill(pid, signal.SIGKILL)
    os.remove(SERVER_PID_FILE)
    say("server", "stopped")
    return 0


def server_status(args) -> int:
    pid = _read_pid()
    up = mcp_is_up(args.dry_run, "server")
    if up is None:
        return 0
    who = (f"runner-started, pid {pid}" if pid and _pid_alive(pid)
           else "not started by the runner")
    say("server", f"{'UP' if up else 'DOWN'}" + (f" ({who})" if up else ""))
    return 0 if up else 1


def server_log(args) -> int:
    step = _step("follow the MCP server's log (Ctrl+C to stop following)",
                 ["tail", "-n", "40", "-f", SERVER_LOG_FILE])
    try:
        res = execute(step, "server", args.dry_run)
    except KeyboardInterrupt:
        return 0
    return 0 if res is None else res.returncode


def cmd_server(args) -> int:
    if args.action == "restart":
        rc = server_stop(args)
        return rc or server_start(args)
    return {"start": server_start, "stop": server_stop,
            "status": server_status, "log": server_log}[args.action](args)


def cmd_reset(args) -> int:
    was_up = None if args.dry_run else mcp_is_up(False, "reset", quiet=True)
    if args.restart_server and (args.dry_run or was_up) and server_stop(args):
        # A server the runner didn't start (e.g. one in another terminal) can't
        # be restarted from here; resetting under it would leave it stale.
        say("reset", "nothing reset. Stop that server (Ctrl+C), then rerun this")
        return 1
    for step in reset_steps():
        res = execute(step, "reset", args.dry_run)
        if res is not None and res.returncode:
            say("reset", f"failed (exit {res.returncode}); stopping here")
            return res.returncode
    if args.restart_server and (args.dry_run or was_up):
        return server_start(args)
    if was_up:
        say("reset", "WARNING: the MCP server is still running with its old in-memory "
                     "state. Restart it: runner.py server restart")
    return 0


def cmd_run(args) -> int:
    tee = None
    if args.tee is not None:
        tee = default_tee_path(args.label) if args.tee == "" else os.path.abspath(args.tee)
    if args.defend:
        up = mcp_is_up(args.dry_run, "run")
        if up is None:
            say("run", "(preflight skipped in dry-run)")
        elif not up:
            say("run", "--defend needs the MCP server, and it isn't answering. "
                       "Start it first: runner.py server start")
            return 1
    res = None
    for step in run_steps(args.waves, args.wave_size, args.pause, args.label, args.defend,
                          args.adaptive, tee, args.adaptive_debug):
        res = execute(step, "run", args.dry_run)
    if tee and not args.dry_run:
        say("run", f"transcript saved to {_short(tee)}")
    return 0 if res is None else res.returncode


def cmd_summary(args) -> int:
    path = os.path.abspath(args.csv) if args.csv else latest_metrics_csv()
    if not path:
        say("summary", f"no metrics CSVs in {_short(METRICS_DIR)}; run some waves first")
        return 1
    agent_path = path.removesuffix(".csv") + "_agent.csv"
    say("summary", f"reading {_short(path)} (in-process)")
    if not args.dry_run:
        waves = per_wave_summary(_read_csv(path))
        print(f"\n  {'wave':>4}  {'bypassed':>10}  {'rate':>6}  {'403s by AI rule':>15}")
        for w in waves:
            print(f"  {w['wave']:>4}  {w['bypassed']:>4}/{w['total']:<5}  "
                  f"{w['bypass_rate'] * 100:5.1f}%  {w['ai_rule_403s']:>15}")
        tot = sum(w["total"] for w in waves)
        byp = sum(w["bypassed"] for w in waves)
        print(f"  {'all':>4}  {byp:>4}/{tot:<5}  {(byp / tot * 100 if tot else 0):5.1f}%")
        print("  (AI-rule 403s count only what CRS missed: on a double match the log shows 949110)\n")
        if os.path.exists(agent_path):
            say("summary", f"defensive-agent passes from {_short(agent_path)}")
            print(f"\n  {'wave':>4}  {'endpoint':<24} {'rule_id':<8} {'verdict':<16} "
                  f"{'attempts':>8}  {'MTTM (s)':>8}")
            for r in _read_csv(agent_path):
                print(f"  {r['wave_id']:>4}  {r['endpoint']:<24} {r['rule_id'] or '-':<8} "
                      f"{r['verdict'][:16]:<16} {r['verify_attempts'] or '-':>8}  "
                      f"{r['mttm_seconds'] or '-':>8}")
            print()
        else:
            say("summary", "no _agent.csv next to it (a run without --defend)")
    res = execute(analyze_step(path), "summary", args.dry_run)
    return 0 if res is None else res.returncode


def cmd_test(args) -> int:
    outcomes = []
    for name, step in test_steps():
        res = execute(step, "test", args.dry_run)
        if res is not None:
            outcomes.append((name, res.returncode == 0))
        print()
    if args.dry_run:
        return 0
    for name, ok in outcomes:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    return 0 if all(ok for _, ok in outcomes) else 1


# --- CLI ----------------------------------------------------------------------

EPILOG = """\
typical fresh run, in order:
  runner.py check                      # is everything up?
  runner.py up                         # if Docker isn't
  runner.py reset                      # clean slate (sudo prompts), BEFORE the server starts
  runner.py server start               # MCP server must be up before traffic fires
  runner.py run --waves 3 --wave-size 20 --defend --label smoke --tee
  runner.py summary                    # newest run

Every command prints the exact shell command(s) it runs. Add --dry-run to
print them without running anything. Manual reference: docs/common-commands.md
"""


def build_parser() -> argparse.ArgumentParser:
    # --dry-run lives on a shared parent so it's accepted after any subcommand
    # (`runner.py run --dry-run`) as well as before it (`runner.py --dry-run run`).
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS,
                        help="print the commands without running them")

    p = argparse.ArgumentParser(
        prog="runner.py",
        description="Run the whole capstone system (WAF, MCP server, attacker, defender) "
                    "from one place, showing every underlying command.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter, parents=[common])
    sub = p.add_subparsers(dest="command", metavar="<command>", required=True)

    def add(name, help_, func, **kw):
        sp = sub.add_parser(name, help=help_, description=help_, parents=[common], **kw)
        sp.set_defaults(func=func)
        return sp

    add("up", "start the WAF + Juice Shop containers (docker compose up -d)", cmd_compose)
    add("down", "stop and remove the containers (docker compose down; images kept)", cmd_compose)
    add("check", "report whether Docker, Ollama + model, the MCP server, and the Anthropic "
                 "key are ready (the key's value is never printed)", cmd_check)

    sp = add("server", "manage the MCP server as a background process "
                       f"(PID + log in {_short(STATE_DIR)})", cmd_server)
    sp.add_argument("action", choices=["start", "stop", "restart", "status", "log"],
                    help="start: launch detached and show its startup lines; stop; restart "
                         "(after a reset); status; log: follow its output")

    sp = add("reset", "clean slate: clear AI rules, truncate WAF logs (sudo prompts), delete "
                      "breach state, reload nginx. Do this BEFORE starting the server", cmd_reset)
    sp.add_argument("--restart-server", action="store_true",
                    help="if the MCP server is running, stop it first and start it again after, "
                         "so it picks up the cleared state")

    sp = add("run", "fire attack waves via attacker-pipeline/run.py. Unset options use "
                    "config.py defaults: 5 waves x 50 payloads, 60 s pause", cmd_run)
    sp.add_argument("--waves", type=int, help="number of waves (default 5)")
    sp.add_argument("--wave-size", type=int, help="payloads per wave (default 50)")
    sp.add_argument("--pause", type=int, help="seconds between waves (default 60)")
    sp.add_argument("--label", help="tag for the output CSV name (run_<label>_<timestamp>.csv); "
                                    "use for anything that isn't real evaluation data")
    sp.add_argument("--defend", action="store_true",
                    help="closed loop: run the defensive agent after every wave "
                         "(needs the MCP server; checked before firing)")
    sp.add_argument("--adaptive", action="store_true",
                    help="adaptive attacker: feed each wave's 403/not-403 results back into "
                         "the next wave's mutation prompts (status codes only)")
    sp.add_argument("--adaptive-debug", action="store_true",
                    help="with --adaptive: print one `[mutate] adaptive:` line per seed "
                         "(sets ADAPTIVE_DEBUG=1)")
    sp.add_argument("--tee", nargs="?", const="", metavar="PATH",
                    help="also save the console output to PATH (no PATH: "
                         f"{_short(TRANSCRIPT_DIR)}/<label>-<timestamp>.txt)")

    sp = add("summary", "summarize a run: per-wave bypass rate, agent passes + MTTM, then "
                        "analyze.py's bypass-pattern report", cmd_summary)
    sp.add_argument("csv", nargs="?", help="a run's wave CSV (default: newest in "
                                           f"{_short(METRICS_DIR)}, by time)")

    add("test", "run every subproject's offline unit tests in its own venv, plus the "
                "runner's; PASS/FAIL per suite", cmd_test)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.dry_run = getattr(args, "dry_run", False)
    if args.dry_run:
        say("dry-run", "commands are printed, nothing is executed\n")
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print()
        say(args.command, "interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
