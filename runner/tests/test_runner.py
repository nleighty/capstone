"""Offline tests for runner.py's command building and parsing.

Nothing real runs here: the tests check the Step objects the builders return
(argv, cwd, env, and the printed display line), the pure parsing helpers, and
that --dry-run never calls subprocess. Run from runner/:
    python3 -m unittest discover -s tests -t .
"""

import io
import os
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from unittest import mock

import runner


class RunCommand(unittest.TestCase):
    def test_defend_adaptive_builds_exact_run_py_call(self):
        (step,) = runner.run_steps(defend=True, adaptive=True)
        self.assertEqual(step.argv, [os.path.join(runner.ATTACKER_DIR, ".venv/bin/python"),
                                     "run.py", "--defend", "--adaptive"])
        self.assertEqual(step.cwd, runner.ATTACKER_DIR)
        self.assertEqual(step.env, {"PYTHONUNBUFFERED": "1"})
        self.assertTrue(step.display.endswith(
            "&& PYTHONUNBUFFERED=1 .venv/bin/python run.py --defend --adaptive"))

    def test_unset_options_are_omitted_so_config_defaults_apply(self):
        (step,) = runner.run_steps()
        self.assertEqual(step.argv[1:], ["run.py"])

    def test_all_options_pass_through_in_order(self):
        (step,) = runner.run_steps(waves=1, wave_size=5, pause=0, label="smoke",
                                   defend=True, adaptive=True)
        self.assertEqual(step.argv[1:], ["run.py", "--waves", "1", "--wave-size", "5",
                                         "--pause", "0", "--label", "smoke",
                                         "--defend", "--adaptive"])

    def test_pause_zero_is_kept(self):
        # 0 is falsy; it must still be passed, or run.py would wait 60 s.
        (step,) = runner.run_steps(pause=0)
        self.assertIn("--pause", step.argv)

    def test_adaptive_debug_sets_env(self):
        (step,) = runner.run_steps(adaptive=True, adaptive_debug=True)
        self.assertEqual(step.env["ADAPTIVE_DEBUG"], "1")
        self.assertIn("ADAPTIVE_DEBUG=1", step.display)

    def test_tee_appears_in_display(self):
        (step,) = runner.run_steps(tee="/tmp/x.txt")
        self.assertEqual(step.tee, "/tmp/x.txt")
        self.assertTrue(step.display.endswith("2>&1 | tee /tmp/x.txt"))

    def test_label_with_spaces_is_quoted(self):
        (step,) = runner.run_steps(label="my run")
        self.assertIn("--label 'my run'", step.display)

    def test_default_tee_path(self):
        p = runner.default_tee_path("smoke", datetime(2026, 11, 20, 9, 5, 7))
        self.assertEqual(p, os.path.join(runner.TRANSCRIPT_DIR, "smoke-20261120_090507.txt"))
        self.assertTrue(os.path.basename(runner.default_tee_path(None)).startswith("run-"))


class TeeTranscript(unittest.TestCase):
    def test_transcript_starts_with_command_then_output(self):
        # Runs a harmless stand-in child process (no Docker/Ollama/Claude).
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "t.txt")  # also checks the folder gets created
            step = runner._step("stand-in", ["python3", "-c", "print('hello'); raise SystemExit(3)"],
                                tee=path)
            with redirect_stdout(io.StringIO()) as screen:
                res = runner._run_tee(step, dict(os.environ))
            with open(path) as f:
                lines = f.read().splitlines()
        self.assertTrue(lines[0].startswith("# "))           # timestamp
        self.assertEqual(lines[1], f"$ {step.display}")
        self.assertEqual(lines[3], "hello")                   # output follows a blank line
        self.assertEqual(screen.getvalue(), "hello\n")        # header is file-only
        self.assertEqual(res.returncode, 3)


class OtherCommands(unittest.TestCase):
    def test_up_down(self):
        (up,) = runner.compose_steps("up")
        (down,) = runner.compose_steps("down")
        self.assertEqual(up.argv, ["docker", "compose", "-f", runner.COMPOSE_FILE, "up", "-d"])
        self.assertEqual(down.argv[-1], "down")

    def test_reset_runs_reset_state_in_mcp_venv_then_reloads(self):
        reset, reload = runner.reset_steps()
        self.assertEqual(reset.cwd, runner.MCP_DIR)
        self.assertEqual(reset.argv, [os.path.join(runner.MCP_DIR, ".venv/bin/python"),
                                      "reset_state.py"])
        self.assertEqual(reload.argv, ["docker", "exec", "waf", "nginx", "-s", "reload"])

    def test_server_start_display_is_shell_equivalent(self):
        step = runner.server_start_step()
        self.assertEqual(step.argv[1:], ["server.py"])
        self.assertIn("PYTHONUNBUFFERED=1 .venv/bin/python server.py >", step.display)
        self.assertTrue(step.display.endswith("2>&1 &"))

    def test_test_steps_cover_three_subprojects_plus_runner(self):
        steps = runner.test_steps()
        self.assertEqual([n for n, _ in steps],
                         ["mcp-server", "defensive-agent", "attacker-pipeline", "runner"])
        for _name, step in steps[:3]:
            # Step.cwd is typed `str | None`; a venv step always sets it.
            assert step.cwd is not None
            self.assertEqual(step.argv[0], os.path.join(step.cwd, ".venv/bin/python"))
            self.assertEqual(step.argv[1:], ["-m", "unittest", "discover", "-s", "tests", "-t", "."])
        self.assertEqual(steps[3][1].argv[0], "python3")

    def test_analyze_step_passes_explicit_csv(self):
        step = runner.analyze_step("/x/run_a.csv")
        self.assertEqual(step.argv[1:], ["analyze.py", "/x/run_a.csv"])
        self.assertEqual(step.cwd, runner.ATTACKER_DIR)

    def test_mcp_probe_uses_configured_url(self):
        self.assertEqual(runner.mcp_probe_step().argv[-1], runner.MCP_URL)


class Display(unittest.TestCase):
    def test_home_paths_shortened_but_runnable(self):
        home = os.path.expanduser("~")
        self.assertEqual(runner._short(os.path.join(home, "a", "b")), "~/a/b")
        self.assertEqual(runner._short("/etc/x"), "/etc/x")
        self.assertEqual(runner._quote("~/a b"), "~/'a b'")


class Parsers(unittest.TestCase):
    def test_docker_inspect(self):
        out = "/waf running healthy\n/juice-shop running \n"
        self.assertEqual(runner.parse_docker_inspect(out),
                         {"waf": "running healthy", "juice-shop": "running"})

    def test_ollama_model_matching(self):
        tags = '{"models": [{"name": "llama3:latest"}, {"name": "mistral:7b"}]}'
        self.assertTrue(runner.ollama_has_model(tags, "llama3"))
        self.assertFalse(runner.ollama_has_model(tags, "llama3.1"))
        self.assertFalse(runner.ollama_has_model("not json", "llama3"))

    def test_anthropic_key_never_returns_value(self):
        with tempfile.TemporaryDirectory() as d:
            env_file = os.path.join(d, ".env")
            with open(env_file, "w") as f:
                f.write('# comment\nANTHROPIC_API_KEY="sk-secret-123"\n')
            ok, where = runner.anthropic_key_status({}, env_file)
            self.assertTrue(ok)
            self.assertNotIn("sk-secret", where)
            ok, where = runner.anthropic_key_status({"ANTHROPIC_API_KEY": "sk-x"}, env_file)
            self.assertEqual((ok, where), (True, "environment"))

    def test_anthropic_key_empty_or_missing(self):
        with tempfile.TemporaryDirectory() as d:
            env_file = os.path.join(d, ".env")
            with open(env_file, "w") as f:
                f.write("ANTHROPIC_API_KEY=\n")
            self.assertFalse(runner.anthropic_key_status({}, env_file)[0])
            self.assertFalse(runner.anthropic_key_status({}, os.path.join(d, "nope"))[0])

    def test_latest_csv_by_mtime_skipping_agent_csv(self):
        with tempfile.TemporaryDirectory() as d:
            def touch(name, t):
                p = os.path.join(d, name)
                open(p, "w").close()
                os.utime(p, (t, t))
                return p
            now = time.time()
            touch("run_zzz_20260101_000000.csv", now - 100)   # sorts last by name, but older
            newest = touch("run_aaa_20261120_000000.csv", now - 10)
            touch("run_aaa_20261120_000000_agent.csv", now)    # newest file, wrong schema
            self.assertEqual(runner.latest_metrics_csv(d), newest)
            self.assertIsNone(runner.latest_metrics_csv(os.path.join(d, "empty")))

    def test_per_wave_summary(self):
        rows = [
            {"wave_id": "1", "blocked": "True", "matched_rule_id": "949110"},
            {"wave_id": "1", "blocked": "False", "matched_rule_id": ""},
            {"wave_id": "2", "blocked": "True", "matched_rule_id": "1000000"},
            {"wave_id": "2", "blocked": "True", "matched_rule_id": "949110"},
        ]
        w1, w2 = runner.per_wave_summary(rows)
        self.assertEqual((w1["total"], w1["bypassed"], w1["ai_rule_403s"]), (2, 1, 0))
        self.assertEqual((w2["bypassed"], w2["ai_rule_403s"], w2["bypass_rate"]), (0, 1, 0.0))


class CliAndDryRun(unittest.TestCase):
    def _main(self, argv):
        buf = io.StringIO()
        with mock.patch("subprocess.run") as run, mock.patch("subprocess.Popen") as popen, \
                redirect_stdout(buf):
            rc = runner.main(argv)
        self.assertFalse(run.called, f"{argv} ran a subprocess in dry-run")
        self.assertFalse(popen.called, f"{argv} started a process in dry-run")
        return rc, buf.getvalue()

    def test_dry_run_never_executes_anything(self):
        for argv in (["up"], ["down"], ["check"], ["reset"], ["reset", "--restart-server"],
                     ["server", "start"], ["server", "status"], ["test"],
                     ["run", "--defend", "--adaptive", "--tee"]):
            rc, _ = self._main(argv + ["--dry-run"])
            self.assertEqual(rc, 0, argv)

    def test_dry_run_accepted_before_subcommand(self):
        rc, out = self._main(["--dry-run", "up"])
        self.assertIn("docker compose", out)

    def test_dry_run_check_never_shows_key(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-should-not-appear"}):
            _, out = self._main(["check", "--dry-run"])
        self.assertNotIn("sk-should-not-appear", out)

    def test_dry_run_run_prints_preflight_and_command(self):
        _, out = self._main(["run", "--defend", "--adaptive", "--dry-run"])
        self.assertIn("curl -s -m 3 -o /dev/null", out)
        self.assertIn(".venv/bin/python run.py --defend --adaptive", out)

    def test_parser_passes_run_options(self):
        a = runner.build_parser().parse_args(
            ["run", "--waves", "1", "--wave-size", "5", "--pause", "0", "--label", "x", "--tee"])
        self.assertEqual((a.waves, a.wave_size, a.pause, a.label, a.tee), (1, 5, 0, "x", ""))
        self.assertIsNone(runner.build_parser().parse_args(["run"]).tee)


if __name__ == "__main__":
    unittest.main()
