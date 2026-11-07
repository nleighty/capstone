# Step 2 — Target + WAF

Code-review sprint, Step 2. Chat held 2026-11-06.

**Source material:** `waf-defense/docker-compose.yml`, `waf-defense/docs/Sprint1_Summary.md`,
`debug-notes-sprint1-paths.md`, the running `waf` container (read-only), my Oct 16 logs, the two rules
in git (`git show 0cfac9c^:waf-defense/modsec-rules/ai_generated_rules.conf`), and the Sprint 4.5
transcript. The rules file on `main` is empty; `0cfac9c` is the commit that deleted both rules.

**Regex testing caveat:** the regex results below came from Python's `re`, not the live WAF.
ModSecurity uses a different regex engine, though it should behave the same on these patterns. The
benign test strings for rule 1000001 were made up, not real traffic.

**How this file is laid out:** each part has a short explanation, then the quiz questions. The end has
questions a grader will probably ask, what changed in the repo, and open items.

---

## Part 1 — Reverse proxy, WAF, and a request's path

### Concepts
- **Forward proxy** works for the client (a school web filter). **Reverse proxy** works for the server
  and stands in front of it. The client thinks the proxy *is* the website.
- There are **two separate connections**: client → Nginx, then Nginx → Juice Shop. That's why Nginx
  can decide what happens to a request.
- **Network firewall** reads the envelope (IP, port). **WAF** opens the letter (path, parameters,
  headers, cookies, body).
- **The three pieces:** Nginx is the doorway, ModSecurity is the inspector (an engine plugged into
  Nginx), CRS is the rulebook. Versions in my logs: ModSecurity 3.0.16, CRS 4.28.0.

### The path
`fire.py` → `localhost:8080` → Docker port forward → Nginx → ModSecurity phase 1 (headers) → phase 2
(body) → **denied:** Nginx answers 403 and Juice Shop never sees it / **allowed:** Nginx opens a new
connection to `juice-shop:3000` → response comes back through phases 3–4 → phase 5 logs.

The client address in my access log is `172.18.0.1`, which is the Docker network's gateway, because
the request came in through Docker's port forward.

### Real requests from my logs
| Marker | `email` sent | Status | What happened |
|---|---|---|---|
| `w1-sqli-01-3` | `' OR 1=1--` | 403 | CRS 942100 matched, 949110 blocked |
| `w1-sqli-01-1` | ` OR 1=1--` (no quote) | 401 | No rule fired; Juice Shop rejected the login |
| `w1-sqli-02-1` | ` OR /*1*/ '1'='1 ` | 500 | No rule fired; Juice Shop returned a server error |
| `w1-sqli-03-1` | `admin@juice-sh.op'--",` | 200 | No rule fired; login accepted, a real break-in |

**A bypass means the WAF let it through, not that the attack worked.** The 401 counts as a bypass
even though it can't break out of the SQL string without a quote.

### Quiz
**Q1. Forward vs. reverse proxy? What does `fire.py` think it's talking to?**
- **Got right:** a forward proxy is for the client and a reverse proxy is for the server. `fire.py`
  thinks it's talking to Juice Shop, but it's really Nginx.
- **Added:** `fire.py` is just pointed at `localhost:8080` and doesn't know what's behind it, so the
  WAF can change without touching the client.

**Q2. Did Juice Shop see the 403 request? The 401 one?**
- **Got right:** not the 403, which was blocked in front of it. The 401 reached it, and the app
  rejected the login.
- **Added:** a status code is only a clue, because an app can send its own 403. The proof is the audit
  log: rules 942100 and 949110 fired on the 403, and none fired on the 401.

**Q3. Could a firewall that only allows port 8080 stop `' OR 1=1--`?**
- **Got right:** no, it only looks at the port, not the content.

**Q4. If Juice Shop published `3000:3000` and an attacker hit it directly?**
- **Got right:** the attack gets past the WAF.
- **Corrected:** the WAF logs wouldn't show it on port 3000. They'd show **nothing**, because the
  request never touches Nginx. The bypass count doesn't change, the threshold doesn't trip, and the
  agent never responds. The worst attack is the one the system can't see. Leaving `ports` off
  `juice-shop` protects the measurements too, not just the app.

---

## Part 2 — `docker-compose.yml`

### Concepts
An **image** is a read-only template, and a **container** is a running copy. **Compose** reads the YAML
and starts everything together. The image fills environment variables into config templates at startup,
e.g. `proxy_pass ${BACKEND};` becomes `proxy_pass http://juice-shop:3000;`.

### Line by line
| Lines | What it does |
|---|---|
| 2–6 | `juice-shop`: image with no tag (`:latest`), joins `waf-net`, **no `ports:`** (`localhost:3000` is refused; I checked) |
| 9 | WAF image bundling Nginx, ModSecurity, CRS |
| 12 | `"8080:8080"` is `HOST:CONTAINER`. The container runs as unprivileged `nginx` (uid 101), so it can't use ports below 1024 |
| 14 | `BACKEND`: where allowed traffic goes |
| 15 | `PARANOIA: "1"`: rule strictness |
| 16–17, 25 | Log paths, moved into the shared folder |
| 31 | `MODSEC_AUDIT_ENGINE: "On"` (default `RelevantOnly`): also logs successful requests |
| 39 | `MODSEC_AUDIT_LOG_PARTS: "ABCDEFHIJZ"` (default `ABIJDEFHZ`): adds part C, the request body. Cost: login passwords end up in the log |
| 41 | Mounts my rules file into the CRS rules folder |
| 42 | Shares `./logs` at `/var/log/waf-logs` |
| 45–46 | `depends_on` starts Juice Shop first, but doesn't wait until it's ready |
| 48–50 | `bridge` network with name lookup, named `waf-defense_waf-net` by Docker |

**Gotcha:** a mount hides whatever was at that path. Mounting `./logs` over `/var/log` hid Nginx's
`nginx/` folder and crashed the container in Sprint 1.

### Exact images I'm running
Tags aren't pinned, and upstream's `nginx` tag has already moved on (CRS 4.30.0), so **these go in the
report**. A pull could change the rules and shift my 33.6% baseline.

| Image | Digest |
|---|---|
| `owasp/modsecurity-crs:nginx` (CRS 4.28.0) | `sha256:2051ff18b836c1d9bbc5c7754451c1687ea27352e497b89d0c9fc7e657861e07` |
| `bkimminich/juice-shop` | `sha256:e68144772ebaaca0ec117b38d44903af92416793230288ef7c5437fc4f26850a` |

### Quiz
**Q1. If `8080:8080` became `9090:8080`, what URL does `fire.py` need? Does `BACKEND` change?**
- **Got right:** port 9090, and the format is outside:inside.
- **Added:** `BACKEND` doesn't change, because that path is entirely inside Docker. `WAF_BASE_URL` needs
  changing in two places: `attacker-pipeline/config.py:9` and `mcp-server/config.py:36` (for
  `verify_rule`'s replays).

**Q2. How can the WAF reach Juice Shop on 3000 with no `ports:`?**
- **Got right:** `BACKEND` is how it knows where to send traffic.
- **Added:** how it *reaches* it: both are on `waf-net`, Docker's name lookup turns `juice-shop` into an
  IP, and containers on the same network can reach each other's ports directly. `ports:` only opens a
  path from outside Docker.

**Q3. With default audit settings, what's recorded for the 200 login bypass?**
- **Got right:** no part C means no POST data.
- **Corrected:** it's worse. `RelevantOnly` keeps a transaction only if a rule fired or the status looks
  like an error. A 200 with no matches gets **no audit entry at all**. The access log still has a line,
  so the bypass is counted, but the agent doesn't know what it contained. Lines 31 and 39 are both needed.

**Q4. Is a newly written rule active right away?**
- **Got right:** no, the WAF needs a reload.
- **Added:** the file changes inside the container immediately, but Nginx and ModSecurity read rules
  into memory at startup or reload. *Saved* and *active* are different states.

---

## Part 3 — How ModSecurity and CRS decide

### Phases
1 request headers → **2 request body (last chance to stop a request)** → 3 response headers → 4 response
body → 5 logging.

### Anomaly scoring
Like points on a driving record. Detection rules add points, and one rule at the end decides.

```apache
# 942100 (trimmed)
SecRule ...|ARGS|... "@detectSQLi" "id:942100,phase:2,block,severity:'CRITICAL',
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

# crs-setup.conf line 98: what block means in phase 2
SecDefaultAction "phase:2,pass,log,tag:'modsecurity'"

# 949110: the rule that denies
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge %{tx.inbound_anomaly_score_threshold}" "id:949110,phase:2,deny,..."
```

`block` means "use the default action", and the default here is `pass`. So 942100 logs and adds points,
and 949110 is what stops the request.

**Points:** CRITICAL 5, ERROR 4, WARNING 3, NOTICE 2. **Thresholds:** 5 inbound, 4 outbound.

| Request | Rules matched | Score | Result |
|---|---|---|---|
| `q=apple juice` | none (no block) | 0 | 200 |
| `email=' OR 1=1--` | 942100 | 5 | 403 from 949110 |
| `q=x' union select id,email from Users--` | 942100, 942190, 942270 | 15 | 403 from 949110 |

One CRITICAL reaches the threshold, so scoring only makes a difference for lower-severity rules. In my
100 marked requests, **no request that got through had any rule match**. They weren't near misses. (That's
one run, so it's an observation, not a general result.)

### Other pieces
- **`@rx`** runs a regex. **`@detectSQLi`** uses libinjection, which matches token shapes: `s&1c` is
  roughly string, logic operator, number, comment.
- **`t:`** transformations normalize input first, e.g. `t:urlDecodeUni`.
- **Paranoia level** decides **which rules run**; the threshold decides **how many points block**. They're
  separate. Levels add on top of each other. SQLi file tag counts: PL1 20, PL2 31, PL3 7, PL4 2. **Blocking**
  level rules count toward the score; a higher **detection** level only logs. Both are 1 here.

### Where my custom rules fit
They use `deny` directly (no points), and they run **after** 949110, because files load alphabetically and
`RESPONSE-999...` comes after `REQUEST-949...`. The `phase:` setting decides when a rule runs, not the
filename. So custom rules only see what CRS was going to allow.

### Quiz
**Q1. Does 942100's `block` stop the request itself?**
- **Got right:** no, it takes the default action of passing, and another rule based on the cumulative
  score does the blocking (949110).

**Q2. One WARNING + one NOTICE? WARNING alone?**
- **Got right:** first is blocked (3 + 2 = 5), second isn't (3). The match still gets logged.

**Q3. Paranoia 1 → 2? Why not run PL4 and skip the AI?**
- **Got right:** bypasses go down and false positives go up. PL4 would block too much benign traffic for a
  real app.
- **Added:** "bypasses go down" is a prediction, since I never measured PL2. A stronger argument: PL4 is
  still a *static* list that attackers can mutate around. My defense updates from what actually got through.

**Q4. Score 15 that also matches 1000000: which ID blocks it? Score 0 that matches: which ID? Why does this
help RGI?**
- **Got right:** CRS (949110) for the first, 1000000 for the second.
- **Didn't know the RGI link:** RGI credit comes from the blocking rule's ID. `949110` means CRS would have
  caught it anyway, and `1000000` means CRS let it through and my rule stopped it. If custom rules ran first,
  they'd claim requests CRS would have blocked, and RGI would look better than it is.

---

## Part 4 — SecRule syntax and the regexes

### The template (`mcp-server/core/rule_writer.py:12-15`)
```apache
SecRule REQUEST_COOKIES|ARGS "@rx {attack_pattern}" "id:{rule_id},phase:2,deny,status:403,msg:'{description}'"
#       WHERE to look         WHAT to test           WHAT to do if it matches
```
**The LLM only fills in the regex and the description.** It can't change where the rule looks, when it runs,
or what it does.
- `ARGS` covers query parameters and body fields, including JSON (`ARGS:json.email`). Not headers or the path.
- **Rules are site-wide.** Rule 1000000's `msg` says "on /rest/user/login" but nothing checks the path, which is
  why `verify_rule` sends benign traffic to all endpoints. The label is misleading.
- There are no `t:` transformations. ModSecurity decodes query parameters once and doesn't URL-decode JSON values,
  so the regex has to spell out `%20`, `%27`, etc. That's a big reason these regexes are so long.

### Regex notation
```
A|B  or        (?:...) group          [abc] one of these      \s \d space / digit
*  0+          +  1+                  ?  optional             {0,40}  0 to 40 times
.  any char    .{0,40}?  as few as possible                   ^  start of value
(?i) ignore case                      [\s\S] any char including newlines
```
A regex searches **anywhere** in the value and stops as soon as its last piece is satisfied.

### Rule 1000000 (595 characters): ten alternatives
Mostly looks for SQL structure: (1) tautologies, (2) quote then comment, (3) `;--`, (4) UNION SELECT, (5) SELECT ...
FROM, (6) DROP/ALTER/TRUNCATE TABLE, (7) INSERT INTO, (8) DELETE FROM, (9) sleep functions, (10) WAITFOR DELAY.

Alternative 1 against ` OR 1=1`:
```
(?:^|[\s'"()*/+,;=-]|%20|%27|%22|%28|%29)   boundary before the word   " "
(?:or|and)                                  the keyword                "OR"
(?:[\s'"()]|%20|%27|%22|%28|%29)+           separators                 " "
(?:0x)?\d+                                  a number                   "1"
(?:['"]|%27|%22)?                           optional closing quote
(?:\s|%20)*                                 optional spaces
(?:=|%3d|<>|!=|%3c|%3e)                     a comparison               "="
(?:\s|%20)*                                 optional spaces
(?:['"]|%27|%22)?                           optional opening quote
(?:0x)?\d                                   a number                   "1"
```

**Matches:** `' OR 1=1--`, `admin@juice-sh.op'--",`, `x'/**/union/**/select/**/id`.
**Correctly doesn't match:** `o'brien@example.com`, `salt and pepper or sugar, select one`, `color 5=5`.
**Misses:** `' OR /*1*/ '1'='1` and `'/**/oR/**/2>1--`. It has the same weakness CRS has: it covers the spellings
it was written for.

### Rule 1000001 (678 characters): six alternatives
Mostly looks for suspicious **encoding**: (A) 3+ double-encoded characters in a row, (B) 4+ percent-encoded in a row,
(C) 4+ HTML entities in a row, (D) an entity then a SQL/JS keyword within 40 characters, (E) an encoded `<` `` ` `` `>`
then a tag, (F) a literal `&lt;` then a tag.

The plain `<script>alert(1)</script>` doesn't match, because CRS blocks that first. This rule only handles leftovers.

| Input | Result |
|---|---|
| `1&#39; order by 10 --` (from my logs) | Match (D) |
| `&#x3c;script&#x3e;alert(1)` | Match (E) |
| `Tom&#39;s juice` | No match |
| `Tom&#39;s order by 10 am` | **False positive** (D) |
| `https://example.com/%E6%97%A5%E6%9C%AC` in a JSON comment | **False positive** (B) |
| `&lt;img of the shop` | **False positive** (F) |
| `%253Cscript%253E` | **Miss**, even though `msg` claims double-encoded script payloads |

**Don't quote `msg` as proof of what a rule does; test the regex.** Also, `&#39;` probably isn't a working SQL quote
(not verified), so this rule may be spending effort on bypasses that aren't real attacks.

### FAIL→revise→PASS (Sprint 4.5 transcript)
1. **`test_waf_configuration` failed (line 43).** Not the regex: `%20/%2F` in the description. ModSecurity treats `%`
   in `msg` as a macro, so the file wouldn't parse. Caught before any reload. `rule_writer` now rewrites `%` as
   `percent-`.
2. **`verify_rule` failed (line 51).** 7/7 attacks blocked, but 3/12 benign blocked. The cause was
   `(?:'|\x22|`|%27|...)\s*(?:%20|%2f|/|\s)*(?:--|%2d%2d|#|;)`, a quote then `--`, `#`, or `;`.
3. **Claude narrowed it, and `verify_rule` passed (line 59).** Quote + `--` still blocks. Quote + `;` now needs `--` or a
   SQL keyword after it. Quote + `#` must be at the very end of the value.

| Input | First version | Revised |
|---|---|---|
| `great 'service'; would buy again` | blocked | allowed |
| `Loved the 'juice' #1 shop` | blocked | allowed |
| `x'; drop table y` | blocked | blocked |
| `admin'#` | blocked | blocked |
| `Loved the 'juice' -- great shop` | blocked | **still blocked** |

**Be upfront about this:** the FAIL was partly set up. `Sprint4.5_Cleanup.md:293` says 3 benign cases were added after
a rule failed them, and the run started from an existing over-broad rule. It shows the loop works, but not that
`verify_rule` caught a surprise by itself.

### Lost coverage
There are two separate things here:

| | Rule file | Bypass sample list |
|---|---|---|
| Holds | WAF rules | Copies of requests that got past the WAF |
| Lives in | `ai_generated_rules.conf` | `_bypass_samples` in `BreachTracker`, saved to `mcp-server/state/breach_tracker_state.json` |
| Updated by | The agent | The MCP server, from the logs |

`verify_rule` doesn't own the list; it just asks for it and re-sends each request (tagged `_replay=1`, marker removed).
The list keeps at most **2 per seed** and **20 per endpoint and attack family**, for a smaller prompt and more variety.
`reset_state.py` deletes it.

1. **The agent overwrites rule X, and the new regex drops some coverage.** This is what weakens the defense.
2. **`verify_rule` runs.** If the old request is still on the list, it gets through and the verdict is **FAIL**. If it was
   pushed off or wiped, it's never sent, so the verdict can be **PASS**.

**Report line:** "`verify_rule` catches lost coverage only for attacks still in its sample list. Anything no longer in the
list can be lost without being noticed."

**Evidence:** the revised rule above blocks `admin'#`, `admin@juice-sh.op&#x27--`, and ` OR '1''='1 `. The Oct 12 rule blocks
none of them, and neither does 1000001. The "floor" prompt existed by then (added by Oct 4). **How real is this?** The design
gap is real from the code, and the coverage really did drop between those two versions. What's unknown is *why*: if the rule file
was reset first, Claude never saw the old rule, and that run says nothing about whether the warning works. So how often Claude
narrows a rule hasn't been measured. **My plan:** test multiple waves without a reset before building a fix. Details in
`mcp-server/docs/future-improvements.md`.

### Quiz
**Q1. Which parts does Claude control? Could it write a log-only rule?**
- **Got right:** Claude controls the regex, the code controls what the rule does, and it can't write a log-only rule.
- **Added:** Claude also writes the description. It could still write a useless regex that never matches, which is why
  `verify_rule` replays real attacks.

**Q2. Why does ` or 5=5` match but `color 5=5` doesn't?**
- **Corrected:** I pointed to `(?:or|and)`, but that finds `or` in both. The difference is the **boundary** before it: the
  character before `or` is a space in one and `l` in the other, and letters aren't allowed.

**Q3. Which alternative matches `' AND 2=2--`, and what exact text?**
- **Got right:** alternative 1, and the `--` isn't covered.
- **Corrected:** the leading `'` isn't covered either. The match is ` AND 2=2`, starting at the space. The boundary is one
  character directly before `AND`, so the rule doesn't need a quote at all.

**Q4. Two reasons alternative 1 misses `'/**/oR/**/2>1--`?**
- **Got right:** `or` needs a separator after it, and `/` isn't allowed.
- **Corrected:** the boundary is fine (`/` is on that list). The second reason is the comparison list: it has `%3e` but not a plain
  `>`. That looks like a real oversight. `' oR 2>1--` also misses, and it has no comments.

**Q5. Why is `Tom&#39;s juice` allowed while `Tom&#39;s order by 10 am` is blocked?**
- **Got right:** alternative D.
- **Corrected:** not the `or` in `order`. D's list has `order[\s+]+by[\s+]*\d`: `order by` plus a digit, within 40 characters of the
  entity. From reading it, `Tom&#39;s order by mail` shouldn't match.

**Q6. Why did the first version block `great 'service'; would buy again`, and what changed?**
- **Got right:** the revision requires `;` to be followed by `--` or a SQL keyword.
- **Added:** it was blocked because `';` is a quote directly followed by `;`, and that alone was enough. A regex can't tell a quoted
  word in a sentence from the end of a SQL string.

**Q7. Would the revised version block `Loved the 'juice' -- great shop`? What does that say about "0/12 benign blocked"?**
- **Corrected:** I said no, but it **is** blocked: quote, space, `--`. The revision only narrowed `;` and `#`. So 0/12 only means
  those 12 requests weren't blocked, not that the rule has no false positives. That's why RFPR needs a separate set of 50–100.

**Q8. A new rule stops blocking `admin'#` and `verify_rule` still says PASS. How?**
- **Got right:** the agent's overwrite in a later run dropped the coverage, and `verify_rule` only uses recorded payloads.
- **Added:** the missing part is why PASS was possible: `admin'#` had to be off the list (pushed out by the cap or wiped by a reset).

---

## Part 5 — Logs, and how a rule gets loaded

### The three logs
| Log | Written by | Contains | MCP server uses it for |
|---|---|---|---|
| `access.log` | Nginx | One line per request, no body | **Bypass counts** (marked and not 403) |
| `error.log` | Nginx + ModSecurity | One line per **denied** request, final decision only | **Blocked counts** |
| `modsec_audit.log` | ModSecurity | JSON per transaction, with body and every rule match | **Payload evidence** |

```
172.18.0.1 - - [16/Oct/2026:18:46:43 +0000] "POST /rest/user/login?_wave_marker=w1-sqli-01-3 HTTP/1.1" 403 146 "-" "python-requests/2.34.2" "-"
client         time                         request line                                               status bytes referer user-agent forwarded-for
```

- The error log had 70 "Access denied" lines and 0 warnings. A bypass was never denied, so **it isn't in the error log**.
- **Traffic mix:** 21,184 audit entries: 21,080 health checks (one every 30 seconds), 100 marked attacks, 4 other. The log is 17.8 MB
  and never rotates. Fine for the lab.

### A rule's path
```
Claude calls write_idempotent_rule(regex, description)
1. WRITE    rule_writer updates ai_generated_rules.conf     SAVED, not active
2. TEST     docker exec waf nginx -t                        parses everything, changes nothing
3. RELOAD   docker exec waf nginx -s reload                 ACTIVE
4. VERIFY   re-send saved bypasses + benign requests
```

- **It's literally one file.** The inode is `26287` on the host and in the container. `rule_writer` updates it in place with `write_text`. A
  write-then-rename would create a new inode, and the single-file mount would keep showing the old content (standard Docker behavior, not tested here).
- **Why it loads:** Nginx loads `/etc/modsecurity.d/setup.conf`, which has `Include /etc/modsecurity.d/owasp-crs/rules/*.conf`. Any `.conf` in that
  folder loads, alphabetically. The image only ships a `.example` of this filename. The name matters because it sorts last, after `REQUEST-949`.
- **Scoped Inclusion:** the agent only touches its own small file, never the main config.
- **Reload:** Nginx starts new workers with the new rules, and the old ones finish and exit. The command returns before that's done, so `verify_rule`
  waits 2 seconds (`VERIFY_SETTLE_SECONDS`) so an old worker doesn't report a false gap.

### Quiz
**Q1. A POST attack gets through. Which log gives the count, and which gives the payload?**
- **Corrected:** I said error.log and access.log. The **count comes from access.log** (a bypass isn't denied, so it's not in the error log), and the
  **payload comes from the audit log** (the access log has no body).
- **Note:** the quiz question also asked why one log can't do both, and that was a flawed question. The audit log has the marker, status, and body, so it
  could. Counting stays on the access log because Sprint 4.5 kept the behavior already proven correct (`mcp-server/docs/future-improvements.md`).

**Q2. A 403 shows `949110` in the error log. How do you find which CRS rules caused it?**
- **Didn't know this one.** Find that transaction in the audit log, by its `_wave_marker` or the `unique_id` shown in the error line, and read `messages`.
  Every rule that added points is listed before 949110.

**Q3. The agent skips the reload and calls `verify_rule`. What happens?**
- **Got right:** verification fails because the bypasses still get through, and the file shows the new rule.
- **Added:** this is misleading, because the regex could be fine. The agent might "fix" a good rule. `verify()`'s docstring warns about this.

**Q4. If the file sorted first instead of last?**
- **Got right:** it still loads, and RGI would go up because AI rules would get credit even where stock CRS could have blocked it.
- **Added:** that happens because the custom rule's `deny` would fire before 949110 runs, so its ID would be the one in the log.

---

## Be ready for these grader questions

1. **"Do your custom rules go through anomaly scoring?"** — No, they `deny` directly, and they run after CRS's decision, so they only see what CRS would allow.
2. **"Why not raise paranoia instead of using AI?"** — More false positives, and it's still a static list. I didn't measure PL2.
3. **"Why does an empty-looking `block` not block?"** — `block` means the default action, which is `pass` here. 949110 denies.
4. **"How do you know a block came from your rule and not CRS?"** — The rule ID in the logs. That's also how RGI gets credited.
5. **"Can the LLM change what a rule does?"** — No, only the regex and description. The template fixes the rest.
6. **"Does your rule apply only to the endpoint that tripped?"** — No, it's site-wide, and that's why the benign set covers all endpoints.
7. **"What does 0/12 benign blocked prove?"** — Only that those 12 pass. I can show a similar sentence that still gets blocked.
8. **"Can a rewrite weaken a rule?"** — Yes. Nothing enforces keeping coverage, and `verify_rule` only checks what's still in its list. How often it happens hasn't been measured.
9. **"Why three logs?"** — Access has every request and status, error has denials, and audit has the body and rule matches.
10. **"When is a rule live?"** — After the reload, not when it's saved. `nginx -t` only checks that it parses.
11. **"Could someone attack Juice Shop without you seeing it?"** — Only by reaching it directly, which is why it has no published port. If they did, the logs would show nothing.

---

## What changed in the repo during this step
All docs, plus one comment; no behavior changed. Nothing committed yet.

- `SECURITY.md`: corrected log ownership (uid 101, not root), added that the 777 folder lets any local user delete logs, and added the port published on all interfaces.
- `docs/sprint-4.6-direction.md`, `docs/common-commands.md`, `mcp-server/reset_state.py` (comment only): same ownership correction.
- `docs/common-commands.md`: the manual truncate now includes the audit log, matching `reset_state.py`.
- `docs/design-notes.md`: example rule ID changed to `1000000`; the `Include` description now matches how the file actually loads.
- `waf-defense/docs/debug-notes-sprint1-paths.md`, `Sprint1_Summary.md`, `step1-architecture.md`: corrected how the rules file gets loaded.
- `waf-defense/docs/future-improvements.md` (new, added to `CLAUDE.md`): `PARANOIA` vs. `BLOCKING_PARANOIA`, and limiting the port to loopback.
- `mcp-server/docs/future-improvements.md`: the lost-coverage issue, with a test plan and options. `README.md` points to it.

## Open items from this step
- **Lost coverage:** my priority after the review. Test multiple waves without a reset first, then decide.
- **Port on all interfaces and `PARANOIA` name:** documented, left alone because of time.
- **Unpinned images:** leaving as is, but the digests above go in the report.
- **RGI denominator (Sprint 5):** the formula divides by total unseen variants, but CRS-blocked ones never reach my rule, so they'd lower RGI even for a perfect rule. "Unseen variants that got past CRS" may be fairer.
- **`docker-compose.yml:29-30` "cheap" comment:** left as is. It's fair at this size, but 99.5% of audit entries are health checks.
