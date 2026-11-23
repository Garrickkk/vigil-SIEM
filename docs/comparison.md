# Trellis vs Wazuh

Same attacks ([attack-scenarios.md](attack-scenarios.md)), two SIEMs: the
one I wrote and Wazuh 4.14.7 with its **default ruleset**, run in the lab on
16–17 Nov 2026 (Ubuntu 24.04 victim with nginx, attacker on the same
host-only network). The last column is the custom rule in
[`rules/`](../rules/) that closes the gap.

*Expected* came from reading Wazuh's ruleset source before the run;
*Observed* is what the lab actually raised.

## Detection matrix

| Trellis rule | Wazuh built-in | Expected | Observed (default Wazuh) | Vigil rule |
|---|---|---|---|---|
| `ssh-brute-force` (5 fails / 60 s) | `5763` (8 / 120 s) | Detected, higher threshold | ✅ `5763` after 8 failures | `100100` at 5 |
| `ssh-password-spray` (5 users / 300 s) | `5712` (8 / 120 s) | Partial | ✅ `5712`; 17 `5710` alerts for 8 attempts (sshd logs two lines per attempt) | `100102` at 5 (lab: fired) |
| `ssh-brute-force-success` (15 min) | `40112` (240 s) | Only within 4 min | ❌ **3 wrong guesses then a login: only an INFO `5715`** (needs 8 failures before `40112` can fire) | `100100` + `100101` (lab: fired) |
| `ssh-root-login` | `5715` (level 3) | Logged, not flagged | not run (root password login is off by default) | |
| `sudo-root-shell` | `5402` (level 3) | Can't tell a shell apart | ❌ `sudo -i` = `5402`, level 3 | `100110` |
| `sudo-suspicious-command` | `5402` (level 3) | Gap | ❌ `curl … \| bash` as root = `5402`, level 3 | `100111` |
| `sudo-password-failures` | `5401`, `5404` | Detected | ⚠️ `5401` ×12, but **`5404` never fired**: it needs 3 failures in *one* command | `100140` |
| `sudo-not-allowed` | `5405` | "NOT in sudoers" only | not run | |
| `local-user-created` | `5902` | Detected | ✅ `5902` + `5901`, and **`40501` CRITICAL** "attacks followed by the addition of an user" | |
| `user-added-to-admin-group` | `2961` (gpasswd only) | Likely gap | ❌ `usermod -aG sudo` raised nothing: Wazuh has no usermod decoder | `100120` + decoder |
| `web-sql-injection` | `31103`, `31152` | Detected | ✅ `31103`, `31171`, `31152` | |
| `web-xss` | `31105` | Detected | ✅ `31105` | |
| `web-path-traversal` | `31104` | Detected | ✅ `31104`, `31153` | |
| `web-scanner-user-agent` | `31508` | Likely gap | ❌ **`31508` never fired** for Nikto 2.1.5 (`Mozilla/5.00 (Nikto/…)`) or `gobuster/3.6` | `100130` |
| `web-404-flood` (20 / 60 s) | `31151` (14 / 90 s) | Detected | ✅ `31151`, but it refires every 14 errors: hundreds of alerts per scan | `100130` names the tool (2-min cool-down); Vigil groups the rest |
| `web-sensitive-file-probe` | `31101` | Gap | ⚠️ plain `31101` 404s; a few `31516` "suspicious URL" | still open |
| `web-login-brute-force` | `31509` (WP/Joomla) | Gap | not run (no login page on web01) | |
| `web-recon-then-ssh-login` | none | Gap | ❌ same IP scanned the site, then broke into SSH: no correlating alert (Vigil's attack chain shows it) | still open |
| `new-open-port` (network scan diff) | `533` (netstat diff) | Host-based, every 6 min | ⚠️ **`533` silently never fired**: Ubuntu 24.04 has no `netstat`. After installing `net-tools`: fired within 6 min | `100150` names netcat; `install-agent.sh` installs net-tools |
| `risky-service-exposed` | none | Gap | not applicable (Wazuh doesn't read network scans) | |

## Things Wazuh does that Trellis doesn't

- File integrity monitoring (`syscheck`): changes to `/etc/passwd`,
  `/etc/sudoers`, etc.
- Rootkit checks, security configuration assessment (CIS benchmarks),
  vulnerability detection against installed packages
- `31106`: a web attack that got a **200** back (likely worked)
- Agents: logs are shipped and buffered, so nothing is lost if the manager
  restarts
- Scales to many hosts; compliance mapping (PCI DSS, GDPR, NIST) on every rule

## Design differences worth writing about

- **One alert per log line.** Wazuh walks a tree of rules: sibling rules
  are tried highest level first, and the first match wins (then its own
  children are tried). So a traversal attempt that gets a 404 raises
  `31104` (level 6), not the generic `31101` (level 5), and never both. Trellis evaluates every rule against every
  event, so one request can be both "SQL injection" and "known scanner".
  This is why vigil groups alerts.
- **No URL decoding.** Wazuh's web rules match the raw URL with patterns
  for common encodings (`%20`, `+`). Trellis decodes up to 3 times, so
  double-encoded payloads (`%2527`) only reach Trellis's rules.
- **Correlation is per rule.** Wazuh's correlation (`frequency`,
  `if_matched_sid`, `same_source_ip`) chains rules together. Trellis's
  `sequence` type works on any event fields across sources. Cross-source
  stories ("scanned the web, then logged in over SSH") need custom Wazuh
  rules, or a view like vigil's attack chain.
- **Who did it.** `sudo` and `useradd` events carry a user, not an IP, so
  neither SIEM ties them to the attacker automatically. Vigil's "after the
  login" view links them by host and time.

## Results

16 of Trellis's 20 detections were tested (4 weren't applicable to this lab).

| Default Wazuh | Count | Which |
|---|---|---|
| Detected | 7 | brute force (8+ tries), spraying (8+), new user, SQLi, XSS, traversal, 404 flood |
| Partial | 4 | login after brute force (only 8+ failures within 4 min), failed sudo (not across commands), sensitive-file probes (plain 404s), new listening port (needs net-tools) |
| Missed or level 3 | 5 | root shell, download-and-run as root, admin-group change, scanner user agents, web-recon-then-SSH |

The custom rules in `rules/` close 7 of the 9 partial or missed cases, and
each one was confirmed firing in the lab against a re-run of the attack.
Still open: sensitive-file probes and cross-source correlation (web scan,
then SSH from the same IP).

### Headline findings

1. **Brute-force blind spot.** Wazuh's "failures followed by a success"
   (`40112`) depends on its brute-force rule (`5763`), which needs 8
   failed-password events. A login after fewer (a short targeted wordlist,
   a leaked password) is an INFO-level `5715`, identical to a normal login.
   Confirmed in the lab after fixing the double counting (see 3): 3 wrong
   guesses then a login gave only `5715`; with Vigil's rules, 5 wrong
   guesses then a login gave `100100` and `100101` (level 12). *Correction:*
   an earlier run that seemed to show this was compromised (a login event
   lost in a Docker crash, and every event read twice).
2. **A silent failure on Ubuntu 24.04.** The default "listening ports
   changed" check runs `netstat`, which isn't installed. Nothing in the
   dashboard says so; the rule just never fires.
3. **Every event was counted twice, and that was my setup.** On Ubuntu 24.04
   the agent already reads the systemd journal; `install-agent.sh` also
   added `/var/log/auth.log` (the same messages, via rsyslog) and a second
   copy of the nginx log. Counts in the first runs (~4,500 `31101`, 37 alerts
   for 8 SSH attempts) are roughly double, and thresholds fired at about
   half the real attempts. Fixed in `install-agent.sh` and verified: a
   re-run of scenario 1 sent 12,816 requests (nginx's own count) and raised
   about 10,000 web alerts, under one per request (the rest were normal
   `200`s). The SSH spray went from 37 alerts to 17 for the same 8 attempts. Bonus trap: rsyslog folds repeats into
   `message repeated 5 times: [...]`, so a SIEM reading only auth.log sees
   one failed login where there were five. Read the journal.
4. **ATT&CK tags inflate scans.** Web-attack rules carry techniques like
   Process Injection, so a scan of 404s "reached" Privilege Escalation and
   Lateral Movement. Vigil counts rejected requests as Reconnaissance only.
5. **A false positive.** `31106` "web attack returned 200" fired against a
   static nginx page that answers every URL with its homepage.
6. **The first sudo hides everything else.** `5403` "First time user
   executed sudo" is checked before `5402` "sudo to ROOT", so on an
   account's first sudo no rule under `5402` runs at all, including custom
   ones. For a freshly compromised account, the attacker's first root shell
   is a level-4 "first time" event. Vigil's sudo rules hang off the parent
   (`5400`) for this reason; `wazuh-logtest` caught it.
7. **Where Wazuh beat Trellis:** `40501` (CRITICAL) tied the attack to the
   new backdoor account with no source IP; `5403` flagged an account using
   sudo for the first time; `2902` flagged package installs.
