# Trellis vs Wazuh

Same attacks ([attack-scenarios.md](attack-scenarios.md)), two SIEMs: the
one I wrote and Wazuh 4.14.7 with its **default ruleset** (no custom rules
yet; those go in [`rules/`](../rules/)).

*Expected* comes from reading Wazuh's ruleset source. *Observed* gets
filled in after running each scenario in the lab. Where they differ is the
interesting part.

## Detection matrix

| Trellis rule | Wazuh built-in equivalent | Expected | Observed |
|---|---|---|---|
| `ssh-brute-force` (5 fails / 60 s) | `5763` (8 / 120 s), `5720` | Detected, higher threshold | |
| `ssh-password-spray` (5 distinct users / 300 s) | `5712` (8 non-existent-user attempts / 120 s) | Partial: counts attempts, not distinct users | |
| `ssh-brute-force-success` (15 min window) | `40112` (240 s window) | Detected only if the login comes within 4 min | |
| `ssh-root-login` | `5715` at level 3 | Logged, not flagged | |
| `sudo-root-shell` | `5402` at level 3 | Logged, can't tell a shell from any other sudo | |
| `sudo-suspicious-command` | `5402` at level 3 | Gap: no built-in rule looks at the command | |
| `sudo-password-failures` | `5401`, `5404` | Detected | |
| `sudo-not-allowed` | `5405` | Detected for "NOT in sudoers" only | |
| `local-user-created` | `5902` (level 8) | Detected | |
| `user-added-to-admin-group` | `2961` (gpasswd format only) | Likely gap for `usermod -aG sudo` | |
| `web-sql-injection` | `31103`, `31152` | Detected; matches the raw URL (no decoding) | |
| `web-xss` | `31105` | Detected | |
| `web-path-traversal` | `31104` | Detected | |
| `web-scanner-user-agent` | `31508` (short list) | Likely gap: only matches a UA that *starts* with `"Nikto`; modern Nikto starts with `Mozilla/5.00` | |
| `web-404-flood` (20 paths / 60 s) | `31151` (14 errors / 90 s) | Detected | |
| `web-sensitive-file-probe` | `31101` only | Gap: seen as a plain 404 | |
| `web-login-brute-force` | `31509` (WordPress/Joomla only) | Gap for a generic login page | |
| `web-recon-then-ssh-login` | none | Gap: no cross-source correlation by default | |
| `new-open-port` (network scan diff) | `533` (host netstat diff) | Different approach: host-based, every 6 min | |
| `risky-service-exposed` | none | Gap: Wazuh doesn't read network scans | |

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

*(After running the scenarios: how many of the 20 Trellis detections did
default Wazuh catch, how fast, and how much noise did each produce?)*
