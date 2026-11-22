# rules/

Custom Wazuh rules for the gaps the [attack scenarios](../docs/attack-scenarios.md)
found in Wazuh 4.14.7's default ruleset. Results and reasoning:
[docs/comparison.md](../docs/comparison.md).

| Rule | Level | Closes the gap |
|---|---|---|
| `100100` | 8 | 5 failed SSH passwords from one IP (Wazuh waits for 8). |
| `100102` | 8 | 5 logins with made-up usernames from one IP (password spraying; Wazuh waits for 8). |
| `100101` | 12 | Successful login from an IP that failed repeatedly in the last 15 minutes. Lab: 5 wrong guesses then a login gave `100100` + `100101`; default Wazuh gave only an INFO `5715`. |
| `100110` | 8 | sudo opening an interactive root shell (`sudo -i`, `sudo bash`, `sudo su`). |
| `100111` | 12 | sudo running a downloaded script (`curl … \| bash`). |
| `100140` | 10 | 3 failed sudo passwords in 2 minutes, across separate commands (`5404` needs all 3 in one). |
| `100120` | 10 | A user added to `sudo`/`wheel`/`admin`/… with `usermod -aG` (needs `vigil_decoders.xml`; Wazuh has no usermod decoder). |
| `100130` | 11 | A scan/attack burst whose User-Agent is a known tool: Nikto, gobuster, sqlmap and others. |
| `100150` | 12 | A listening port held by netcat/socat (a bind shell or backdoor). |

**All nine rules have fired in the lab** (17 Nov 2026) against real attacks
from the attacker VM: `100100`/`100101` (hydra, 5 wrong guesses then the
password), `100110`, `100111`, `100120`, `100140` (privilege escalation as
`deploy`), `100150` (`nc -lvnp 4444`, ~6 minutes later), and `100102`/`100130`
via `wazuh-logtest` with real log lines.

## Deploy and test

With Wazuh running (`.\setup\vigil.ps1 up`):

```powershell
python rules/vigil_rules.py deploy   # copies both files in, restarts the manager
python rules/vigil_rules.py test     # runs tests.json through wazuh-logtest
```

`test` feeds each case's log lines into one `wazuh-logtest` session (so the
counting rules see the earlier lines) and checks which rule fires on each.
Every rule has at least one case, plus no-false-positive and no-regression
cases (an ordinary sudo stays `5402`; a browser's 404 burst stays `31151`).

If the manager doesn't start after `deploy` (a rule syntax error, say),
the script prints the error, removes the files and restarts Wazuh.
`python rules/vigil_rules.py remove` takes them out at any time.

The files live in `/var/ossec/etc`, a Docker volume, so they survive
restarts and `vigil.ps1 down`/`up` (but not `vigil.ps1 reset`).

## Then re-run the attacks

`logtest` proves a rule matches a log line. Re-running the scenarios proves
it works end to end, with real timing:

- Scenario 4 with 5 wrong guesses before the password: `100100`, then `100101`.
- Scenario 5: `100110`, `100111`, `100120`, `100140`.
- Scenario 1 (gobuster): `100130` instead of plain `31151`.
- Scenario 6: `100150` instead of `533` (can only be tested live).

## Known trade-offs

- **The sudo rules sit next to Wazuh's first-time-sudo rule (`5403`), not
  under `5402`.** `5403` is checked before `5402`, so on a user's first sudo
  nothing under `5402` runs. Found by `tests.json`: the root-shell case
  returned `5403` until the rules moved. When `100110`/`100111` fire on a
  first sudo, that event isn't also reported as "first time".
- **The 5th failure is reported as `100100`, not `5760`.** Wazuh counts an
  event only under the rule that finally alerted, so `5763` now fires on
  the 9th failure instead of the 8th. `tests.json` checks this.
- **`100130` upgrades Wazuh's burst rules (`31151/2/3`) instead of matching
  every request.** Matching each scanner request directly would replace
  `31101` and stop `31151` counting 404s. The cost: a scanner that only gets
  `200` responses isn't named.
- **`100110`/`100111` match common shells and download tools.** Something
  like `sudo python3 -c '…'` still gets through; this is a starting point.

Rule IDs use the 100000–109999 range reserved for custom rules.
