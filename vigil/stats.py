"""Everything the pages show, computed from a list of alerts.

Wazuh raises one alert per matching log line, so a brute force is a dozen
alerts. Grouping them by (rule, source IP, agent) turns that back into
"one thing happened, 12 times", which is what you actually triage.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .model import SEVERITIES, SEVERITY_ORDER, TACTIC_ORDER, TACTICS, Alert


def worst(severities) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")


def combined_status(statuses) -> str:
    statuses = set(statuses)
    if "open" in statuses:
        return "open"
    if "acknowledged" in statuses:
        return "acknowledged"
    return "closed"


@dataclass
class Group:
    rule_id: str
    src_ip: str
    agent_name: str
    alerts: list[Alert] = field(default_factory=list)   # newest first
    status: str = "open"

    @property
    def latest(self) -> Alert:
        return self.alerts[0]

    @property
    def first_seen(self) -> datetime:
        return self.alerts[-1].ts

    @property
    def last_seen(self) -> datetime:
        return self.alerts[0].ts

    @property
    def count(self) -> int:
        return len(self.alerts)

    @property
    def severity(self) -> str:
        return worst(a.severity for a in self.alerts)

    @property
    def ids(self) -> list[str]:
        return [a.id for a in self.alerts]


def group_alerts(alerts: list[Alert], statuses: dict[str, str]) -> list[Group]:
    groups: dict[tuple, Group] = {}
    for a in alerts:   # alerts arrive newest first, so groups keep that order
        g = groups.get(a.group_key)
        if g is None:
            g = groups[a.group_key] = Group(a.rule_id, a.src_ip, a.agent_name)
        g.alerts.append(a)
    for g in groups.values():
        g.status = combined_status(statuses.get(i, "open") for i in g.ids)
    return sorted(groups.values(), key=lambda g: g.last_seen, reverse=True)


@dataclass
class Bucket:
    start: datetime
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def timeline(alerts: list[Alert], since: datetime, until: datetime, n: int = 48) -> list[Bucket]:
    span = max((until - since).total_seconds(), 1)
    step = span / n
    buckets = [Bucket(since + timedelta(seconds=i * step), dict.fromkeys(SEVERITIES, 0)) for i in range(n)]
    for a in alerts:
        i = int((a.ts - since).total_seconds() // step)
        if 0 <= i < n:
            buckets[i].counts[a.severity] += 1
        elif i == n:   # an alert exactly at `until`
            buckets[-1].counts[a.severity] += 1
    return buckets


def overview(alerts: list[Alert], statuses: dict[str, str]) -> dict:
    open_alerts = [a for a in alerts if statuses.get(a.id, "open") == "open"]
    by_sev = Counter(a.severity for a in open_alerts)

    ips: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        if a.src_ip:
            ips[a.src_ip].append(a)
    top_ips = sorted(
        ({"ip": ip, "count": len(al), "severity": worst(x.severity for x in al),
          "agents": sorted({x.agent_name for x in al}),
          "tactics": len({t for x in al for t in x.mitre_tactics})}
         for ip, al in ips.items()),
        key=lambda r: (SEVERITY_ORDER[r["severity"]], r["count"]), reverse=True)[:6]

    rules: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        rules[a.rule_id].append(a)
    top_rules = sorted(
        ({"rule_id": rid, "description": al[0].description, "level": al[0].level,
          "severity": al[0].severity, "count": len(al)} for rid, al in rules.items()),
        key=lambda r: (r["level"], r["count"]), reverse=True)[:6]

    return {
        "total": len(alerts),
        "open": len(open_alerts),
        "urgent_open": by_sev.get("critical", 0) + by_sev.get("high", 0),
        "by_severity": {s: by_sev.get(s, 0) for s in SEVERITIES},
        "top_ips": top_ips,
        "top_rules": top_rules,
        "tactics": tactic_coverage(alerts),
        "agents": agent_summary(alerts),
        "latest_ts": alerts[0].ts if alerts else None,
    }


def tactic_coverage(alerts: list[Alert]) -> list[dict]:
    """How many alerts touched each ATT&CK tactic, in kill-chain order."""
    counts: Counter[str] = Counter()
    sev: dict[str, list[str]] = defaultdict(list)
    for a in alerts:
        for t in a.mitre_tactics:
            counts[t] += 1
            sev[t].append(a.severity)
    return [{"tactic": t, "count": counts.get(t, 0), "severity": worst(sev[t]) if t in sev else None}
            for t in TACTICS]


def agent_summary(alerts: list[Alert]) -> list[dict]:
    agents: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        agents[a.agent_name or "(manager)"].append(a)
    rows = []
    for name, al in agents.items():
        rows.append({
            "name": name, "id": al[0].agent_id, "ip": al[0].agent_ip, "count": len(al),
            "severity": worst(x.severity for x in al), "last_seen": max(x.ts for x in al),
            "by_severity": {s: sum(1 for x in al if x.severity == s) for s in SEVERITIES},
        })
    return sorted(rows, key=lambda r: (SEVERITY_ORDER[r["severity"]], r["count"]), reverse=True)


def rule_summary(alerts: list[Alert]) -> list[dict]:
    rules: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        rules[a.rule_id].append(a)
    rows = []
    for rid, al in rules.items():
        first = al[0]
        rows.append({
            "rule_id": rid, "description": first.description, "level": first.level,
            "severity": first.severity, "groups": first.groups, "mitre_ids": first.mitre_ids,
            "count": len(al), "sources": len({x.src_ip for x in al if x.src_ip}),
            "agents": sorted({x.agent_name for x in al}), "last_seen": max(x.ts for x in al),
        })
    return sorted(rows, key=lambda r: (r["level"], r["count"]), reverse=True)


def attack_chain(alerts: list[Alert]) -> dict:
    """Lay one source IP's alerts out as a story: chronological, with each
    step tagged by the earliest kill-chain tactic it maps to."""
    ordered = sorted(alerts, key=lambda a: a.ts)
    steps = []
    for g in _consecutive_runs(ordered):
        tactics = sorted({t for a in g for t in a.mitre_tactics}, key=lambda t: TACTIC_ORDER.get(t, 99))
        steps.append({
            "rule_id": g[0].rule_id, "description": g[0].description,
            "severity": worst(a.severity for a in g), "count": len(g),
            "first": g[0].ts, "last": g[-1].ts, "agent": g[0].agent_name,
            "tactics": tactics, "stage": tactics[0] if tactics else None,
            "mitre_ids": sorted({m for a in g for m in a.mitre_ids}),
            "users": sorted({a.user for a in g if a.user}),
            "example": g[-1],
        })
    reached = {t for s in steps for t in s["tactics"]}
    return {
        "steps": steps,
        "tactics": [{"tactic": t, "reached": t in reached} for t in TACTICS],
        "furthest": max(reached, key=lambda t: TACTIC_ORDER[t]) if reached else None,
        "agents": sorted({a.agent_name for a in alerts}),
        "users": sorted({a.user for a in alerts if a.user}),
        "first": ordered[0].ts if ordered else None,
        "last": ordered[-1].ts if ordered else None,
        "severity": worst(a.severity for a in alerts),
    }


FOLLOW_UP_WINDOW = timedelta(minutes=30)


def logins(alerts: list[Alert]) -> list[Alert]:
    """Alerts that record a successful login (Wazuh tags them
    authentication_success, including 40112 'failures followed by a success')."""
    return [a for a in alerts if "authentication_success" in a.groups
            or a.rule_id == "40112"]


def follow_up(login_alerts: list[Alert], agent_alerts: dict[str, list[Alert]]) -> list[dict]:
    """What happened on each host right after the attacker logged in.

    Alerts like 'sudo to root' or 'new user added' carry no source IP, so
    Wazuh can't tie them to the attacker. Showing what the same host logged in
    the next 30 minutes is how an analyst would connect them by hand. It's
    correlation by time, not proof, and the page says so."""
    out = []
    for login in sorted(login_alerts, key=lambda a: a.ts):
        until = login.ts + FOLLOW_UP_WINDOW
        after = [a for a in agent_alerts.get(login.agent_name, [])
                 if login.ts < a.ts <= until and not a.src_ip]
        if after:
            out.append({"login": login, "alerts": sorted(after, key=lambda a: a.ts)})
    return out


def _consecutive_runs(alerts: list[Alert]) -> list[list[Alert]]:
    """Merge back-to-back alerts of the same rule on the same agent into one
    step, so 8 failed logins read as one line in the story."""
    runs: list[list[Alert]] = []
    for a in alerts:
        if runs and runs[-1][-1].rule_id == a.rule_id and runs[-1][-1].agent_name == a.agent_name:
            runs[-1].append(a)
        else:
            runs.append([a])
    return runs
