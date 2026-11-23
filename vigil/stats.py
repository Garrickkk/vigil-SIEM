"""Everything the pages show, computed from a list of alerts.

These functions are the reference implementation. DemoSource uses them
directly; IndexerSource asks OpenSearch to compute the same numbers with
aggregations and returns the same shapes, so the templates don't care where
the numbers came from (tests/test_aggregations.py checks the two agree).

Wazuh raises one alert per matching log line, so a brute force is a dozen
alerts. Grouping them by (rule, source IP, agent) turns that back into
"one thing happened, 12 times", which is what you actually triage.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .model import SEVERITIES, SEVERITY_ORDER, TACTIC_ORDER, TACTICS, Alert

FOLLOW_UP_WINDOW = timedelta(minutes=30)
TOP_N = 6


def worst(severities) -> str:
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")


def combined_status(statuses) -> str:
    statuses = set(statuses)
    if "open" in statuses:
        return "open"
    if "acknowledged" in statuses:
        return "acknowledged"
    return "closed"


def status_from_counts(total: int, non_open: int, closed: int) -> str:
    """Group status from counts: open while any alert is untriaged."""
    if total > non_open:
        return "open"
    return "acknowledged" if non_open > closed else "closed"


# ---- groups -------------------------------------------------------------

@dataclass
class LatestRef:
    """The newest alert of a group, as much as the tables need."""
    id: str
    description: str
    who: str = ""


@dataclass
class GroupRow:
    rule_id: str
    src_ip: str
    agent_name: str
    count: int
    first_seen: datetime
    last_seen: datetime
    severity: str
    latest: Any            # an Alert or a LatestRef
    status: str = "open"

    @property
    def key(self) -> str:
        return "|".join((self.rule_id, self.src_ip, self.agent_name))


def group_alerts(alerts: list[Alert], statuses: dict[str, str]) -> list[GroupRow]:
    by_key: dict[tuple, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_key[a.group_key].append(a)
    rows = []
    for (rule_id, src_ip, agent), al in by_key.items():
        al.sort(key=lambda a: a.ts, reverse=True)
        rows.append(GroupRow(
            rule_id=rule_id, src_ip=src_ip, agent_name=agent, count=len(al),
            first_seen=al[-1].ts, last_seen=al[0].ts, severity=worst(a.severity for a in al),
            latest=al[0], status=combined_status(statuses.get(a.id, "open") for a in al)))
    return sort_groups(rows)


def sort_groups(rows: list[GroupRow]) -> list[GroupRow]:
    return sorted(sorted(rows, key=lambda g: g.key), key=lambda g: g.last_seen, reverse=True)


# ---- timeline -----------------------------------------------------------

@dataclass
class Bucket:
    start: datetime
    counts: dict[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def bucket_edges(since: datetime, until: datetime, n: int) -> list[datetime]:
    step = max((until - since).total_seconds(), 1) / n
    return [since + timedelta(seconds=i * step) for i in range(n + 1)]


def timeline(alerts: list[Alert], since: datetime, until: datetime, n: int = 48) -> list[Bucket]:
    edges = bucket_edges(since, until, n)
    step = (edges[1] - edges[0]).total_seconds()
    buckets = [Bucket(edges[i], dict.fromkeys(SEVERITIES, 0)) for i in range(n)]
    for a in alerts:
        i = int((a.ts - since).total_seconds() // step)
        if 0 <= i < n:
            buckets[i].counts[a.severity] += 1
        elif i == n:   # an alert exactly at `until`
            buckets[-1].counts[a.severity] += 1
    return buckets


# ---- summaries ------------------------------------------------------------

def severity_counts(alerts: list[Alert]) -> dict[str, int]:
    c = Counter(a.severity for a in alerts)
    return {s: c.get(s, 0) for s in SEVERITIES}


def tactic_coverage(alerts: list[Alert]) -> list[dict]:
    """How many alerts touched each ATT&CK tactic, in kill-chain order.
    Rejected web requests only count towards Reconnaissance (see
    Alert.chain_tactics)."""
    counts: Counter[str] = Counter()
    sev: dict[str, list[str]] = defaultdict(list)
    for a in alerts:
        for t in a.chain_tactics:
            counts[t] += 1
            sev[t].append(a.severity)
    return tactic_rows(counts, {t: worst(v) for t, v in sev.items()})


def tactic_rows(counts: dict[str, int], severity: dict[str, str]) -> list[dict]:
    return [{"tactic": t, "count": counts.get(t, 0), "severity": severity.get(t)} for t in TACTICS]


def top_ips(alerts: list[Alert]) -> list[dict]:
    ips: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        if a.src_ip:
            ips[a.src_ip].append(a)
    rows = [{"ip": ip, "count": len(al), "severity": worst(x.severity for x in al),
             "tactics": len({t for x in al for t in x.chain_tactics})}
            for ip, al in ips.items()]
    return sort_top_ips(rows)


def sort_top_ips(rows: list[dict]) -> list[dict]:
    rows = sorted(rows, key=lambda r: r["ip"])
    return sorted(rows, key=lambda r: (SEVERITY_ORDER[r["severity"]], r["count"]), reverse=True)[:TOP_N]


def agent_summary(alerts: list[Alert]) -> list[dict]:
    agents: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        agents[a.agent_name or "(manager)"].append(a)
    rows = []
    for name, al in agents.items():
        rows.append({
            "name": name, "id": al[0].agent_id, "ip": al[0].agent_ip, "count": len(al),
            "severity": worst(x.severity for x in al), "last_seen": max(x.ts for x in al),
            "by_severity": severity_counts(al),
        })
    return sort_agents(rows)


def sort_agents(rows: list[dict]) -> list[dict]:
    rows = sorted(rows, key=lambda r: r["name"])
    return sorted(rows, key=lambda r: (SEVERITY_ORDER[r["severity"]], r["count"]), reverse=True)


def rule_summary(alerts: list[Alert]) -> list[dict]:
    rules: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        rules[a.rule_id].append(a)
    rows = []
    for rid, al in rules.items():
        first = max(al, key=lambda x: x.ts)
        rows.append({
            "rule_id": rid, "description": first.description, "level": first.level,
            "severity": first.severity, "groups": first.groups, "mitre_ids": first.mitre_ids,
            "count": len(al), "sources": len({x.src_ip for x in al if x.src_ip}),
            "agents": sorted({x.agent_name for x in al}), "last_seen": max(x.ts for x in al),
        })
    return sort_rules(rows)


def sort_rules(rows: list[dict]) -> list[dict]:
    rows = sorted(rows, key=lambda r: r["rule_id"])
    return sorted(rows, key=lambda r: (r["level"], r["count"]), reverse=True)


def summarize(alerts: list[Alert], since: datetime, until: datetime, n: int = 48) -> dict:
    """Everything the overview needs, in one dict."""
    return {
        "total": len(alerts),
        "by_severity": severity_counts(alerts),
        "latest_ts": max((a.ts for a in alerts), default=None),
        "top_ips": top_ips(alerts),
        "top_rules": rule_summary(alerts)[:TOP_N],
        "tactics": tactic_coverage(alerts),
        "agents": agent_summary(alerts),
        "timeline": timeline(alerts, since, until, n),
    }


# ---- attack chain -------------------------------------------------------

def chain_steps(alerts: list[Alert]) -> list[dict]:
    """One step per (rule, agent): 'Nikto made 4,000 requests' is one line,
    however the rules interleave."""
    by_key: dict[tuple, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_key[(a.rule_id, a.agent_name)].append(a)
    steps = []
    for (rule_id, agent), al in by_key.items():
        al.sort(key=lambda a: a.ts)
        steps.append(make_step(
            rule_id=rule_id, agent=agent, count=len(al), first=al[0].ts, last=al[-1].ts,
            severity=worst(a.severity for a in al),
            tactics={t for a in al for t in a.chain_tactics},
            attempt=all(a.failed_web for a in al),
            mitre_ids={m for a in al for m in a.mitre_ids},
            users={u for a in al for u in (a.user, a.src_user, a.dst_user) if u},
            example=al[-1]))
    return sorted(steps, key=lambda s: s["first"])


def make_step(*, rule_id, agent, count, first, last, severity, tactics, attempt,
              mitre_ids, users, example) -> dict:
    ordered = sorted(tactics, key=lambda t: TACTIC_ORDER.get(t, 99))
    return {
        "rule_id": rule_id, "description": example.description, "severity": severity,
        "count": count, "first": first, "last": last, "agent": agent,
        "tactics": ordered, "stage": ordered[0] if ordered else None, "attempt": attempt,
        "mitre_ids": sorted(mitre_ids), "users": sorted(users), "example": example,
    }


def attack_chain(steps: list[dict]) -> dict | None:
    if not steps:
        return None
    reached = {t for s in steps for t in s["tactics"]}
    return {
        "steps": steps,
        "tactics": [{"tactic": t, "reached": t in reached} for t in TACTICS],
        "furthest": max(reached, key=lambda t: TACTIC_ORDER[t]) if reached else None,
        "agents": sorted({s["agent"] for s in steps}),
        "users": sorted({u for s in steps for u in s["users"]}),
        "first": min(s["first"] for s in steps),
        "last": max(s["last"] for s in steps),
        "severity": worst(s["severity"] for s in steps),
        "count": sum(s["count"] for s in steps),
        "attempts": sum(s["count"] for s in steps if s["attempt"]),
    }


def is_login(a: Alert) -> bool:
    """A successful login (Wazuh tags these authentication_success, and 40112
    'failures followed by a success' is one too)."""
    return "authentication_success" in a.groups or a.rule_id == "40112"


def follow_up(login_alerts: list[Alert], agent_alerts: dict[str, list[Alert]]) -> list[dict]:
    """What happened on each host right after the attacker logged in.

    Alerts like 'sudo to root' or 'new user added' carry no source IP, so
    Wazuh can't tie them to the attacker. Showing what the same host logged in
    the next 30 minutes is how an analyst would connect them by hand. It's
    correlation by time, not proof, and the page says so."""
    per_agent: dict[str, list[Alert]] = defaultdict(list)
    for login in login_alerts:
        per_agent[login.agent_name].append(login)
    out = []
    for agent, logins in per_agent.items():
        # one section per host: hydra's success, 40112 and the attacker's own
        # ssh session are usually seconds apart and describe one break-in
        logins.sort(key=lambda a: a.ts)
        start, until = logins[0].ts, logins[-1].ts + FOLLOW_UP_WINDOW
        after = [a for a in agent_alerts.get(agent, [])
                 if start < a.ts <= until and not a.src_ip and not _background(a)]
        if after:
            out.append({"login": logins[0], "logins": len(logins),
                        "alerts": sorted(after, key=lambda a: a.ts),
                        "steps": host_steps(after)})
    return sorted(out, key=lambda f: f["login"].ts)


# Alerts that describe the host, not anyone's actions: configuration
# assessment (CIS benchmark) results and the agent/manager's own status.
_BACKGROUND_GROUPS = {"sca", "ossec_agent_status"}
_BACKGROUND_RULES = {"501", "502", "503", "504", "506"}


def _background(a: Alert) -> bool:
    return a.rule_id in _BACKGROUND_RULES or bool(_BACKGROUND_GROUPS.intersection(a.groups))


def host_steps(alerts: list[Alert]) -> list[dict]:
    """After-login alerts grouped by rule, like the attack chain steps:
    38 sudo commands are one row with x38, not 38 rows."""
    by_rule: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        by_rule[a.rule_id].append(a)
    rows = []
    for rule_id, al in by_rule.items():
        al.sort(key=lambda a: a.ts)
        rows.append({
            "rule_id": rule_id, "description": al[-1].description, "count": len(al),
            "first": al[0].ts, "last": al[-1].ts, "severity": worst(a.severity for a in al),
            "who": sorted({a.who for a in al if a.who}),
            "mitre_ids": sorted({m for a in al for m in a.mitre_ids}), "example": al[-1],
        })
    return sorted(rows, key=lambda r: r["first"])
