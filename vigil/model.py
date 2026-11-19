"""The Alert model: one Wazuh alert document, flattened into the fields the
dashboard uses. Everything else stays available in `raw`."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 .. critical=4

# Wazuh rule levels run 0-15. Wazuh's own docs group them roughly like this:
# 0-3 noise/system, 4-6 low, 7-9 medium (bad but not urgent), 10-12 high
# (repeated attacks, multiple failures), 13-15 critical (high-confidence attack).
LEVEL_BANDS = [(13, "critical"), (10, "high"), (7, "medium"), (4, "low"), (0, "info")]
SEVERITY_MIN_LEVEL = dict((s, lvl) for lvl, s in LEVEL_BANDS)
SEVERITY_MAX_LEVEL = {"critical": 15, "high": 12, "medium": 9, "low": 6, "info": 3}

# MITRE ATT&CK Enterprise tactics in kill-chain order. Used to lay out an
# attacker's alerts as a story: recon first, impact last.
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]
TACTIC_ORDER = {t: i for i, t in enumerate(TACTICS)}


def level_to_severity(level: int) -> str:
    for floor, sev in LEVEL_BANDS:
        if level >= floor:
            return sev
    return "info"


def parse_timestamp(text: str) -> datetime:
    """Wazuh writes '2026-11-09T09:12:01.123+0700'. Older Pythons'
    fromisoformat rejects the '+0700' offset, so normalize it first."""
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    ts = datetime.fromisoformat(text)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


_ISO_AT_START = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))")
_ACCESS_LOG_TIME = re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")


def parse_event_time(full_log: str) -> datetime | None:
    """When the logged event actually happened, read from the raw log line.

    Wazuh's `timestamp` is when the manager *received* the event. After an
    outage the agent replays buffered events and they all get a fresh
    timestamp, so the original time only survives in the log line itself.
    Handles RFC 3339 syslog (Ubuntu 24.04's default) and nginx/Apache access
    logs; returns None for formats without a year or time zone."""
    m = _ISO_AT_START.match(full_log)
    if m:
        try:
            return parse_timestamp(m.group(1))
        except ValueError:
            return None
    m = _ACCESS_LOG_TIME.search(full_log)
    if m:
        try:
            return datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
    return None


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


@dataclass
class Alert:
    id: str
    ts: datetime
    rule_id: str
    level: int
    description: str
    groups: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    agent_id: str = ""
    agent_name: str = ""
    agent_ip: str = ""
    src_ip: str = ""
    user: str = ""
    src_user: str = ""
    dst_user: str = ""
    location: str = ""
    decoder: str = ""
    full_log: str = ""
    firedtimes: int = 0
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def severity(self) -> str:
        return level_to_severity(self.level)

    @property
    def http_status(self) -> str:
        """HTTP status code for web access log alerts (Wazuh decodes it as data.id)."""
        status = str((self.raw.get("data") or {}).get("id", ""))
        return status if status.isdigit() and len(status) == 3 else ""

    @property
    def failed_web(self) -> bool:
        """A web request the server refused or failed (4xx/5xx)."""
        return "web" in self.groups and self.http_status[:1] in ("4", "5")

    @property
    def chain_tactics(self) -> list[str]:
        """ATT&CK tactics that say how far an attacker actually got.

        Wazuh tags its web-attack rules with techniques like Process Injection
        and Exploit Public-Facing Application, so one Nikto scan of 404s
        "reaches" Initial Access, Privilege Escalation and Lateral Movement.
        A request the server rejected is an attempt, so it only counts as
        Reconnaissance."""
        if self.failed_web:
            return [t for t in self.mitre_tactics if t == "Reconnaissance"]
        return self.mitre_tactics

    @property
    def event_ts(self) -> datetime | None:
        return parse_event_time(self.full_log)

    @property
    def delay(self) -> float:
        """Seconds between the logged event and Wazuh receiving it (0 if unknown)."""
        ev = self.event_ts
        return max((self.ts - ev).total_seconds(), 0.0) if ev else 0.0

    @property
    def who(self) -> str:
        """'deploy → root' for sudo/su, otherwise just the user."""
        if self.src_user and self.dst_user and self.src_user != self.dst_user:
            return f"{self.src_user} → {self.dst_user}"
        return self.user

    @property
    def epoch(self) -> float:
        return self.ts.timestamp()

    @property
    def group_key(self) -> tuple[str, str, str]:
        """Alerts with the same rule, source IP and agent are one 'story'
        (8 failed logins from one IP are one thing to look at, not eight)."""
        return (self.rule_id, self.src_ip, self.agent_name)

    @classmethod
    def from_doc(cls, doc_id: str, src: dict) -> "Alert":
        rule = src.get("rule") or {}
        mitre = rule.get("mitre") or {}
        agent = src.get("agent") or {}
        data = src.get("data") or {}
        # Wazuh stores the username in different fields depending on the
        # decoder: dstuser for "Failed password for X", srcuser for
        # "Invalid user X" and sudo, plain user for some JSON logs.
        user = data.get("dstuser") or data.get("srcuser") or data.get("user") or ""
        return cls(
            id=doc_id,
            ts=parse_timestamp(src.get("timestamp") or src.get("@timestamp")),
            rule_id=str(rule.get("id", "")),
            level=int(rule.get("level", 0)),
            description=str(rule.get("description", "")).strip(),
            groups=_as_list(rule.get("groups")),
            mitre_ids=_as_list(mitre.get("id")),
            mitre_tactics=_as_list(mitre.get("tactic")),
            mitre_techniques=_as_list(mitre.get("technique")),
            agent_id=str(agent.get("id", "")),
            agent_name=str(agent.get("name", "")),
            agent_ip=str(agent.get("ip", "")),
            src_ip=str(data.get("srcip", "")),
            user=str(user),
            src_user=str(data.get("srcuser", "")),
            dst_user=str(data.get("dstuser", "")),
            location=str(src.get("location", "")),
            decoder=str((src.get("decoder") or {}).get("name", "")),
            full_log=str(src.get("full_log", "")),
            firedtimes=int(rule.get("firedtimes", 0) or 0),
            raw=src,
        )
