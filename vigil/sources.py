"""Where alerts come from.

IndexerSource reads the wazuh-alerts-* indices straight from the Wazuh
indexer (OpenSearch). DemoSource serves a built-in attack story so the
dashboard can be tried without a running Wazuh.

Both offer the same methods. Lists of alerts come back as Alert objects;
the summary pages (overview, rules, agents, attack chains, groups) come
back as the shapes defined in stats.py. DemoSource computes those in Python;
IndexerSource asks OpenSearch to count with aggregations, so a scan of
40,000 requests costs one small query instead of downloading 40,000 alerts.
"""

from __future__ import annotations

import ssl
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Protocol

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from . import stats
from .model import (SEVERITIES, SEVERITY_MAX_LEVEL, SEVERITY_MIN_LEVEL, Alert,
                    level_to_severity)


@dataclass
class Filters:
    severity: str = ""
    agent: str = ""
    rule_id: str = ""
    src_ip: str = ""
    mitre: str = ""   # technique ID (T1110) or tactic name (Credential Access)
    q: str = ""       # free text: description, raw log, IP, user, agent, rule ID
    no_src: str = ""  # "1": only alerts without a source IP (groups like sudo, useradd)

    @classmethod
    def from_args(cls, args) -> "Filters":
        return cls(**{k: (args.get(k) or "").strip() for k in asdict(cls())})

    @classmethod
    def for_group(cls, key: str) -> "Filters":
        """Filters matching exactly one group, from its 'rule|ip|agent' key."""
        rule_id, src_ip, agent = (key.split("|") + ["", "", ""])[:3]
        return cls(rule_id=rule_id, src_ip=src_ip, agent=agent, no_src="" if src_ip else "1")

    def active(self) -> dict[str, str]:
        return {k: v for k, v in asdict(self).items() if v}

    def matches(self, a: Alert) -> bool:
        if self.severity and a.severity != self.severity:
            return False
        if self.agent and a.agent_name != self.agent:
            return False
        if self.rule_id and a.rule_id != self.rule_id:
            return False
        if self.src_ip and a.src_ip != self.src_ip:
            return False
        if self.no_src and a.src_ip:
            return False
        if self.mitre and self.mitre not in a.mitre_ids and self.mitre not in a.mitre_tactics:
            return False
        if self.q:
            needle = self.q.lower()
            hay = " ".join((a.description, a.full_log, a.src_ip, a.user,
                            a.agent_name, a.rule_id)).lower()
            if needle not in hay:
                return False
        return True


class Source(Protocol):
    name: str

    def fetch(self, since: datetime, until: datetime, filters: Filters) -> tuple[list[Alert], bool]:
        """Alerts in [since, until], newest first, and whether the result was
        cut off at the source's limit."""

    def get(self, alert_id: str) -> Alert | None: ...
    def health(self) -> tuple[bool, str]: ...
    def summarize(self, since, until, filters, n=48) -> dict: ...
    def severity_counts(self, since, until, ids) -> dict[str, int]: ...
    def groups(self, since, until, filters, triaged) -> list[stats.GroupRow]: ...
    def rule_summary(self, since, until, filters) -> list[dict]: ...
    def agent_summary(self, since, until, filters) -> list[dict]: ...
    def chain(self, addr, since, until) -> list[dict]: ...
    def logins(self, addr, since, until) -> list[Alert]: ...
    def host_activity(self, agent, since, until) -> list[Alert]: ...
    def fetch_ids(self, since, until, filters) -> list[str]: ...


class PythonSummaries:
    """Summary methods computed in Python from fetched alerts. The reference
    implementation (used by DemoSource) and IndexerSource's fallback."""

    def _alerts(self, since, until, filters) -> list[Alert]:
        return self.fetch(since, until, filters)[0]

    def summarize(self, since, until, filters, n=48):
        return stats.summarize(self._alerts(since, until, filters), since, until, n)

    def severity_counts(self, since, until, ids):
        wanted = set(ids)
        return stats.severity_counts([a for a in self._alerts(since, until, Filters()) if a.id in wanted])

    def groups(self, since, until, filters, triaged):
        return stats.group_alerts(self._alerts(since, until, filters), triaged)

    def rule_summary(self, since, until, filters):
        return stats.rule_summary(self._alerts(since, until, filters))

    def agent_summary(self, since, until, filters):
        return stats.agent_summary(self._alerts(since, until, filters))

    def chain(self, addr, since, until):
        return stats.chain_steps(self._alerts(since, until, Filters(src_ip=addr)))

    def logins(self, addr, since, until):
        return [a for a in self._alerts(since, until, Filters(src_ip=addr)) if stats.is_login(a)]

    def host_activity(self, agent, since, until):
        return self._alerts(since, until, Filters(agent=agent, no_src="1"))

    def fetch_ids(self, since, until, filters):
        return [a.id for a in self._alerts(since, until, filters)]


class DemoSource(PythonSummaries):
    name = "demo"

    def __init__(self, docs: list[tuple[str, dict]]):
        self.alerts = sorted((Alert.from_doc(i, d) for i, d in docs),
                             key=lambda a: a.ts, reverse=True)
        self._by_id = {a.id: a for a in self.alerts}

    def fetch(self, since, until, filters):
        return [a for a in self.alerts if since <= a.ts <= until and filters.matches(a)], False

    def get(self, alert_id):
        return self._by_id.get(alert_id)

    def health(self):
        return True, "built-in demo data"


class _WazuhTLSAdapter(HTTPAdapter):
    """TLS settings for wazuh-docker's self-made certificates.

    1. Hostname: the indexer's certificate is issued to 'wazuh.indexer' (its
       name inside the Docker network), but from Windows you reach it as
       'localhost'. Rather than turning verification off, check the
       certificate against the name it was actually issued for.

    2. Python 3.13+ turns on strict X.509 checks, which reject Wazuh's root
       CA: its cert tool makes it with a plain `openssl req -x509`, so it has
       no keyUsage extension. Only that strict flag is cleared. The chain is
       still verified against the CA file, and the hostname is still checked.
    """

    def __init__(self, hostname: str, ca_file: str, **kwargs):
        self._hostname = hostname
        self._ca_file = ca_file
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context(cert_reqs=ssl.CERT_REQUIRED)
        ctx.load_verify_locations(cafile=self._ca_file)
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        kwargs["ssl_context"] = ctx
        if self._hostname:
            kwargs["assert_hostname"] = self._hostname
        super().init_poolmanager(*args, **kwargs)



# ---- OpenSearch query pieces ------------------------------------------------

# Severity bands as rule.level ranges ("to" is exclusive), matching model.LEVEL_BANDS.
LEVEL_RANGES = [
    {"key": "info", "to": 4}, {"key": "low", "from": 4, "to": 7},
    {"key": "medium", "from": 7, "to": 10}, {"key": "high", "from": 10, "to": 13},
    {"key": "critical", "from": 13},
]
SEVERITY_AGG = {"range": {"field": "rule.level", "keyed": True, "ranges": LEVEL_RANGES}}

# A web request the server rejected (4xx/5xx). Wazuh's access-log decoder
# stores the status code in data.id, a keyword field, hence prefix queries.
FAILED_WEB = {"bool": {
    "filter": [{"term": {"rule.groups": "web"}}],
    "should": [{"prefix": {"data.id": "4"}}, {"prefix": {"data.id": "5"}}],
    "minimum_should_match": 1,
}}

# Tactics the way Alert.chain_tactics counts them: every tactic for normal
# alerts, only Reconnaissance for rejected web requests.
TACTIC_AGGS = {
    "real": {"filter": {"bool": {"must_not": [FAILED_WEB]}},
             "aggs": {"t": {"terms": {"field": "rule.mitre.tactic", "size": 20},
                            "aggs": {"lvl": {"max": {"field": "rule.level"}}}}}},
    "recon": {"filter": {"bool": {"filter": [FAILED_WEB, {"term": {"rule.mitre.tactic": "Reconnaissance"}}]}},
              "aggs": {"lvl": {"max": {"field": "rule.level"}}}},
}

NEWEST = [{"timestamp": {"order": "desc"}}]
GROUP_SOURCES = [
    {"rule": {"terms": {"field": "rule.id"}}},
    {"ip": {"terms": {"field": "data.srcip", "missing_bucket": True}}},
    {"agent": {"terms": {"field": "agent.name", "missing_bucket": True}}},
]
RULE_TERMS = {
    "terms": {"field": "rule.id", "size": 500},
    "aggs": {
        "latest": {"top_hits": {"size": 1, "sort": NEWEST, "_source": {"includes": ["rule"]}}},
        "last": {"max": {"field": "timestamp"}},
        "srcs": {"cardinality": {"field": "data.srcip"}},
        "agents": {"terms": {"field": "agent.name", "size": 20}},
    },
}
AGENT_TERMS = {
    "terms": {"field": "agent.name", "size": 100, "missing": ""},
    "aggs": {
        "latest": {"top_hits": {"size": 1, "sort": NEWEST, "_source": {"includes": ["agent"]}}},
        "last": {"max": {"field": "timestamp"}},
        "sev": SEVERITY_AGG,
    },
}
MAX_IDS = 60000   # stays under OpenSearch's default max_terms_count (65536)


class AggregationError(Exception):
    """OpenSearch rejected an aggregation query (e.g. a mapping difference)."""


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _from_ms(value) -> datetime | None:
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc) if value is not None else None


def _sev_counts(agg: dict) -> dict[str, int]:
    buckets = agg.get("buckets", {})
    return {s: int(buckets.get(s, {}).get("doc_count", 0)) for s in SEVERITIES}


def _worst_from_counts(counts: dict[str, int]) -> str:
    return stats.worst(s for s, n in counts.items() if n) if any(counts.values()) else "info"


def _level_sev(agg: dict) -> str:
    v = agg.get("value")
    return level_to_severity(int(v)) if v is not None else "info"


def _tactics(aggs: dict) -> tuple[dict[str, int], dict[str, str]]:
    """Counts and worst severity per tactic from TACTIC_AGGS results."""
    counts, sev = {}, {}
    for b in aggs.get("real", {}).get("t", {}).get("buckets", []):
        counts[b["key"]] = b["doc_count"]
        sev[b["key"]] = _level_sev(b["lvl"])
    recon = aggs.get("recon", {})
    if recon.get("doc_count"):
        t = "Reconnaissance"
        counts[t] = counts.get(t, 0) + recon["doc_count"]
        sev[t] = stats.worst(x for x in (sev.get(t), _level_sev(recon["lvl"])) if x)
    return counts, sev


def _list(value) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def _top_source(bucket: dict, name: str = "latest") -> tuple[str, dict]:
    hit = bucket[name]["hits"]["hits"][0]
    return hit["_id"], hit["_source"]


class IndexerSource(PythonSummaries):
    name = "indexer"

    def __init__(self, url: str, username: str, password: str, ca_cert: str | bool = True,
                 tls_hostname: str = "", index: str = "wazuh-alerts-*",
                 max_alerts: int = 5000, timeout: float = 30.0):
        self.url = url.rstrip("/")
        self.index = index
        self.max_alerts = max_alerts
        self.timeout = timeout
        self.session = requests.Session()
        # Ignore HTTPS_PROXY / REQUESTS_CA_BUNDLE / .netrc from the environment.
        # requests lets REQUESTS_CA_BUNDLE override session.verify, which would
        # silently swap Wazuh's CA for another bundle; and the indexer is local,
        # so it should never go through a proxy.
        self.session.trust_env = False
        self.session.auth = (username, password)
        self.session.verify = ca_cert
        if isinstance(ca_cert, str):
            self.session.mount("https://", _WazuhTLSAdapter(tls_hostname, ca_cert))
        self._warned = False

    # ---- query building (kept separate so it can be unit-tested) ---------

    def query_filters(self, since: datetime, until: datetime, filters: Filters) -> dict:
        must: list[dict] = [{"range": {"timestamp": {
            "gte": since.isoformat(), "lte": until.isoformat()}}}]
        if filters.severity in SEVERITY_MIN_LEVEL:
            must.append({"range": {"rule.level": {
                "gte": SEVERITY_MIN_LEVEL[filters.severity],
                "lte": SEVERITY_MAX_LEVEL[filters.severity]}}})
        if filters.agent:
            must.append({"term": {"agent.name": filters.agent}})
        if filters.rule_id:
            must.append({"term": {"rule.id": filters.rule_id}})
        if filters.src_ip:
            must.append({"term": {"data.srcip": filters.src_ip}})
        if filters.mitre:
            must.append({"bool": {"minimum_should_match": 1, "should": [
                {"term": {"rule.mitre.id": filters.mitre}},
                {"term": {"rule.mitre.tactic": filters.mitre}}]}})
        query: dict = {"bool": {"filter": must}}
        if filters.no_src:
            query["bool"]["must_not"] = [{"exists": {"field": "data.srcip"}}]
        # Free text (filters.q) is matched in Python after fetching, so it
        # means exactly the same thing as in demo mode.
        return query

    def build_query(self, since: datetime, until: datetime, filters: Filters) -> dict:
        return {
            "size": self.max_alerts,
            "sort": NEWEST,
            "track_total_hits": True,
            "query": self.query_filters(since, until, filters),
        }

    def _search(self, body: dict) -> dict:
        resp = self.session.post(f"{self.url}/{self.index}/_search", json=body, timeout=self.timeout)
        if resp.status_code == 400 and "aggs" in body:
            raise AggregationError(resp.text[:500])
        resp.raise_for_status()
        return resp.json()

    def _aggregate(self, query: dict, aggs: dict, total: bool = False) -> dict:
        body = {"size": 0, "query": query, "aggs": aggs}
        if total:
            body["track_total_hits"] = True
        return self._search(body)

    def _fallback(self, err: Exception) -> None:
        if not self._warned:
            print(f"warning: OpenSearch rejected an aggregation, computing in Python "
                  f"instead (counts may be capped at {self.max_alerts}): {err}", file=sys.stderr)
            self._warned = True

    # ---- plain alert lists ---------------------------------------------------

    def fetch(self, since, until, filters):
        result = self._search(self.build_query(since, until, filters))
        hits = result.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        alerts = [Alert.from_doc(h["_id"], h["_source"]) for h in hits.get("hits", [])]
        return [a for a in alerts if filters.matches(a)], total > len(alerts)

    def _docs(self, query: dict, size: int) -> list[Alert]:
        result = self._search({"size": size, "sort": NEWEST, "query": query})
        return [Alert.from_doc(h["_id"], h["_source"]) for h in result.get("hits", {}).get("hits", [])]

    def get(self, alert_id):
        result = self._search({"size": 1, "query": {"ids": {"values": [alert_id]}}})
        hits = result.get("hits", {}).get("hits", [])
        return Alert.from_doc(hits[0]["_id"], hits[0]["_source"]) if hits else None

    def fetch_ids(self, since, until, filters):
        if filters.q:
            return super().fetch_ids(since, until, filters)
        result = self._search({"size": 10000, "_source": False,
                               "query": self.query_filters(since, until, filters)})
        return [h["_id"] for h in result.get("hits", {}).get("hits", [])]

    def logins(self, addr, since, until):
        q = self.query_filters(since, until, Filters(src_ip=addr))
        q["bool"]["filter"].append({"bool": {"minimum_should_match": 1, "should": [
            {"term": {"rule.groups": "authentication_success"}}, {"term": {"rule.id": "40112"}}]}})
        return self._docs(q, 500)

    def host_activity(self, agent, since, until):
        return self._docs(self.query_filters(since, until, Filters(agent=agent, no_src="1")), 1000)

    # ---- aggregated summaries --------------------------------------------

    def summarize(self, since, until, filters, n=48):
        if filters.q:
            return super().summarize(since, until, filters, n)
        edges = stats.bucket_edges(since, until, n)
        ranges = [{"key": str(i), "from": _ms(edges[i]),
                   "to": _ms(edges[i + 1]) + (1 if i == n - 1 else 0)} for i in range(n)]
        aggs = {
            "sev": SEVERITY_AGG,
            "latest": {"max": {"field": "timestamp"}},
            "ips": {"terms": {"field": "data.srcip", "size": 50},
                    "aggs": {"lvl": {"max": {"field": "rule.level"}}, **TACTIC_AGGS}},
            "rules": RULE_TERMS,
            "agents": AGENT_TERMS,
            "timeline": {"date_range": {"field": "timestamp", "keyed": True, "ranges": ranges},
                         "aggs": {"sev": SEVERITY_AGG}},
            **TACTIC_AGGS,
        }
        try:
            r = self._aggregate(self.query_filters(since, until, filters), aggs, total=True)
        except AggregationError as e:
            self._fallback(e)
            return super().summarize(since, until, filters, n)
        a = r["aggregations"]
        ips = []
        for b in a["ips"]["buckets"]:
            counts, _ = _tactics(b)
            ips.append({"ip": b["key"], "count": b["doc_count"], "severity": _level_sev(b["lvl"]),
                        "tactics": len(counts)})
        t_counts, t_sev = _tactics(a)
        timeline = [stats.Bucket(edges[i], _sev_counts(a["timeline"]["buckets"][str(i)]["sev"]))
                    for i in range(n)]
        return {
            "total": r["hits"]["total"]["value"],
            "by_severity": _sev_counts(a["sev"]),
            "latest_ts": _from_ms(a["latest"].get("value")),
            "top_ips": stats.sort_top_ips(ips),
            "top_rules": self._rule_rows(a["rules"])[:stats.TOP_N],
            "tactics": stats.tactic_rows(t_counts, t_sev),
            "agents": self._agent_rows(a["agents"]),
            "timeline": timeline,
        }

    def severity_counts(self, since, until, ids):
        if not ids:
            return dict.fromkeys(SEVERITIES, 0)
        q = self.query_filters(since, until, Filters())
        q["bool"]["filter"].append({"ids": {"values": list(ids)[:MAX_IDS]}})
        try:
            return _sev_counts(self._aggregate(q, {"sev": SEVERITY_AGG})["aggregations"]["sev"])
        except AggregationError as e:
            self._fallback(e)
            return super().severity_counts(since, until, ids)

    def rule_summary(self, since, until, filters):
        if filters.q:
            return super().rule_summary(since, until, filters)
        try:
            r = self._aggregate(self.query_filters(since, until, filters), {"rules": RULE_TERMS})
        except AggregationError as e:
            self._fallback(e)
            return super().rule_summary(since, until, filters)
        return self._rule_rows(r["aggregations"]["rules"])

    def agent_summary(self, since, until, filters):
        if filters.q:
            return super().agent_summary(since, until, filters)
        try:
            r = self._aggregate(self.query_filters(since, until, filters), {"agents": AGENT_TERMS})
        except AggregationError as e:
            self._fallback(e)
            return super().agent_summary(since, until, filters)
        return self._agent_rows(r["aggregations"]["agents"])

    @staticmethod
    def _rule_rows(agg: dict) -> list[dict]:
        rows = []
        for b in agg["buckets"]:
            _, src = _top_source(b)
            rule = src.get("rule", {})
            level = int(rule.get("level", 0))
            mitre = rule.get("mitre") or {}
            rows.append({
                "rule_id": str(b["key"]), "description": str(rule.get("description", "")).strip(),
                "level": level, "severity": level_to_severity(level),
                "groups": _list(rule.get("groups")), "mitre_ids": _list(mitre.get("id")),
                "count": b["doc_count"], "sources": int(b["srcs"]["value"]),
                "agents": sorted(x["key"] for x in b["agents"]["buckets"]),
                "last_seen": _from_ms(b["last"]["value"]),
            })
        return stats.sort_rules(rows)

    @staticmethod
    def _agent_rows(agg: dict) -> list[dict]:
        rows = []
        for b in agg["buckets"]:
            _, src = _top_source(b)
            agent = src.get("agent", {})
            counts = _sev_counts(b["sev"])
            rows.append({
                "name": b["key"] or "(manager)", "id": str(agent.get("id", "")),
                "ip": str(agent.get("ip", "")), "count": b["doc_count"],
                "severity": _worst_from_counts(counts), "last_seen": _from_ms(b["last"]["value"]),
                "by_severity": counts,
            })
        return stats.sort_agents(rows)

    def _composite(self, query: dict, sources: list, sub_aggs: dict, max_buckets: int = 2000) -> list[dict]:
        """All buckets of a composite aggregation, following after_key."""
        buckets, after = [], None
        while len(buckets) < max_buckets:
            comp: dict = {"size": 500, "sources": sources}
            if after:
                comp["after"] = after
            r = self._aggregate(query, {"c": {"composite": comp, "aggs": sub_aggs}})
            c = r["aggregations"]["c"]
            buckets.extend(c["buckets"])
            after = c.get("after_key")
            if not after or not c["buckets"]:
                break
        return buckets

    def groups(self, since, until, filters, triaged):
        if filters.q:
            return super().groups(since, until, filters, triaged)
        query = self.query_filters(since, until, filters)
        sub = {
            "first": {"min": {"field": "timestamp"}},
            "last": {"max": {"field": "timestamp"}},
            "lvl": {"max": {"field": "rule.level"}},
            "latest": {"top_hits": {"size": 1, "sort": NEWEST, "_source": {
                "includes": ["rule.description", "data.srcuser", "data.dstuser", "data.user"]}}},
        }
        try:
            buckets = self._composite(query, GROUP_SOURCES, sub)
            non_open = self._triaged_counts(query, triaged)
        except AggregationError as e:
            self._fallback(e)
            return super().groups(since, until, filters, triaged)
        rows = []
        for b in buckets:
            k = b["key"]
            key = (str(k["rule"]), k.get("ip") or "", k.get("agent") or "")
            doc_id, src = _top_source(b)
            data = src.get("data") or {}
            src_user, dst_user = data.get("srcuser", ""), data.get("dstuser", "")
            who = (f"{src_user} → {dst_user}" if src_user and dst_user and src_user != dst_user
                   else dst_user or src_user or data.get("user", ""))
            n_triaged, n_closed = non_open.get(key, (0, 0))
            rows.append(stats.GroupRow(
                rule_id=key[0], src_ip=key[1], agent_name=key[2], count=b["doc_count"],
                first_seen=_from_ms(b["first"]["value"]), last_seen=_from_ms(b["last"]["value"]),
                severity=_level_sev(b["lvl"]),
                latest=stats.LatestRef(doc_id, str((src.get("rule") or {}).get("description", "")).strip(), who),
                status=stats.status_from_counts(b["doc_count"], n_triaged, n_closed)))
        return stats.sort_groups(rows)

    def _triaged_counts(self, query: dict, triaged: dict[str, str]) -> dict[tuple, tuple[int, int]]:
        """Per group: how many alerts are acknowledged/closed, and how many closed."""
        if not triaged:
            return {}
        ids = list(triaged)[:MAX_IDS]
        closed = [i for i in ids if triaged[i] == "closed"]
        q = {"bool": {**query["bool"], "filter": query["bool"]["filter"] + [{"ids": {"values": ids}}]}}
        sub = {"closed": {"filter": {"ids": {"values": closed}}}}
        out = {}
        for b in self._composite(q, GROUP_SOURCES, sub):
            k = b["key"]
            out[(str(k["rule"]), k.get("ip") or "", k.get("agent") or "")] = (
                b["doc_count"], b["closed"]["doc_count"])
        return out

    def chain(self, addr, since, until):
        query = self.query_filters(since, until, Filters(src_ip=addr))
        sources = [{"rule": {"terms": {"field": "rule.id"}}},
                   {"agent": {"terms": {"field": "agent.name", "missing_bucket": True}}}]
        sub = {
            "first": {"min": {"field": "timestamp"}},
            "last": {"max": {"field": "timestamp"}},
            "lvl": {"max": {"field": "rule.level"}},
            "latest": {"top_hits": {"size": 1, "sort": NEWEST}},
            "mitre": {"terms": {"field": "rule.mitre.id", "size": 30}},
            "failed": {"filter": FAILED_WEB},
            "u1": {"terms": {"field": "data.dstuser", "size": 20}},
            "u2": {"terms": {"field": "data.srcuser", "size": 20}},
            "u3": {"terms": {"field": "data.user", "size": 20}},
            **TACTIC_AGGS,
        }
        try:
            buckets = self._composite(query, sources, sub)
        except AggregationError as e:
            self._fallback(e)
            return super().chain(addr, since, until)
        steps = []
        for b in buckets:
            doc_id, src = _top_source(b)
            t_counts, _ = _tactics(b)
            steps.append(stats.make_step(
                rule_id=str(b["key"]["rule"]), agent=b["key"].get("agent") or "",
                count=b["doc_count"], first=_from_ms(b["first"]["value"]),
                last=_from_ms(b["last"]["value"]), severity=_level_sev(b["lvl"]),
                tactics=set(t_counts), attempt=b["failed"]["doc_count"] == b["doc_count"],
                mitre_ids={x["key"] for x in b["mitre"]["buckets"]},
                users={x["key"] for u in ("u1", "u2", "u3") for x in b[u]["buckets"]},
                example=Alert.from_doc(doc_id, src)))
        return sorted(steps, key=lambda s: s["first"])

    def health(self):
        try:
            resp = self.session.get(f"{self.url}/_cluster/health", timeout=5)
            resp.raise_for_status()
            return True, f"indexer {resp.json().get('status', '?')}"
        except requests.exceptions.SSLError:
            return False, "TLS error: check VIGIL_CA_CERT and VIGIL_TLS_HOSTNAME"
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 401:
                return False, "indexer rejected the username/password"
            return False, f"indexer error: {e}"
        except requests.exceptions.RequestException:
            return False, f"can't reach the indexer at {self.url}"
