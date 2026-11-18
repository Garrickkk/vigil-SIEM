"""Where alerts come from.

IndexerSource reads the wazuh-alerts-* indices straight from the Wazuh
indexer (OpenSearch). DemoSource serves a built-in attack story so the
dashboard can be tried without a running Wazuh.

Both return Alert objects, and every page is computed from those, so the
two sources behave the same way.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import ssl
from typing import Protocol

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

from .model import SEVERITY_MAX_LEVEL, SEVERITY_MIN_LEVEL, Alert


@dataclass
class Filters:
    severity: str = ""
    agent: str = ""
    rule_id: str = ""
    src_ip: str = ""
    mitre: str = ""   # technique ID (T1110) or tactic name (Credential Access)
    q: str = ""       # free text: description, raw log, IP, user, agent, rule ID

    @classmethod
    def from_args(cls, args) -> "Filters":
        return cls(**{k: (args.get(k) or "").strip() for k in asdict(cls())})

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


class DemoSource:
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


class IndexerSource:
    name = "indexer"

    def __init__(self, url: str, username: str, password: str, ca_cert: str | bool = True,
                 tls_hostname: str = "", index: str = "wazuh-alerts-*",
                 max_alerts: int = 5000, timeout: float = 15.0):
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

    # ---- query building (kept separate so it can be unit-tested) ---------

    def build_query(self, since: datetime, until: datetime, filters: Filters) -> dict:
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
        # Free text (filters.q) is matched in Python after fetching, so it
        # means exactly the same thing as in demo mode.
        return {
            "size": self.max_alerts,
            "sort": [{"timestamp": {"order": "desc"}}],
            "track_total_hits": True,
            "query": {"bool": {"filter": must}},
        }

    def _search(self, body: dict) -> dict:
        resp = self.session.post(f"{self.url}/{self.index}/_search", json=body, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def fetch(self, since, until, filters):
        result = self._search(self.build_query(since, until, filters))
        hits = result.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        alerts = [Alert.from_doc(h["_id"], h["_source"]) for h in hits.get("hits", [])]
        return [a for a in alerts if filters.matches(a)], total > len(alerts)

    def get(self, alert_id):
        result = self._search({"size": 1, "query": {"ids": {"values": [alert_id]}}})
        hits = result.get("hits", {}).get("hits", [])
        return Alert.from_doc(hits[0]["_id"], hits[0]["_source"]) if hits else None

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
