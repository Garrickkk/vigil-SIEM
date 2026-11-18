from datetime import datetime, timedelta, timezone

import pytest

from vigil import stats
from vigil.demo import generate
from vigil.model import Alert, level_to_severity, parse_timestamp
from vigil.sources import DemoSource, Filters, IndexerSource
from vigil.triage import TriageStore

UTC7 = timezone(timedelta(hours=7))
NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC7)


def doc(rule_id="5760", level=5, ts="2026-11-09T10:00:00.000+0700", srcip="192.0.2.77",
        agent="web01", groups=("sshd", "authentication_failed"), mitre=None, **data):
    d = {"timestamp": ts, "rule": {"id": rule_id, "level": level, "description": f"rule {rule_id}",
                                   "groups": list(groups), "firedtimes": 1},
         "agent": {"id": "001", "name": agent, "ip": "10.0.0.10"},
         "full_log": f"log for {rule_id}", "location": "/var/log/auth.log",
         "decoder": {"name": "sshd"}, "data": {"srcip": srcip, **data} if srcip else data}
    if mitre:
        d["rule"]["mitre"] = mitre
    return d


def alert(**kw) -> Alert:
    return Alert.from_doc(kw.pop("id", "a1"), doc(**kw))


# ---- model ------------------------------------------------------------------

@pytest.mark.parametrize("level,sev", [(0, "info"), (3, "info"), (4, "low"), (6, "low"),
                                       (7, "medium"), (9, "medium"), (10, "high"),
                                       (12, "high"), (13, "critical"), (15, "critical")])
def test_level_bands(level, sev):
    assert level_to_severity(level) == sev


def test_wazuh_timestamp_with_compact_offset():
    ts = parse_timestamp("2026-11-09T09:12:01.123+0700")
    assert ts.utcoffset() == timedelta(hours=7)
    assert ts.hour == 9


def test_from_doc_flattens_fields():
    a = alert(mitre={"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
              dstuser="deploy")
    assert (a.rule_id, a.level, a.severity) == ("5760", 5, "low")
    assert a.src_ip == "192.0.2.77" and a.user == "deploy" and a.agent_name == "web01"
    assert a.mitre_tactics == ["Credential Access"]


def test_who_shows_actor_and_target_for_sudo():
    a = alert(rule_id="5402", srcip=None, srcuser="deploy", dstuser="root")
    assert a.who == "deploy → root"
    assert alert(dstuser="deploy").who == "deploy"


def test_missing_optional_fields_dont_crash():
    a = Alert.from_doc("x", {"timestamp": "2026-11-09T10:00:00Z", "rule": {"id": "1", "level": 3}})
    assert a.src_ip == "" and a.mitre_ids == [] and a.agent_name == ""


# ---- filters & sources ----------------------------------------------------

def test_filters_match():
    a = alert(mitre={"id": ["T1110"], "tactic": ["Credential Access"]}, dstuser="deploy")
    assert Filters(severity="low").matches(a)
    assert not Filters(severity="high").matches(a)
    assert Filters(mitre="T1110").matches(a) and Filters(mitre="Credential Access").matches(a)
    assert Filters(q="DEPLOY").matches(a)   # case-insensitive free text
    assert not Filters(src_ip="10.0.0.1").matches(a)


def test_indexer_query_pushes_filters_down():
    src = IndexerSource("https://localhost:9200", "admin", "pw", ca_cert=False)
    q = src.build_query(NOW - timedelta(hours=1), NOW,
                        Filters(severity="high", agent="web01", src_ip="192.0.2.77", mitre="T1110", q="x"))
    f = q["query"]["bool"]["filter"]
    assert {"range": {"rule.level": {"gte": 10, "lte": 12}}} in f
    assert {"term": {"agent.name": "web01"}} in f
    assert {"term": {"data.srcip": "192.0.2.77"}} in f
    assert q["sort"] == [{"timestamp": {"order": "desc"}}]
    # free text is applied in Python, not sent to OpenSearch
    assert "x" not in str(f)


def test_indexer_pins_tls_hostname(tmp_path):
    import ssl
    import subprocess
    ca = tmp_path / "ca.pem"
    subprocess.run(["openssl", "req", "-x509", "-new", "-nodes", "-newkey", "rsa:2048", "-batch",
                    "-subj", "/OU=Wazuh/O=Wazuh/", "-keyout", str(tmp_path / "k"), "-out", str(ca)],
                   check=True, capture_output=True)
    src = IndexerSource("https://localhost:9200", "admin", "pw", ca_cert=str(ca),
                        tls_hostname="wazuh.indexer")
    kw = src.session.get_adapter("https://localhost:9200").poolmanager.connection_pool_kw
    assert kw["assert_hostname"] == "wazuh.indexer"
    assert kw["ssl_context"].verify_mode == ssl.CERT_REQUIRED


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.exceptions.HTTPError(response=self)

    def json(self):
        return self.payload


def test_indexer_fetch_parses_hits_and_flags_truncation(monkeypatch):
    src = IndexerSource("https://localhost:9200", "admin", "pw", ca_cert=False, max_alerts=1)
    payload = {"hits": {"total": {"value": 5}, "hits": [{"_id": "abc", "_source": doc()}]}}
    monkeypatch.setattr(src.session, "post", lambda *a, **k: FakeResponse(payload))
    alerts, truncated = src.fetch(NOW - timedelta(days=1), NOW, Filters())
    assert [a.id for a in alerts] == ["abc"] and truncated


def test_indexer_health_reports_bad_password(monkeypatch):
    src = IndexerSource("https://localhost:9200", "admin", "pw", ca_cert=False)
    monkeypatch.setattr(src.session, "get", lambda *a, **k: FakeResponse({}, status=401))
    ok, msg = src.health()
    assert not ok and "password" in msg


# ---- stats ------------------------------------------------------------------

def test_grouping_collapses_repeats_and_combines_status():
    al = [alert(id=f"f{i}", ts=f"2026-11-09T10:00:0{i}.000+0700") for i in range(5)]
    al += [alert(id="other", rule_id="5715", groups=("authentication_success",))]
    al.sort(key=lambda a: a.ts, reverse=True)
    groups = stats.group_alerts(al, {"f0": "closed", "f1": "acknowledged"})
    fails = next(g for g in groups if g.rule_id == "5760")
    assert fails.count == 5 and fails.status == "open"
    groups = stats.group_alerts(al, {f"f{i}": "closed" for i in range(5)})
    assert next(g for g in groups if g.rule_id == "5760").status == "closed"


def test_timeline_buckets_by_severity():
    since = NOW - timedelta(hours=4)
    al = [alert(level=12, ts="2026-11-09T11:59:00.000+0700"), alert(level=3, ts="2026-11-09T08:01:00.000+0700")]
    b = stats.timeline(al, since, NOW, n=4)
    assert b[-1].counts["high"] == 1 and b[0].counts["info"] == 1
    assert sum(x.total for x in b) == 2


def test_attack_chain_merges_runs_and_orders_tactics():
    al = [alert(id=f"f{i}", ts=f"2026-11-09T10:00:0{i}.000+0700",
                mitre={"id": ["T1110.001", "T1021.004"], "tactic": ["Lateral Movement", "Credential Access"]})
          for i in range(3)]
    al.append(alert(id="ok", rule_id="40112", level=12, ts="2026-11-09T10:00:09.000+0700",
                    mitre={"id": ["T1078"], "tactic": ["Initial Access"]}))
    chain = stats.attack_chain(al)
    assert [s["count"] for s in chain["steps"]] == [3, 1]
    assert chain["steps"][0]["stage"] == "Credential Access"   # earliest in kill-chain order
    assert chain["furthest"] == "Lateral Movement"


def test_follow_up_finds_host_activity_after_login():
    login = alert(id="login", rule_id="40112", ts="2026-11-09T10:00:00.000+0700")
    sudo = alert(id="sudo", rule_id="5402", srcip=None, ts="2026-11-09T10:05:00.000+0700")
    late = alert(id="late", rule_id="5902", srcip=None, ts="2026-11-09T11:00:00.000+0700")
    other_ip = alert(id="noise", ts="2026-11-09T10:06:00.000+0700", srcip="10.0.0.5")
    out = stats.follow_up([login], {"web01": [sudo, late, other_ip]})
    assert [a.id for a in out[0]["alerts"]] == ["sudo"]


def test_demo_story_is_consistent():
    src = DemoSource(generate(NOW))
    ids = [a.id for a in src.alerts]
    assert len(ids) == len(set(ids))
    alerts, _ = src.fetch(NOW - timedelta(days=1), NOW, Filters(src_ip="192.0.2.77"))
    rules = {a.rule_id for a in alerts}
    assert {"31103", "31104", "5760", "5763", "40112"} <= rules
    assert all(a.ts <= NOW for a in src.alerts)


# ---- triage -----------------------------------------------------------------

def test_triage_defaults_open_and_keeps_note():
    t = TriageStore(":memory:")
    assert t.statuses(["a", "b"]) == {"a": "open", "b": "open"}
    t.set(["a"], "acknowledged", note="my own test")
    t.set(["a"], "closed")   # status-only change keeps the note
    assert t.get("a")["status"] == "closed" and t.get("a")["note"] == "my own test"
    with pytest.raises(ValueError):
        t.set(["a"], "deleted")


def test_triage_handles_many_ids():
    t = TriageStore(":memory:")
    ids = [f"id{i}" for i in range(1200)]
    t.set(ids[:600], "closed")
    s = t.statuses(ids)
    assert s["id0"] == "closed" and s["id1199"] == "open"
