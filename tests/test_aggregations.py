"""IndexerSource (OpenSearch aggregations) must agree with the Python
reference implementation (DemoSource) on the same alerts."""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from fake_opensearch import FakeOpenSearch, attach
from vigil import stats
from vigil.demo import generate
from vigil.sources import DemoSource, Filters, IndexerSource

NOW = datetime(2026, 11, 16, 23, 59, tzinfo=timezone(timedelta(hours=7)))
SINCE, UNTIL = NOW - timedelta(days=1), NOW


def scan_burst(start: datetime, n: int = 300) -> list[tuple[str, dict]]:
    """A Nikto-style scan: three rules interleaving, mostly 404s, a couple of
    200s, all from one IP. Real data that produced 802 steps before."""
    docs = []
    rules = [("31101", 5, "Web server 400 error code.", [], []),
             ("31104", 6, "Common web attack.", ["T1055", "T1083"],
              ["Defense Evasion", "Discovery", "Privilege Escalation"]),
             ("31151", 10, "Multiple web server 400 error codes from same source ip.", ["T1595.002"],
              ["Reconnaissance"])]
    for i in range(n):
        rid, level, desc, ids, tactics = rules[i % 3]
        status = "200" if i in (4, 7) else "404"
        ts = start + timedelta(seconds=i)
        rule = {"id": rid, "level": level, "description": desc, "groups": ["web", "accesslog", "attack"]}
        if ids:
            rule["mitre"] = {"id": ids, "tactic": tactics, "technique": ["x"] * len(ids)}
        stamp = ts.astimezone(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
        docs.append((f"scan-{i:04d}", {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000%z"), "rule": rule,
            "agent": {"id": "001", "name": "web01", "ip": "10.0.0.10"},
            "data": {"srcip": "192.168.56.102", "id": status, "url": f"/p{i}"},
            "full_log": f'192.168.56.102 - - [{stamp}] "GET /p{i} HTTP/1.1" {status} 162 "-" "Nikto"',
            "decoder": {"name": "web-accesslog"}, "location": "/var/log/nginx/access.log"}))
    return docs


@pytest.fixture(scope="module")
def docs():
    return generate(NOW) + scan_burst(NOW - timedelta(hours=2))


@pytest.fixture(scope="module")
def demo(docs):
    return DemoSource(copy.deepcopy(docs))


@pytest.fixture(scope="module")
def indexer(docs):
    src = IndexerSource("https://localhost:9200", "admin", "pw", ca_cert=False, max_alerts=50)
    attach(src, FakeOpenSearch(copy.deepcopy(docs)))
    return src


def rows(items, keys):
    return [{k: (r[k] if isinstance(r, dict) else getattr(r, k)) for k in keys} for r in items]


def test_summarize_matches(demo, indexer):
    a = demo.summarize(SINCE, UNTIL, Filters())
    b = indexer.summarize(SINCE, UNTIL, Filters())
    for key in ("total", "by_severity", "latest_ts", "top_ips", "tactics"):
        assert a[key] == b[key], key
    assert rows(a["top_rules"], ("rule_id", "count", "level", "description")) == \
        rows(b["top_rules"], ("rule_id", "count", "level", "description"))
    assert a["agents"] == b["agents"]
    assert [x.counts for x in a["timeline"]] == [x.counts for x in b["timeline"]]
    assert b["total"] > indexer.max_alerts   # counted by OpenSearch, not capped by the fetch limit


def test_summary_is_one_aggregation_query(docs):
    fake = FakeOpenSearch(copy.deepcopy(docs))
    src = IndexerSource("https://x:9200", "a", "b", ca_cert=False)
    attach(src, fake)
    src.summarize(SINCE, UNTIL, Filters())
    assert len(fake.requests) == 1 and fake.requests[0]["size"] == 0


def test_rule_and_agent_summaries_match(demo, indexer):
    keys = ("rule_id", "description", "level", "severity", "groups", "mitre_ids", "count",
            "sources", "agents", "last_seen")
    assert rows(demo.rule_summary(SINCE, UNTIL, Filters()), keys) == \
        rows(indexer.rule_summary(SINCE, UNTIL, Filters()), keys)
    assert demo.agent_summary(SINCE, UNTIL, Filters()) == indexer.agent_summary(SINCE, UNTIL, Filters())


def test_groups_and_statuses_match(demo, indexer, docs):
    scan_ids = [i for i, _ in docs if i.startswith("scan-")]
    triaged = {scan_ids[0]: "closed", **{i: "acknowledged" for i in scan_ids[1:3]}}
    for i, d in docs:   # close a whole group: every 5760 from 192.0.2.77
        if d["rule"]["id"] == "5760" and (d.get("data") or {}).get("srcip") == "192.0.2.77":
            triaged[i] = "closed"
    keys = ("key", "count", "severity", "status", "first_seen", "last_seen")
    a = sorted(rows(demo.groups(SINCE, UNTIL, Filters(), triaged), keys), key=lambda r: r["key"])
    b = sorted(rows(indexer.groups(SINCE, UNTIL, Filters(), triaged), keys), key=lambda r: r["key"])
    assert a == b
    statuses = {r["key"]: r["status"] for r in b}
    assert statuses["5760|192.0.2.77|web01"] == "closed"
    assert statuses["31101|192.168.56.102|web01"] == "open"


def test_groups_follow_composite_pages(docs):
    fake = FakeOpenSearch(copy.deepcopy(docs))
    src = IndexerSource("https://x:9200", "a", "b", ca_cert=False)
    attach(src, fake)
    import vigil.sources as s
    orig = s.IndexerSource._composite

    def tiny_pages(self, query, sources, sub, max_buckets=2000):
        # same logic, 3 buckets per page, to exercise after_key
        buckets, after = [], None
        while True:
            comp = {"size": 3, "sources": sources, **({"after": after} if after else {})}
            c = self._aggregate(query, {"c": {"composite": comp, "aggs": sub}})["aggregations"]["c"]
            buckets.extend(c["buckets"])
            after = c.get("after_key")
            if not after:
                return buckets
    s.IndexerSource._composite = tiny_pages
    try:
        paged = src.groups(SINCE, UNTIL, Filters(), {})
    finally:
        s.IndexerSource._composite = orig
    assert len(paged) == len(DemoSource(copy.deepcopy(docs)).groups(SINCE, UNTIL, Filters(), {}))


@pytest.mark.parametrize("addr", ["192.0.2.77", "192.168.56.102", "203.0.113.45"])
def test_attack_chain_matches(demo, indexer, addr):
    keys = ("rule_id", "agent", "count", "first", "last", "severity", "tactics", "stage",
            "attempt", "mitre_ids", "users")
    assert rows(demo.chain(addr, SINCE, UNTIL), keys) == rows(indexer.chain(addr, SINCE, UNTIL), keys)


def test_scan_is_three_steps_and_only_reconnaissance(indexer):
    chain = stats.attack_chain(indexer.chain("192.168.56.102", SINCE, UNTIL))
    assert len(chain["steps"]) == 3          # was one step per interleaved run
    assert chain["count"] == 300
    # the two 200 responses keep 31104's tactics; everything rejected counts as recon only
    by_rule = {s["rule_id"]: s for s in chain["steps"]}
    assert by_rule["31151"]["attempt"] and by_rule["31151"]["tactics"] == ["Reconnaissance"]
    assert not by_rule["31104"]["attempt"]   # contains a 200
    assert "Privilege Escalation" in by_rule["31104"]["tactics"]


def test_rejected_scan_does_not_reach_lateral_movement(docs):
    only_404 = [(i, d) for i, d in scan_burst(NOW - timedelta(hours=2)) if d["data"]["id"] == "404"]
    chain = stats.attack_chain(DemoSource(only_404).chain("192.168.56.102", SINCE, UNTIL))
    assert chain["furthest"] == "Reconnaissance"


def test_logins_host_activity_ids_and_severity_counts_match(demo, indexer, docs):
    def ids(alerts):
        return sorted(a.id for a in alerts)
    assert ids(demo.logins("192.0.2.77", SINCE, UNTIL)) == ids(indexer.logins("192.0.2.77", SINCE, UNTIL))
    assert ids(demo.host_activity("web01", SINCE, UNTIL)) == ids(indexer.host_activity("web01", SINCE, UNTIL))
    f = Filters.for_group("5402||web01")
    assert sorted(demo.fetch_ids(SINCE, UNTIL, f)) == sorted(indexer.fetch_ids(SINCE, UNTIL, f))
    some = [i for i, _ in docs][::7]
    assert demo.severity_counts(SINCE, UNTIL, some) == indexer.severity_counts(SINCE, UNTIL, some)


def test_free_text_and_rejected_aggs_fall_back_to_python(docs, capsys):
    src = IndexerSource("https://x:9200", "a", "b", ca_cert=False)
    attach(src, FakeOpenSearch(copy.deepcopy(docs), reject_aggs=True))
    out = src.summarize(SINCE, UNTIL, Filters())
    assert out["total"] > 0 and "computing in Python" in capsys.readouterr().err
    q = src.summarize(SINCE, UNTIL, Filters(q="sqlmap"))
    assert all(r["rule_id"] == "31103" for r in q["top_rules"])


def test_event_time_from_raw_log():
    from vigil.model import Alert
    delayed = Alert.from_doc("x", {
        "timestamp": "2026-11-16T17:05:12.000+0000", "rule": {"id": "5715", "level": 3},
        "full_log": "2026-11-16T16:55:30.123456+00:00 web01 sshd[9]: Accepted password for deploy"})
    assert delayed.event_ts.minute == 55 and 580 < delayed.delay < 590
    on_time = Alert.from_doc("y", {"timestamp": "2026-11-16T16:55:31.000+0000",
                                   "rule": {"id": "1", "level": 3}, "full_log": "Nov 16 16:55:30 x"})
    assert on_time.event_ts is None and on_time.delay == 0
