"""A tiny in-memory stand-in for OpenSearch's _search API.

It evaluates only the query and aggregation features Vigil uses, with
OpenSearch's semantics for them (multi-valued fields count in every bucket,
range "to" is exclusive, missing composite keys are null and sort first,
max/min on dates are epoch milliseconds). Tests feed the same alerts to
DemoSource and to an IndexerSource backed by this, and check that both
produce the same pages.
"""

from __future__ import annotations

import json
from vigil.model import parse_timestamp

DATE_FIELDS = {"timestamp"}


def values(src: dict, path: str) -> list:
    cur = [src]
    for part in path.split("."):
        nxt = []
        for c in cur:
            if isinstance(c, dict) and part in c:
                v = c[part]
                nxt.extend(v if isinstance(v, list) else [v])
        cur = nxt
    if path in DATE_FIELDS:
        return [int(parse_timestamp(v).timestamp() * 1000) for v in cur]
    return cur


def _num_or_date(field: str, v):
    if field in DATE_FIELDS and isinstance(v, str):
        return int(parse_timestamp(v).timestamp() * 1000)
    return v


def _cmp_ok(x, op, y) -> bool:
    if isinstance(y, str) and not isinstance(x, str):
        x = str(x)
    if isinstance(x, str) and not isinstance(y, str):
        y = str(y)
    return {"gte": x >= y, "gt": x > y, "lte": x <= y, "lt": x < y}[op]


def matches(doc_id: str, src: dict, q: dict) -> bool:
    (kind, spec), = q.items()
    if kind == "bool":
        def as_list(x):
            return x if isinstance(x, list) else [x] if x else []
        for clause in as_list(spec.get("filter")) + as_list(spec.get("must")):
            if not matches(doc_id, src, clause):
                return False
        for clause in as_list(spec.get("must_not")):
            if matches(doc_id, src, clause):
                return False
        should = as_list(spec.get("should"))
        if should:
            need = spec.get("minimum_should_match", 1)
            if sum(matches(doc_id, src, c) for c in should) < need:
                return False
        return True
    if kind == "range":
        (field, ops), = spec.items()
        vals = values(src, field)
        return any(all(_cmp_ok(v, op, _num_or_date(field, bound)) for op, bound in ops.items())
                   for v in vals)
    if kind == "term":
        (field, want), = spec.items()
        return any(str(v) == str(want) for v in values(src, field))
    if kind == "prefix":
        (field, want), = spec.items()
        return any(str(v).startswith(want) for v in values(src, field))
    if kind == "exists":
        return bool(values(src, spec["field"]))
    if kind == "ids":
        return doc_id in set(spec["values"])
    if kind == "match_all":
        return True
    raise NotImplementedError(kind)


def _source(src: dict, spec) -> dict | None:
    if spec is False:
        return None
    if not spec or spec is True:
        return src
    out: dict = {}
    for path in spec.get("includes", []):
        parts = path.split(".")
        cur, dst = src, out
        for i, p in enumerate(parts):
            if not isinstance(cur, dict) or p not in cur:
                break
            if i == len(parts) - 1:
                dst[p] = cur[p]
            else:
                dst = dst.setdefault(p, {})
                cur = cur[p]
    return out


def _sorted_docs(docs, sort):
    for spec in reversed(sort or []):
        (field, opts), = spec.items()
        rev = opts.get("order", "asc") == "desc"
        docs = sorted(docs, key=lambda d: (values(d[1], field) or [0])[0], reverse=rev)
    return docs


def aggregate(docs: list[tuple[str, dict]], aggs: dict) -> dict:
    return {name: _agg(docs, spec) for name, spec in aggs.items()}


def _agg(docs, spec) -> dict:
    sub = spec.get("aggs", {})
    kind = next(k for k in spec if k != "aggs")
    body = spec[kind]
    if kind in ("range", "date_range"):
        field = body["field"]
        out = {}
        for r in body["ranges"]:
            lo, hi = r.get("from"), r.get("to")
            sel = [d for d in docs if any((lo is None or v >= lo) and (hi is None or v < hi)
                                          for v in values(d[1], field))]
            out[r["key"]] = {"doc_count": len(sel), **aggregate(sel, sub)}
        assert body.get("keyed"), "Vigil always uses keyed ranges"
        return {"buckets": out}
    if kind == "terms":
        field = body["field"]
        groups: dict = {}
        for d in docs:
            vals = values(d[1], field)
            if not vals and "missing" in body:
                vals = [body["missing"]]
            for v in set(vals):
                groups.setdefault(v, []).append(d)
        ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), str(kv[0])))[:body.get("size", 10)]
        return {"buckets": [{"key": k, "doc_count": len(g), **aggregate(g, sub)} for k, g in ordered]}
    if kind in ("max", "min"):
        vals = [v for d in docs for v in values(d[1], body["field"])]
        return {"value": (max if kind == "max" else min)(vals) if vals else None}
    if kind == "cardinality":
        return {"value": len({v for d in docs for v in values(d[1], body["field"])})}
    if kind == "filter":
        sel = [d for d in docs if matches(d[0], d[1], body)]
        return {"doc_count": len(sel), **aggregate(sel, sub)}
    if kind == "top_hits":
        top = _sorted_docs(docs, body.get("sort"))[:body.get("size", 3)]
        return {"hits": {"hits": [{"_id": i, "_source": _source(s, body.get("_source"))} for i, s in top]}}
    if kind == "composite":
        groups = {}
        for d in docs:
            combos = [()]
            for source in body["sources"]:
                (name, s), = source.items()
                vals = values(d[1], s["terms"]["field"])
                if not vals:
                    if not s["terms"].get("missing_bucket"):
                        combos = []
                        break
                    vals = [None]
                combos = [c + ((name, v),) for c in combos for v in set(vals)]
            for c in combos:
                groups.setdefault(c, []).append(d)

        def sort_key(c):
            return tuple((v is not None, v if v is not None else "") for _, v in c)
        keys = sorted(groups, key=sort_key)
        after = body.get("after")
        if after:
            names = [next(iter(s)) for s in body["sources"]]
            a = sort_key(tuple((n, after[n]) for n in names))
            keys = [k for k in keys if sort_key(k) > a]
        page = keys[:body["size"]]
        buckets = [{"key": dict(k), "doc_count": len(groups[k]), **aggregate(groups[k], sub)} for k in page]
        out = {"buckets": buckets}
        if page and len(keys) > body["size"]:
            out["after_key"] = dict(page[-1])
        return out
    raise NotImplementedError(kind)


class FakeOpenSearch:
    def __init__(self, docs: list[tuple[str, dict]], reject_aggs: bool = False):
        self.docs = docs
        self.reject_aggs = reject_aggs
        self.requests: list[dict] = []

    def search(self, body: dict) -> tuple[int, dict]:
        body = json.loads(json.dumps(body))   # must be JSON-serializable, like the real thing
        self.requests.append(body)
        if self.reject_aggs and "aggs" in body:
            return 400, {"error": "unsupported aggregation"}
        hits = [d for d in self.docs if matches(d[0], d[1], body.get("query", {"match_all": {}}))]
        result: dict = {"hits": {"total": {"value": len(hits)}, "hits": [
            {"_id": i, "_source": _source(s, body.get("_source", True))}
            for i, s in _sorted_docs(hits, body.get("sort"))[:body.get("size", 10)]]}}
        if "aggs" in body:
            result["aggregations"] = aggregate(hits, body["aggs"])
        return 200, result


class FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status_code = status
        self.payload = payload
        self.text = json.dumps(payload)

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.exceptions.HTTPError(response=self)

    def json(self):
        return self.payload


def attach(source, fake: FakeOpenSearch) -> None:
    """Route an IndexerSource's HTTP calls to the fake."""
    source.session.post = lambda url, json=None, timeout=None: FakeResponse(*fake.search(json))

