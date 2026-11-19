"""Flask dashboard for triaging Wazuh alerts."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import requests
from flask import (Flask, Response, abort, g, redirect, render_template, request,
                   url_for)

from .. import stats
from ..model import SEVERITIES, TACTICS
from ..sources import Filters, Source
from ..triage import STATUSES, TriageStore

RANGES = {"1h": timedelta(hours=1), "6h": timedelta(hours=6), "24h": timedelta(days=1),
          "7d": timedelta(days=7), "30d": timedelta(days=30)}
PAGE_SIZE = 50


def create_app(source: Source, triage_db: str) -> Flask:
    app = Flask(__name__)
    triage = TriageStore(triage_db)
    local_tz = datetime.now().astimezone().tzinfo

    # ---- template helpers ------------------------------------------------

    @app.template_filter("ts")
    def fmt_ts(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        return dt.astimezone(local_tz).strftime(fmt) if dt else "-"

    @app.template_filter("ago")
    def fmt_ago(dt: datetime | None) -> str:
        if dt is None:
            return "-"
        s = int((datetime.now(local_tz) - dt).total_seconds())
        if s < 5:
            return "just now"
        for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
            if s >= size:
                return f"{s // size}{unit} ago"
        return f"{s}s ago"

    @app.template_filter("duration")
    def fmt_duration(td: timedelta) -> str:
        s = int(td.total_seconds())
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s // 60}m {s % 60}s" if s % 60 else f"{s // 60}m"
        return f"{s // 3600}h {(s % 3600) // 60}m"

    @app.template_filter("mitre_url")
    def mitre_url(tid: str) -> str:
        return "https://attack.mitre.org/techniques/" + tid.strip().replace(".", "/") + "/"

    @app.template_global()
    def url_with(**changes) -> str:
        """The current URL with some query parameters changed (None removes one)."""
        args = request.args.to_dict()
        for k, v in changes.items():
            if v is None or v == "":
                args.pop(k, None)
            else:
                args[k] = v
        return url_for(request.endpoint, **(request.view_args or {}), **args)

    @app.context_processor
    def globals_():
        return {"RANGES": RANGES, "range_key": current_range_key(), "SEVERITIES": SEVERITIES,
                "STATUSES": STATUSES, "source_name": source.name, "source_health": health()}

    def health():
        if "health" not in g:
            g.health = source.health()
        return g.health

    def current_range_key(default: str = "24h") -> str:
        key = request.args.get("range", default)
        return key if key in RANGES else default

    def window(default: str = "24h") -> tuple[datetime, datetime]:
        now = datetime.now(local_tz)
        return now - RANGES[current_range_key(default)], now

    def fetch(since, until, filters: Filters | None = None):
        alerts, truncated = source.fetch(since, until, filters or Filters())
        g.truncated = getattr(g, "truncated", False) or truncated
        return alerts

    # ---- safety ----------------------------------------------------------

    @app.before_request
    def same_origin_posts():
        # The dashboard has no login, so stop other websites from making your
        # browser submit triage forms to it (CSRF): every POST must come from
        # a page on this same host.
        if request.method == "POST":
            origin = request.headers.get("Origin") or request.headers.get("Referer") or ""
            if urlsplit(origin).netloc != request.host:
                abort(403)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "script-src 'self'; frame-ancestors 'none'")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        return resp

    @app.errorhandler(requests.exceptions.RequestException)
    def source_down(err):
        ok, msg = source.health()
        return render_template("unreachable.html", message=msg, error=str(err)), 502

    # ---- pages -----------------------------------------------------------

    @app.route("/")
    def overview():
        since, until = window()
        triaged = triage.non_open()
        s = source.summarize(since, until, Filters())
        not_open = source.severity_counts(since, until, list(triaged))
        open_sev = {k: max(s["by_severity"][k] - not_open[k], 0) for k in SEVERITIES}
        s.update(by_severity=open_sev, open=sum(open_sev.values()),
                 urgent_open=open_sev["critical"] + open_sev["high"])
        groups = source.groups(since, until, Filters(), triaged)
        buckets = s["timeline"]
        return render_template(
            "overview.html", s=s, buckets=buckets,
            peak=max((b.total for b in buckets), default=0) or 1,
            since=since, until=until, groups=groups[:10], group_count=len(groups))

    @app.route("/alerts")
    def alerts():
        since, until = window()
        filters = Filters.from_args(request.args)
        status_filter = request.args.get("status", "open")
        view = "all" if request.args.get("view") == "all" else "grouped"
        if view == "grouped":
            groups = source.groups(since, until, filters, triage.non_open())
            alert_total = sum(g.count for g in groups)
            agents = sorted({g.agent_name for g in groups if g.agent_name})
            rows = [g for g in groups if not status_filter or g.status == status_filter]
            status = {}
        else:
            items = fetch(since, until, filters)
            alert_total = len(items)
            agents = sorted({a.agent_name for a in items if a.agent_name})
            status = triage.statuses([a.id for a in items])
            rows = [a for a in items if not status_filter or status[a.id] == status_filter]
        page = max(request.args.get("page", 1, type=int), 1)
        pages = max((len(rows) + PAGE_SIZE - 1) // PAGE_SIZE, 1)
        return render_template(
            "alerts.html", rows=rows[(page - 1) * PAGE_SIZE: page * PAGE_SIZE], total=len(rows),
            alert_total=alert_total, view=view, status=status, status_filter=status_filter,
            filters=filters, page=min(page, pages), pages=pages, agents=agents, tactics=TACTICS)

    @app.route("/alerts.csv")
    def alerts_csv():
        since, until = window()
        items = fetch(since, until, Filters.from_args(request.args))
        status = triage.statuses([a.id for a in items])
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["timestamp", "severity", "level", "rule_id", "description", "agent",
                    "src_ip", "user", "mitre", "status", "full_log", "id"])
        for a in items:
            w.writerow([_csv_safe(str(v)) for v in (
                a.ts.isoformat(), a.severity, a.level, a.rule_id, a.description,
                a.agent_name, a.src_ip, a.user, " ".join(a.mitre_ids),
                status[a.id], a.full_log, a.id)])
        name = f"vigil-alerts-{current_range_key()}.csv"
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={name}"})

    @app.route("/alert/<path:alert_id>")
    def alert_detail(alert_id):
        alert = source.get(alert_id)
        if alert is None:
            abort(404)
        until = datetime.now(local_tz)
        since = alert.ts - timedelta(days=7)
        key = "|".join(alert.group_key)
        group_ids = source.fetch_ids(since, until, Filters.for_group(key))
        others = []
        if alert.src_ip:
            steps = source.chain(alert.src_ip, since, until)
            others = sorted((st for st in steps if st["rule_id"] != alert.rule_id),
                            key=lambda st: st["last"], reverse=True)[:8]
        t = triage.get(alert.id)
        if t["updated_at"]:
            t["updated_at"] = datetime.fromtimestamp(t["updated_at"], local_tz)
        return render_template(
            "alert.html", a=alert, t=t, group_ids=group_ids, others=others,
            raw_json=json.dumps(alert.raw, indent=2, sort_keys=True))

    @app.route("/alert/<path:alert_id>/triage", methods=["POST"])
    def triage_alert(alert_id):
        status = request.form.get("status", "")
        if status not in STATUSES:
            abort(400)
        ids = [alert_id]
        if request.form.get("scope") == "group":
            alert = source.get(alert_id)
            if alert is not None:
                until = datetime.now(local_tz)
                ids = source.fetch_ids(alert.ts - timedelta(days=7), until,
                                       Filters.for_group("|".join(alert.group_key))) or ids
        triage.set(ids, status, note=request.form.get("note", "")[:2000])
        return redirect(url_for("alert_detail", alert_id=alert_id))

    @app.route("/triage", methods=["POST"])
    def triage_bulk():
        status = request.form.get("status", "")
        keys = set(request.form.getlist("group"))
        ids = set(request.form.getlist("alert"))
        if status not in STATUSES or not (keys or ids):
            return redirect(request.referrer or url_for("alerts"))
        if keys:
            key = request.form.get("range", "24h")
            until = datetime.now(local_tz)
            since = until - RANGES.get(key, RANGES["24h"])
            for k in keys:
                ids.update(source.fetch_ids(since, until, Filters.for_group(k)))
        triage.set(sorted(ids), status)
        return redirect(request.referrer or url_for("alerts"))

    @app.route("/ip/<addr>")
    def investigate(addr):
        since, until = window(default="7d")
        chain = stats.attack_chain(source.chain(addr, since, until))
        logged_in = source.logins(addr, since, until) if chain else []
        after = []
        if logged_in:
            per_agent = {}
            for name in {a.agent_name for a in logged_in}:
                times = [a.ts for a in logged_in if a.agent_name == name]
                per_agent[name] = source.host_activity(
                    name, min(times), min(until, max(times) + stats.FOLLOW_UP_WINDOW))
            after = stats.follow_up(logged_in, per_agent)
        return render_template("ip.html", addr=addr, chain=chain,
                               count=chain["count"] if chain else 0,
                               after=after, logged_in=logged_in)

    @app.route("/investigate")
    def investigate_search():
        addr = request.args.get("ip", "").strip()
        if not addr:
            return redirect(url_for("overview"))
        return redirect(url_for("investigate", addr=addr, range=request.args.get("range", "7d")))

    @app.route("/agents")
    def agents():
        since, until = window()
        return render_template("agents.html", rows=source.agent_summary(since, until, Filters()))

    @app.route("/rules")
    def rules():
        since, until = window()
        return render_template("rules.html", rows=source.rule_summary(since, until, Filters()))

    return app


def _csv_safe(text: str) -> str:
    """Log lines are attacker-controlled. A cell starting with = + - @ is run
    as a formula when the CSV is opened in Excel, so neutralize it."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
