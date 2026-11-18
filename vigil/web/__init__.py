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
        alerts = fetch(since, until)
        status = triage.statuses([a.id for a in alerts])
        groups = stats.group_alerts(alerts, status)
        buckets = stats.timeline(alerts, since, until)
        return render_template(
            "overview.html", s=stats.overview(alerts, status), buckets=buckets,
            peak=max((b.total for b in buckets), default=0) or 1,
            since=since, until=until, groups=groups[:10], group_count=len(groups))

    @app.route("/alerts")
    def alerts():
        since, until = window()
        filters = Filters.from_args(request.args)
        status_filter = request.args.get("status", "open")
        view = "all" if request.args.get("view") == "all" else "grouped"
        items = fetch(since, until, filters)
        status = triage.statuses([a.id for a in items])
        if view == "grouped":
            rows = stats.group_alerts(items, status)
            if status_filter:
                rows = [r for r in rows if r.status == status_filter]
        else:
            rows = [a for a in items if not status_filter or status[a.id] == status_filter]
        page = max(request.args.get("page", 1, type=int), 1)
        pages = max((len(rows) + PAGE_SIZE - 1) // PAGE_SIZE, 1)
        return render_template(
            "alerts.html", rows=rows[(page - 1) * PAGE_SIZE: page * PAGE_SIZE], total=len(rows),
            alert_total=len(items), view=view, status=status, status_filter=status_filter,
            filters=filters, page=min(page, pages), pages=pages,
            agents=sorted({a.agent_name for a in items}), tactics=TACTICS)

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
        same_group = []
        others = []
        if alert.src_ip:
            from_ip = fetch(since, until, Filters(src_ip=alert.src_ip))
            same_group = [a for a in from_ip if a.group_key == alert.group_key]
            seen = set()
            for a in from_ip:   # newest first; one row per other rule
                if a.rule_id != alert.rule_id and a.rule_id not in seen:
                    seen.add(a.rule_id)
                    others.append(a)
        t = triage.get(alert.id)
        if t["updated_at"]:
            t["updated_at"] = datetime.fromtimestamp(t["updated_at"], local_tz)
        return render_template(
            "alert.html", a=alert, t=t, same_group=same_group,
            others=others[:8], raw_json=json.dumps(alert.raw, indent=2, sort_keys=True))

    @app.route("/alert/<path:alert_id>/triage", methods=["POST"])
    def triage_alert(alert_id):
        status = request.form.get("status", "")
        if status not in STATUSES:
            abort(400)
        ids = [alert_id]
        if request.form.get("scope") == "group":
            ids = [i for i in request.form.get("group_ids", "").split(",") if i] or ids
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
            for a in fetch(since, until):
                if "|".join(a.group_key) in keys:
                    ids.add(a.id)
        triage.set(sorted(ids), status)
        return redirect(request.referrer or url_for("alerts"))

    @app.route("/ip/<addr>")
    def investigate(addr):
        since, until = window(default="7d")
        alerts = fetch(since, until, Filters(src_ip=addr))
        chain = stats.attack_chain(alerts) if alerts else None
        after = []
        logged_in = stats.logins(alerts)
        if logged_in:
            # one fetch per host the attacker got into
            per_agent = {}
            for name in {a.agent_name for a in logged_in}:
                start = min(a.ts for a in logged_in if a.agent_name == name)
                per_agent[name] = fetch(start, min(until, max(a.ts for a in logged_in) + stats.FOLLOW_UP_WINDOW),
                                        Filters(agent=name))
            after = stats.follow_up(logged_in, per_agent)
        return render_template("ip.html", addr=addr, chain=chain, count=len(alerts), after=after,
                               logged_in=logged_in)

    @app.route("/investigate")
    def investigate_search():
        addr = request.args.get("ip", "").strip()
        if not addr:
            return redirect(url_for("overview"))
        return redirect(url_for("investigate", addr=addr, range=request.args.get("range", "7d")))

    @app.route("/agents")
    def agents():
        since, until = window()
        return render_template("agents.html", rows=stats.agent_summary(fetch(since, until)))

    @app.route("/rules")
    def rules():
        since, until = window()
        return render_template("rules.html", rows=stats.rule_summary(fetch(since, until)))

    return app


def _csv_safe(text: str) -> str:
    """Log lines are attacker-controlled. A cell starting with = + - @ is run
    as a formula when the CSV is opened in Excel, so neutralize it."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
