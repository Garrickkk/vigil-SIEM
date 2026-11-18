"""Command line: `python -m vigil serve` and `python -m vigil check`.

Connection settings come from environment variables (or a .env file in the
repo root), so passwords never end up in your shell history:

  VIGIL_INDEXER_URL       default https://localhost:9200
  VIGIL_INDEXER_USER      default admin
  VIGIL_INDEXER_PASSWORD  required unless --demo
  VIGIL_CA_CERT           default wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem
  VIGIL_TLS_HOSTNAME      default wazuh.indexer (the name on the indexer's certificate)
  VIGIL_INDEX             default wazuh-alerts-*
  VIGIL_TRIAGE_DB         default vigil-triage.db
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CA = REPO_ROOT / "wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem"


def load_dotenv(path: Path) -> None:
    """Minimal .env reader: KEY=value lines, # comments. Real environment
    variables win over the file."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def make_source(demo: bool):
    from .sources import DemoSource, IndexerSource

    if demo:
        from .demo import generate
        return DemoSource(generate())

    password = os.environ.get("VIGIL_INDEXER_PASSWORD")
    if not password:
        sys.exit("VIGIL_INDEXER_PASSWORD isn't set. Put it in .env (see .env.example), "
                 "or run with --demo to try the dashboard without Wazuh.")
    ca = os.environ.get("VIGIL_CA_CERT") or str(DEFAULT_CA)
    if ca.lower() in ("false", "0", "no"):
        print("warning: TLS verification is OFF (VIGIL_CA_CERT=false). Lab use only.", file=sys.stderr)
        verify: str | bool = False
    elif not Path(ca).is_file():
        sys.exit(f"CA certificate not found: {ca}\n"
                 "Run .\\setup\\vigil.ps1 up first (it generates it), or set VIGIL_CA_CERT.")
    else:
        verify = ca
    return IndexerSource(
        url=os.environ.get("VIGIL_INDEXER_URL", "https://localhost:9200"),
        username=os.environ.get("VIGIL_INDEXER_USER", "admin"),
        password=password,
        ca_cert=verify,
        tls_hostname=os.environ.get("VIGIL_TLS_HOSTNAME", "wazuh.indexer") if verify else "",
        index=os.environ.get("VIGIL_INDEX", "wazuh-alerts-*"),
    )


def main(argv: list[str] | None = None) -> int:
    load_dotenv(REPO_ROOT / ".env")
    parser = argparse.ArgumentParser(prog="vigil", description="Triage dashboard for Wazuh alerts.")
    parser.add_argument("--version", action="version", version=f"vigil {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="run the dashboard")
    serve.add_argument("--demo", action="store_true", help="use built-in demo alerts instead of Wazuh")
    serve.add_argument("--host", default="127.0.0.1",
                       help="address to listen on (default 127.0.0.1; the dashboard has no login)")
    serve.add_argument("--port", type=int, default=5050)

    check = sub.add_parser("check", help="test the connection to the Wazuh indexer")
    check.add_argument("--demo", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args(argv)
    source = make_source(args.demo)

    if args.cmd == "check":
        ok, msg = source.health()
        print(("ok: " if ok else "error: ") + msg)
        return 0 if ok else 1

    from .web import create_app

    db = os.environ.get("VIGIL_TRIAGE_DB", "vigil-triage-demo.db" if args.demo else "vigil-triage.db")
    app = create_app(source, db)
    ok, msg = source.health()
    print(f"vigil {__version__} · source: {source.name} ({msg})")
    print(f"open http://{args.host}:{args.port}")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: listening beyond localhost, and the dashboard has no login.", file=sys.stderr)
    app.run(host=args.host, port=args.port, debug=False)
    return 0
