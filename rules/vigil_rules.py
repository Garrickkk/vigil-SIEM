"""Deploy Vigil's custom Wazuh rules and test them with wazuh-logtest.

    python rules/vigil_rules.py deploy   # copy rules + decoders in, restart the manager
    python rules/vigil_rules.py test     # run rules/tests.json through wazuh-logtest
    python rules/vigil_rules.py remove   # take them out again, restart the manager

Works on Windows, macOS and Linux; it only needs `docker` on the PATH and
the manager container from setup/vigil.ps1 running.

If the manager doesn't come back after `deploy` (usually a rule syntax
error), the script shows the error from ossec.log, removes the files and
restarts the manager, so a bad rule can't leave Wazuh down.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = {
    HERE / "vigil_rules.xml": "/var/ossec/etc/rules/vigil_rules.xml",
    HERE / "vigil_decoders.xml": "/var/ossec/etc/decoders/vigil_decoders.xml",
}


def docker(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["docker", *args], input=input_text, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        sys.exit(f"docker {' '.join(args[:3])}… failed:\n{proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def manager() -> str:
    names = docker("ps", "--filter", "name=wazuh.manager", "--format", "{{.Names}}").stdout.split()
    if not names:
        sys.exit("The Wazuh manager container isn't running. Start it with .\\setup\\vigil.ps1 up")
    return names[0]


def restart(container: str) -> bool:
    print("restarting the Wazuh manager (about 30 seconds)…")
    docker("exec", container, "/var/ossec/bin/wazuh-control", "restart", check=False)
    for _ in range(20):
        status = docker("exec", container, "/var/ossec/bin/wazuh-control", "status", check=False).stdout
        if re.search(r"wazuh-analysisd is running", status):
            return True
        time.sleep(3)
    return False


def deploy() -> None:
    c = manager()
    for local, remote in FILES.items():
        docker("cp", str(local), f"{c}:{remote}")
        docker("exec", c, "chown", "wazuh:wazuh", remote)
        docker("exec", c, "chmod", "660", remote)
        print(f"copied {local.name} -> {remote}")
    if restart(c):
        print("ok: manager running with Vigil rules. Next: python rules/vigil_rules.py test")
        return
    log = docker("exec", c, "tail", "-n", "30", "/var/ossec/logs/ossec.log", check=False).stdout
    errors = [line for line in log.splitlines() if "ERROR" in line or "CRITICAL" in line]
    print("error: the manager didn't start with the new rules. From ossec.log:")
    print("\n".join(errors[-10:]) or log)
    print("rolling back…")
    remove(quiet=True)
    sys.exit(1)


def remove(quiet: bool = False) -> None:
    c = manager()
    for remote in FILES.values():
        docker("exec", c, "rm", "-f", remote, check=False)
    ok = restart(c)
    if not quiet:
        print("removed Vigil rules" + ("" if ok else "; warning: manager not running, check .\\setup\\vigil.ps1 status"))


def logtest(container: str, lines: list[str]) -> list[str | None]:
    """Rule ID that fired for each line, in one logtest session (so
    frequency/correlation rules see the earlier lines)."""
    out = docker("exec", "-i", container, "/var/ossec/bin/wazuh-logtest",
                 input_text="\n".join(lines) + "\n").stdout
    chunks = out.split("**Phase 1: Completed pre-decoding.")[1:]
    ids: list[str | None] = []
    for chunk in chunks:
        phase3 = chunk.split("**Phase 3: Completed filtering (rules).")
        m = re.search(r"id: '(\d+)'", phase3[1]) if len(phase3) > 1 else None
        ids.append(m.group(1) if m else None)
    return ids


def expand(steps: list[dict]) -> tuple[list[str], list[tuple[int, int, dict]]]:
    lines, spans, n = [], [], 1
    for step in steps:
        start = len(lines)
        for _ in range(step.get("times", 1)):
            lines.append(step["log"].replace("{n}", str(n)))
            n += 1
        spans.append((start, len(lines), step))
    return lines, spans


def test(pattern: str = "") -> None:
    c = manager()
    cases = json.loads((HERE / "tests.json").read_text(encoding="utf-8"))["cases"]
    failed = skipped = 0
    for case in cases:
        if pattern and pattern.lower() not in case["name"].lower():
            continue
        if case.get("live_only"):
            skipped += 1
            print(f"  SKIP  {case['name']}\n        lab check: {case['live_only']}")
            continue
        lines, spans = expand(case["steps"])
        got = logtest(c, lines)
        problems = []
        if len(got) != len(lines):
            problems.append(f"logtest answered {len(got)} of {len(lines)} lines")
        else:
            for start, end, step in spans:
                last = got[end - 1]
                if "expect" in step and last not in step["expect"]:
                    problems.append(f"line {end}: expected {' or '.join(step['expect'])}, got {last}")
                bad = [g for g in got[start:end] if g in step.get("not", [])]
                if bad:
                    problems.append(f"lines {start + 1}-{end}: {bad[0]} fired but shouldn't")
        if problems:
            failed += 1
            print(f"  FAIL  {case['name']}")
            for p in problems:
                print(f"        {p}")
            print(f"        rule per line: {got}")
        else:
            print(f"  ok    {case['name']}")
    print(f"\n{'all passed' if not failed else f'{failed} failed'}"
          f"{f', {skipped} to check in the lab' if skipped else ''}")
    sys.exit(1 if failed else 0)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("deploy")
    t = sub.add_parser("test")
    t.add_argument("pattern", nargs="?", default="", help="only cases whose name contains this")
    sub.add_parser("remove")
    args = p.parse_args()
    {"deploy": deploy, "remove": remove}.get(args.cmd, lambda: test(args.pattern))()


if __name__ == "__main__":
    main()
