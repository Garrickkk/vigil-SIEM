"""The rules/ tooling: logtest output parsing, test expansion, and that the
rule files and test cases agree with each other."""

import json
import re
import sys
import xml.dom.minidom
from pathlib import Path

RULES = Path(__file__).resolve().parent.parent / "rules"
sys.path.insert(0, str(RULES))
import vigil_rules  # noqa: E402

SAMPLE = """Starting wazuh-logtest v4.14.7
Type one log per line

**Phase 1: Completed pre-decoding.
	full event: 'a'
	program_name: 'sshd'

**Phase 2: Completed decoding.
	name: 'sshd'
	dstuser: 'deploy'

**Phase 3: Completed filtering (rules).
	id: '5760'
	level: '5'
**Alert to be generated.


**Phase 1: Completed pre-decoding.
	full event: 'b'

**Phase 2: Completed decoding.
	No decoder matched.

**Phase 1: Completed pre-decoding.
	full event: 'c'

**Phase 2: Completed decoding.
	name: 'sudo'

**Phase 3: Completed filtering (rules).
	id: '100110'
	level: '8'
**Alert to be generated.
"""


def test_logtest_output_parsing(monkeypatch):
    class P:
        stdout = SAMPLE
        returncode = 0
    monkeypatch.setattr(vigil_rules.subprocess, "run", lambda *a, **k: P())
    assert vigil_rules.logtest("mgr", ["a", "b", "c"]) == ["5760", None, "100110"]


def test_expand_counts_across_steps():
    lines, spans = vigil_rules.expand([{"log": "x{n}", "times": 2}, {"log": "y{n}"}])
    assert lines == ["x1", "x2", "y3"] and [s[:2] for s in spans] == [(0, 2), (2, 3)]


def test_rule_files_are_valid_and_ids_unique():
    text = (RULES / "vigil_rules.xml").read_text(encoding="utf-8")
    xml.dom.minidom.parseString("<root>" + text + "</root>")
    xml.dom.minidom.parseString("<root>" + (RULES / "vigil_decoders.xml").read_text(encoding="utf-8") + "</root>")
    ids = re.findall(r'<rule id="(\d+)"', text)
    assert len(ids) == len(set(ids)) and all(100000 <= int(i) < 110000 for i in ids)


def test_every_custom_rule_has_a_test_case():
    ids = set(re.findall(r'<rule id="(\d+)"', (RULES / "vigil_rules.xml").read_text(encoding="utf-8")))
    cases = json.loads((RULES / "tests.json").read_text(encoding="utf-8"))["cases"]
    tested = {e for c in cases for s in c["steps"] for e in s.get("expect", []) + s.get("not", [])}
    live = {"100150"} if any("100150" in c.get("live_only", "") for c in cases) else set()
    assert ids - tested - live == set()
