# Changelog

Versions follow 0.MINOR.PATCH until 1.0: minor = feature, patch = fix or docs.

## 0.3.3

- Brute-force blind spot re-tested with single counting; docs say 100101 fires, not 40112

## 0.3.2

- install-agent.sh only adds log sources the agent doesn't already read (journald + auth.log doubled every count)
- Corrected findings affected by the double counting

## 0.3.1

- Sudo rules hang off 5400: Wazuh's first-time-sudo rule hid everything under 5402
- vigil_rules.py sends bytes (Windows added \r to every log line) and reads logtest's stderr

## 0.3.0

- rules/: 9 custom Wazuh rules and a usermod decoder for gaps found in the lab
- rules/vigil_rules.py: deploy, test (wazuh-logtest) and remove
- comparison.md filled with observed results

## 0.2.0

- Summary pages counted by OpenSearch aggregations (no 5,000-alert cap)
- Attack chain: one step per rule and host; rejected web requests count as Reconnaissance only
- Show the logged event time when Wazuh received an event late
- install-agent.sh installs net-tools (rule 533 needs netstat on Ubuntu 24.04)

## 0.1.0

- Single-node Wazuh 4.14.7 on Docker Desktop (setup/vigil.ps1), dashboard/indexer/API bound to localhost
- agent/install-agent.sh to enroll Ubuntu/Debian lab VMs
- Triage dashboard: grouped alerts, attack chain per IP, ATT&CK overview, triage notes, CSV export, demo mode
- Docs: lab setup, attack scenarios, Trellis vs Wazuh comparison plan
