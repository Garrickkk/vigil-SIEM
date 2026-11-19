# Changelog

Versions follow 0.MINOR.PATCH until 1.0: minor = feature, patch = fix or docs.

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
