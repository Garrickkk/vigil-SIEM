#!/usr/bin/env bash
# Install the Wazuh agent on an Ubuntu/Debian lab VM and point it at your
# Wazuh manager.
#
#   sudo ./install-agent.sh <manager-ip> [agent-name]
#   sudo ./install-agent.sh 192.168.56.1 web01
#
# Besides the defaults (auth.log, syslog, file integrity, rootcheck, the
# netstat port check), it also collects the nginx access log if nginx is
# installed, which is the web source Trellis reads too.

set -euo pipefail

WAZUH_VERSION="4.14.7-1"
MANAGER="${1:-}"
AGENT_NAME="${2:-$(hostname)}"
OSSEC_CONF=/var/ossec/etc/ossec.conf
MARKER="<!-- vigil: extra log sources -->"

die() { echo "error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
[[ -n "$MANAGER" ]] || die "usage: sudo $0 <manager-ip> [agent-name]"
command -v apt-get >/dev/null || die "this script supports Ubuntu/Debian only"

echo "==> Adding the Wazuh apt repository"
apt-get install -y -q curl gnupg apt-transport-https >/dev/null
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | gpg --batch --yes --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update -q

echo "==> Installing wazuh-agent ${WAZUH_VERSION} (manager: ${MANAGER}, name: ${AGENT_NAME})"
WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" \
  apt-get install -y -q "wazuh-agent=${WAZUH_VERSION}"
# An agent newer than the manager can't connect, so don't let apt upgrade it.
apt-mark hold wazuh-agent >/dev/null

# Wazuh's "listening ports changed" check (rule 533) runs `netstat`, which
# Ubuntu 24.04 no longer installs. Without it the check fails silently and
# rule 533 never fires.
if ! command -v netstat >/dev/null; then
  echo "==> Installing net-tools (netstat) for the listening-ports check"
  apt-get install -y -q net-tools >/dev/null
fi

# Add a log source only if the packaged config doesn't already read it.
# Reading one event from two places doubles every count (and halves every
# threshold): on Ubuntu 24.04 the agent already reads the systemd journal,
# which holds every sshd/sudo/useradd message, and rsyslog writes the same
# messages to /var/log/auth.log. auth.log is also worse: rsyslog folds
# repeats into "message repeated 5 times: [...]", hiding failed logins.
reads() { grep -q "<location>$1</location>" "$OSSEC_CONF"; }

extra=""
if ! reads journald && ! reads /var/log/auth.log && [[ -f /var/log/auth.log ]]; then
  extra+="  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/auth.log</location>\n  </localfile>\n"
fi
if [[ -f /var/log/nginx/access.log ]] && ! reads /var/log/nginx/access.log; then
  extra+="  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/access.log</location>\n  </localfile>\n"
fi
if [[ -n "$extra" ]] && ! grep -qF "$MARKER" "$OSSEC_CONF"; then
  echo "==> Adding log sources the default config doesn't cover"
  printf '\n%s\n<ossec_config>\n%b</ossec_config>\n' "$MARKER" "$extra" >> "$OSSEC_CONF"
fi
echo "==> Log sources:"
grep -E "<location>" "$OSSEC_CONF" | sed 's/^ */    /'
if [[ $(grep -c "<location>/var/log/nginx/access.log</location>" "$OSSEC_CONF") -gt 1 ]]; then
  echo "    warning: nginx access.log is read twice; remove one <localfile> block" >&2
fi

systemctl daemon-reload
systemctl enable wazuh-agent >/dev/null
systemctl restart wazuh-agent

echo "==> Waiting for the agent to connect"
for _ in $(seq 1 12); do
  if grep -q "Connected to the server" /var/ossec/logs/ossec.log 2>/dev/null; then
    echo "    connected. It should show as 'active' in the dashboard within a minute."
    exit 0
  fi
  sleep 5
done
echo "    not connected yet. Check: tail -f /var/ossec/logs/ossec.log"
echo "    Most common cause: Windows Firewall blocking 1514/1515 (see docs/lab-setup.md)."
exit 1
