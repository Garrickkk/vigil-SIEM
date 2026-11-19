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

# Ubuntu 24.04+ logs to journald; auth.log only exists if rsyslog is installed.
if [[ ! -f /var/log/auth.log ]]; then
  echo "==> Installing rsyslog so /var/log/auth.log exists"
  apt-get install -y -q rsyslog >/dev/null
  systemctl enable --now rsyslog
fi

if ! grep -qF "$MARKER" "$OSSEC_CONF"; then
  echo "==> Adding extra log sources"
  # ossec.conf may contain several <ossec_config> blocks; appending one keeps
  # the packaged defaults untouched.
  {
    echo ""
    echo "$MARKER"
    echo "<ossec_config>"
    echo "  <localfile>"
    echo "    <log_format>syslog</log_format>"
    echo "    <location>/var/log/auth.log</location>"
    echo "  </localfile>"
    if [[ -d /var/log/nginx ]]; then
      echo "  <localfile>"
      echo "    <log_format>apache</log_format>"
      echo "    <location>/var/log/nginx/access.log</location>"
      echo "  </localfile>"
    fi
    echo "</ossec_config>"
  } >> "$OSSEC_CONF"
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
