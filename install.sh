#!/usr/bin/env bash
# VPSentry installer: Ubuntu 22.04+ / Debian 12+, systemd, x86_64 or aarch64.
set -Eeuo pipefail
umask 027
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_BASE=/opt/vpsentry
CONFIG_DIR=/etc/vpsentry
DATA_DIR=/var/lib/vpsentry
VPSENTRY_BUILD_DIR=''
PREVIOUS_RELEASE=''
SWITCHED=0

fail() { printf '\nVPSentry installation failed: %s\n' "$*" >&2; exit 1; }
on_error() {
  local result=$?
  printf '\nInstallation failed at line %s (exit %s). Existing database and configuration have been preserved.\n' "$1" "$result" >&2
  if [[ "$SWITCHED" == 1 && -n "$PREVIOUS_RELEASE" ]]; then
    ln -sfn "$PREVIOUS_RELEASE" "$INSTALL_BASE/current"
    systemctl restart vpsentry vpsentry-network || true
    printf 'Restored previous application release: %s\n' "$PREVIOUS_RELEASE" >&2
  fi
  printf 'Inspect: journalctl -u vpsentry -u vpsentry-network -n 50 --no-pager\n' >&2
  exit "$result"
}
trap 'on_error "$LINENO"' ERR
[[ "$(uname -s)" == Linux ]] || fail 'This installer requires Ubuntu/Debian Linux.'
[[ "$EUID" == 0 ]] || fail 'Run sudo ./install.sh.'
[[ -r /etc/os-release ]] || fail '/etc/os-release is missing.'
# shellcheck disable=SC1091
. /etc/os-release
case "$ID" in
  ubuntu) [[ "${VERSION_ID%%.*}" -ge 22 ]] || fail 'Ubuntu 22.04 or newer is required.' ;;
  debian) [[ "${VERSION_ID%%.*}" -ge 12 ]] || fail 'Debian 12 or newer is required.' ;;
  *) fail 'Supported distributions: Ubuntu 22.04+ and Debian 12+.' ;;
esac
[[ -d /run/systemd/system ]] || fail 'A running systemd instance is required; ordinary containers are not supported.'
case "$(uname -m)" in x86_64) NODE_ARCH=x64 ;; aarch64|arm64) NODE_ARCH=arm64 ;; *) fail 'Only x86_64 and arm64 are supported.' ;; esac
[[ -f "$SOURCE_DIR/frontend/package-lock.json" ]] || fail 'frontend/package-lock.json is missing. Download the complete source release.'
exec 9>/run/lock/vpsentry-install.lock
flock -n 9 || fail 'Another VPSentry installer is running.'
export DEBIAN_FRONTEND=noninteractive
printf 'Installing operating system dependencies…\n'
apt-get update
apt-get install -y python3 python3-venv python3-pip build-essential ca-certificates curl xz-utils rsync iproute2 nftables iptables
getent group vpsentry >/dev/null || groupadd --system vpsentry
id vpsentry >/dev/null 2>&1 || useradd --system --gid vpsentry --home-dir "$DATA_DIR" --shell /usr/sbin/nologin vpsentry
getent group adm >/dev/null || groupadd --system adm
getent group systemd-journal >/dev/null || groupadd --system systemd-journal
usermod -aG adm,systemd-journal vpsentry
install -d -o root -g root -m 0755 "$INSTALL_BASE" "$INSTALL_BASE/releases" "$INSTALL_BASE/tools"
install -d -o root -g vpsentry -m 0750 "$CONFIG_DIR"
install -d -o vpsentry -g vpsentry -m 0750 "$DATA_DIR"

# Isolated official Node runtime: no changes to the machine's default Node installation.
NODE_VERSION=22.23.2
NODE_DIRECTORY="$INSTALL_BASE/tools/node-v$NODE_VERSION-linux-$NODE_ARCH"
if [[ ! -x "$NODE_DIRECTORY/bin/node" ]]; then
  VPSENTRY_BUILD_DIR="$(mktemp -d /tmp/vpsentry-node.XXXXXX)"
  NODE_ARCHIVE="node-v$NODE_VERSION-linux-$NODE_ARCH.tar.xz"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 "https://nodejs.org/dist/v$NODE_VERSION/$NODE_ARCHIVE" -o "$VPSENTRY_BUILD_DIR/$NODE_ARCHIVE"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt" -o "$VPSENTRY_BUILD_DIR/SHASUMS256.txt"
  (cd "$VPSENTRY_BUILD_DIR" && awk -v name="$NODE_ARCHIVE" '$2 == name {print}' SHASUMS256.txt > selected.sha256 && test -s selected.sha256 && sha256sum -c selected.sha256)
  tar -xJf "$VPSENTRY_BUILD_DIR/$NODE_ARCHIVE" -C "$INSTALL_BASE/tools" --no-same-owner
  rm -rf -- "$VPSENTRY_BUILD_DIR"
fi
RELEASE="$INSTALL_BASE/releases/$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -o vpsentry -g vpsentry -m 0755 "$RELEASE"
rsync -a --exclude='.git' --exclude='.venv' --exclude='.env' --exclude='data' --exclude='node_modules' --exclude='dist' --exclude='__pycache__' --exclude='.pytest_cache' --exclude='artifacts' --exclude='.impeccable' "$SOURCE_DIR/" "$RELEASE/"
chown -R vpsentry:vpsentry "$RELEASE"
printf 'Building isolated application release…\n'
runuser -u vpsentry -- python3 -m venv "$RELEASE/.venv"
runuser -u vpsentry -- "$RELEASE/.venv/bin/pip" install --no-cache-dir -r "$RELEASE/requirements.txt"
runuser -u vpsentry -- env PATH="$NODE_DIRECTORY/bin:/usr/bin:/bin" npm_config_cache="$DATA_DIR/.npm" npm --prefix "$RELEASE/frontend" ci --no-audit --no-fund
runuser -u vpsentry -- env PATH="$NODE_DIRECTORY/bin:/usr/bin:/bin" npm --prefix "$RELEASE/frontend" run build
# Validate imports and bytecode before replacing the running release.
runuser -u vpsentry -- "$RELEASE/.venv/bin/python" -m compileall -q "$RELEASE/backend"
chown -R root:root "$RELEASE"
chmod -R go-w "$RELEASE"

if [[ ! -f "$CONFIG_DIR/vpsentry.env" ]]; then
  # Password is generated in Python; it is never placed in argv or shell history.
  (cd "$RELEASE" && VPSENTRY_CONFIG_DIR="$CONFIG_DIR" "$RELEASE/.venv/bin/python" - <<'PY'
import os, secrets
from pathlib import Path
from backend.services.auth import hash_password
config = Path(os.environ['VPSENTRY_CONFIG_DIR'])
password = secrets.token_urlsafe(24)
text = Path('.env.example').read_text().replace('VPSENTRY_PASSWORD_HASH=\n', 'VPSENTRY_PASSWORD_HASH=' + hash_password(password) + '\n')
(config / 'vpsentry.env').write_text(text)
(config / 'initial-credentials').write_text('Username: admin\nPassword: ' + password + '\n')
os.chmod(config / 'initial-credentials', 0o600)
PY
  )
fi
chown root:vpsentry "$CONFIG_DIR/vpsentry.env"
chmod 0640 "$CONFIG_DIR/vpsentry.env"
# Load through Settings, not by executing an environment file as a root shell.
(cd "$RELEASE" && runuser -u vpsentry -- "$RELEASE/.venv/bin/python" - <<'PY'
from backend.config import Settings
from backend.models.store import Store
config = Settings(_env_file='/etc/vpsentry/vpsentry.env')
if not config.password_hash:
    raise SystemExit('Missing VPSENTRY_PASSWORD_HASH in /etc/vpsentry/vpsentry.env')
Store(config.data_dir)
PY
)
for unit in vpsentry.service vpsentry-network.service vpsentry-firewall.service vpsentry-firewall.timer; do
  install -m 0644 "$RELEASE/systemd/$unit" "/etc/systemd/system/$unit"
done
if [[ -L "$INSTALL_BASE/current" ]]; then
  PREVIOUS_RELEASE="$(readlink -f "$INSTALL_BASE/current")"
elif [[ -e "$INSTALL_BASE/current" ]]; then
  fail '/opt/vpsentry/current must be a symlink, not a directory.'
fi
ln -sfn "$RELEASE" "$INSTALL_BASE/current"
SWITCHED=1
systemctl daemon-reload
systemctl enable vpsentry.service vpsentry-network.service vpsentry-firewall.timer
systemctl restart vpsentry.service vpsentry-network.service vpsentry-firewall.timer
systemctl start vpsentry-firewall.service
# Check the authenticated API locally without printing secrets or needing plaintext password.
(cd "$RELEASE" && "$RELEASE/.venv/bin/python" - <<'PY'
import time, urllib.request, urllib.error
from backend.config import Settings
config = Settings(_env_file='/etc/vpsentry/vpsentry.env')
address = '[::1]' if config.host == '::1' else '127.0.0.1' if config.host in ('0.0.0.0','localhost') else config.host
for _ in range(30):
    try:
        urllib.request.urlopen(f'http://{address}:{config.port}/api/health', timeout=2)
    except urllib.error.HTTPError as error:
        if error.code == 401 and 'VPSentry' in error.headers.get('WWW-Authenticate', ''):
            break
    except OSError:
        pass
    time.sleep(1)
else:
    raise SystemExit('VPSentry did not become available within 30 seconds')
PY
)
systemctl is-active --quiet vpsentry.service
systemctl is-active --quiet vpsentry-network.service
systemctl is-enabled --quiet vpsentry.service
PORT="$(cd "$RELEASE" && "$RELEASE/.venv/bin/python" -c "from backend.config import Settings; print(Settings(_env_file='/etc/vpsentry/vpsentry.env').port)")"
SERVER_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
SERVER_IP="${SERVER_IP:-YOUR_SERVER_IP}"
printf '\n================================================\n             VPSentry Installed\n================================================\nStatus: Running\nService: vpsentry.service\nPort: %s\n\nDashboard:\nhttp://%s:%s\n\n' "$PORT" "$SERVER_IP" "$PORT"
if [[ -f "$CONFIG_DIR/initial-credentials" ]]; then
  printf 'Administrator credentials: sudo cat /etc/vpsentry/initial-credentials\n'
fi
printf '\nUse HTTPS or an SSH tunnel on untrusted networks; HTTP does not encrypt credentials.\nNo firewall rules were opened or changed.\n\nUseful commands:\nsudo systemctl status vpsentry\nsudo systemctl restart vpsentry\nsudo systemctl stop vpsentry\njournalctl -u vpsentry -f\n================================================\n'
