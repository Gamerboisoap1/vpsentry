#!/bin/sh
# VPSentry demo helper for iSH/Alpine Linux.
# This is intentionally limited to the owner's VPS and a small port list.
set -u

TARGET="91.99.82.136"
SSH_PORT="22"
PORTS="22 80 443 8787"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing '$1'. Install it with: apk add $1"
    exit 1
  }
}

network_demo() {
  need nc
  echo "Checking a small set of ports on $TARGET..."
  for port in $PORTS; do
    if nc -z -w 2 "$TARGET" "$port" >/dev/null 2>&1; then
      echo "  $port/tcp open or reachable"
    else
      echo "  $port/tcp closed or filtered"
    fi
  done
  echo "Refresh VPSentry Network Scans after about 30 seconds."
}

ssh_demo() {
  need ssh
  echo "Sending exactly 6 invalid SSH logins to $TARGET:$SSH_PORT."
  echo "This is only for your VPS and should trigger the SSH alert threshold."
  i=1
  while [ "$i" -le 6 ]; do
    printf '  Attempt %s/6\n' "$i"
    timeout 5 ssh -p "$SSH_PORT" \
      -o BatchMode=yes \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      "vpsentry-demo-alert@$TARGET" </dev/null >/dev/null 2>&1 || true
    i=$((i + 1))
  done
  echo "Refresh VPSentry SSH Security after about 30 seconds."
}

echo "VPSentry demo target: $TARGET"
echo "1) Network scan demo"
echo "2) SSH brute-force alert demo (6 bounded failures)"
printf "Choose 1 or 2: "
read choice
case "$choice" in
  1) network_demo ;;
  2) ssh_demo ;;
  *) echo "Choose 1 or 2."; exit 1 ;;
esac
