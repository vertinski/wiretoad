#!/bin/bash
# test_send_100mb.sh - Send 100MB of random data over the tunnel to the RPi5

set -euo pipefail

# Defaults
PEER_IP="${1:-10.0.0.2}"
PORT="${2:-9000}"
SIZE_MB="${3:-100}"

echo "=== PSK Tunnel Data Send Test ==="
echo "Peer: ${PEER_IP}:${PORT}  Size: ${SIZE_MB} MB"

# Basic checks
if ! command -v nc >/dev/null 2>&1; then
  echo "Error: netcat (nc) is required. Install netcat-openbsd or nmap-ncat." >&2
  exit 1
fi

if ! ip link show tun0 >/dev/null 2>&1; then
  echo "Warning: tun0 not found. Ensure the tunnel is running." >&2
fi

# Try to confirm routing via tun0 (best-effort)
if ip route get "${PEER_IP}" 2>/dev/null | grep -q 'dev tun0'; then
  echo "Route to ${PEER_IP} goes via tun0 ✔"
else
  echo "Warning: route to ${PEER_IP} may not use tun0. Proceeding anyway." >&2
fi

# Determine a safe close option for nc
NC_CLOSE_OPT=""
if nc -h 2>&1 | grep -q ' -N '; then
  NC_CLOSE_OPT="-N"  # OpenBSD/nmap-ncat supports -N to close on EOF
elif nc -h 2>&1 | grep -q ' -q '; then
  NC_CLOSE_OPT="-q 0" # GNU netcat supports -q seconds
fi

# Sender pipeline (use pv if available for progress)
BYTES=$((SIZE_MB * 1024 * 1024))
echo "Sending ${SIZE_MB} MB of random data to ${PEER_IP}:${PORT}..."
if command -v pv >/dev/null 2>&1; then
  head -c "${BYTES}" /dev/urandom | pv -br -s "${BYTES}" | nc ${NC_CLOSE_OPT} "${PEER_IP}" "${PORT}"
else
  head -c "${BYTES}" /dev/urandom | nc ${NC_CLOSE_OPT} "${PEER_IP}" "${PORT}"
fi

echo "✓ Transfer complete"
echo "Note: Start a receiver on the RPi5, e.g.:\n  nc -l -p ${PORT} > /dev/null"


