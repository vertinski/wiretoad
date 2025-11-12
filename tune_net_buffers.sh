#!/bin/bash
# tune_net_buffers.sh - Raise kernel socket buffer limits for higher throughput

set -e

echo "=== Tuning kernel buffer limits for PSK tunnel ==="

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)" >&2
  exit 1
fi

CONF="/etc/sysctl.d/99-psk-tunnel-buffers.conf"

cat > "$CONF" <<EOF
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
EOF

sysctl --system >/dev/null

echo "Applied settings from $CONF"
sysctl -n net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default
echo "✓ Kernel buffers tuned"


