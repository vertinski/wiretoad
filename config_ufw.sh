#!/bin/bash
# config_ufw.sh - Minimal UFW settings for PSK tunnel on RPi5

set -e

# Configuration
PEER_IP="169.254.10.2"      # Laptop transport IP
UDP_PORT="51820"            # Tunnel UDP port
WAN_IFACE="eth0"            # Physical interface
TUN_IFACE="tun0"            # Tunnel interface

echo "=== Configure UFW for PSK Tunnel (RPi5) ==="

# Require root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Ensure UFW is available (Debian/RPi OS)
if ! command -v ufw >/dev/null 2>&1; then
    apt update
    apt install -y ufw
fi

# Allow inbound UDP from laptop to the tunnel listener
ufw allow in on "$WAN_IFACE" proto udp from "$PEER_IP" to any port "$UDP_PORT" comment 'PSK tunnel'

# Permit traffic over the tunnel interface
ufw allow in on "$TUN_IFACE"
ufw allow out on "$TUN_IFACE"

# Enable UFW if inactive, otherwise reload rules
if ufw status | grep -q "Status: inactive"; then
    ufw --force enable
else
    ufw reload
fi

ufw status verbose
echo "✓ UFW configured for PSK tunnel"


