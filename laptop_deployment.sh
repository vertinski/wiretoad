#!/bin/bash
# laptop_deployment.sh - Deploy pure PSK tunnel on Laptop (Fedora/RHEL)

set -e

echo "=== Pure PSK Tunnel Setup - Laptop ==="

# Install dependencies (Fedora/RHEL)
if command -v dnf >/dev/null 2>&1; then
    sudo dnf -y install python3 python3-pip
elif command -v yum >/dev/null 2>&1; then
    sudo yum -y install python3 python3-pip
else
    echo "Warning: dnf/yum not found. Ensure Python 3 and pip are installed."
fi

# Create directories
sudo mkdir -p /var/lib/psk-tunnel
sudo mkdir -p /mnt/secure
sudo mkdir -p /usr/local/bin
sudo mkdir -p /opt/psk-tunnel

# Create and activate virtual environment
if [ ! -d "/opt/psk-tunnel/venv" ]; then
    sudo python3 -m venv /opt/psk-tunnel/venv
fi

# Upgrade pip and install Python dependencies inside venv
sudo /opt/psk-tunnel/venv/bin/pip install --upgrade pip
sudo /opt/psk-tunnel/venv/bin/pip install cryptography tqdm

# Install tunnel script
if [ -f core_protocol.py ]; then
    sudo cp core_protocol.py /usr/local/bin/psk_tunnel.py
else
    echo "Warning: core_protocol.py not found in current directory. Skipping copy."
fi
sudo chmod +x /usr/local/bin/psk_tunnel.py

# Enable TUN/TAP for current session
if ! lsmod | grep -q "\btun\b"; then
    sudo modprobe tun || true
fi

# Tune kernel socket buffer limits (optional but recommended)
if [ -f tune_net_buffers.sh ]; then
    echo "Applying kernel buffer tuning..."
    sudo bash tune_net_buffers.sh || true
else
    echo "Note: tune_net_buffers.sh not found; skipping kernel buffer tuning"
fi

echo "✓ PSK tunnel installed on Laptop"


