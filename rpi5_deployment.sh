#!/bin/bash
# setup_psk_tunnel.sh - Deploy pure PSK tunnel

set -e

SITE="A"  # or "B"

echo "=== Pure PSK Tunnel Setup - Site ${SITE} ==="

# Install dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# Create directories
sudo mkdir -p /var/lib/psk-tunnel
sudo mkdir -p /mnt/secure
sudo mkdir -p /usr/local/bin
sudo mkdir -p /opt/psk-tunnel

# Create and activate virtual environment (non-interactive)
if [ ! -d "/opt/psk-tunnel/venv" ]; then
    sudo python3 -m venv /opt/psk-tunnel/venv
fi

# Upgrade pip and install Python dependencies inside venv
sudo /opt/psk-tunnel/venv/bin/pip install --upgrade pip
sudo /opt/psk-tunnel/venv/bin/pip install cryptography tqdm

# Install tunnel script
# Copy the repository's core implementation as the runtime entry script
if [ -f core_protocol.py ]; then
    sudo cp core_protocol.py /usr/local/bin/psk_tunnel.py
else
    echo "Warning: core_protocol.py not found in current directory. Skipping copy."
fi
sudo chmod +x /usr/local/bin/psk_tunnel.py

# Enable TUN/TAP
sudo modprobe tun
echo "tun" | sudo tee -a /etc/modules

# Tune kernel socket buffer limits (optional but recommended)
if [ -f tune_net_buffers.sh ]; then
  echo "Applying kernel buffer tuning..."
  sudo bash tune_net_buffers.sh || true
else
  echo "Note: tune_net_buffers.sh not found; skipping kernel buffer tuning"
fi

echo "✓ PSK tunnel installed"