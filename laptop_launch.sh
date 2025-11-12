#!/bin/bash
# laptop_launch.sh

# Laptop (Site A) Configuration
LOCAL_IP="10.0.0.1"
REMOTE_IP="10.0.0.2"
REMOTE_HOST="169.254.10.3"  # Peer (RPi) transport IP
PSK_FILE="/mnt/secure/psk.bin"

sudo /opt/psk-tunnel/venv/bin/python /usr/local/bin/psk_tunnel.py \
    --psk "${PSK_FILE}" \
    --local-port 51820 \
    --remote-host "${REMOTE_HOST}" \
    --remote-port 51820 \
    --initiator \
    --local-ip "${LOCAL_IP}" \
    --remote-ip "${REMOTE_IP}" \
    --state /var/lib/psk-tunnel/state_siteA.json


