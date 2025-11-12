#!/bin/bash
# rpi5_launch.sh

# RPi5 (Site B) Configuration  
LOCAL_IP="10.0.0.2"
REMOTE_IP="10.0.0.1"
REMOTE_HOST="169.254.10.2"  # Peer (Laptop) transport IP
PSK_FILE="/mnt/secure/psk.bin"

sudo /opt/psk-tunnel/venv/bin/python /usr/local/bin/psk_tunnel.py \
    --psk "${PSK_FILE}" \
    --local-port 51820 \
    --remote-host "${REMOTE_HOST}" \
    --remote-port 51820 \
    --local-ip "${LOCAL_IP}" \
    --remote-ip "${REMOTE_IP}" \
    --state /var/lib/psk-tunnel/state_siteB.json


