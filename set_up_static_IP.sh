#!/bin/bash

# Network Configuration Script for Direct Connection
# For Raspberry Pi connected directly to laptop (no DHCP/internet needed)

set -e

# Configuration - EDIT THESE VALUES
STATIC_IP="169.254.10.3"      # Your Raspberry Pi's IP
NETMASK="24"                   # Subnet mask in CIDR notation (24 = 255.255.255.0)
LAPTOP_IP="169.254.10.2"       # Your laptop's IP (for reference, not used as gateway)
CONNECTION_NAME="Wired connection 1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Static IP Configuration for Direct Connection ===${NC}"
echo ""
echo "Configuration:"
echo "  Interface: eth0"
echo "  Connection: $CONNECTION_NAME"
echo "  Static IP: $STATIC_IP/$NETMASK"
echo "  Peer (laptop): $LAPTOP_IP"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Check if NetworkManager is running
if ! systemctl is-active --quiet NetworkManager; then
    echo -e "${YELLOW}Starting NetworkManager...${NC}"
    systemctl start NetworkManager
fi

echo -e "${YELLOW}Step 1: Configuring eth0 with static IP...${NC}"

# Configure the connection for static IP (manual method)
nmcli connection modify "$CONNECTION_NAME" \
    ipv4.method manual \
    ipv4.addresses "$STATIC_IP/$NETMASK" \
    ipv4.gateway "" \
    ipv4.dns "" \
    ipv6.method disabled

echo -e "${GREEN}✓ Static IP configured${NC}"

echo -e "${YELLOW}Step 2: Disabling auto-connect delay...${NC}"
nmcli connection modify "$CONNECTION_NAME" connection.autoconnect yes
nmcli connection modify "$CONNECTION_NAME" connection.autoconnect-retries 0

echo -e "${GREEN}✓ Auto-connect configured${NC}"

echo -e "${YELLOW}Step 3: Restarting connection...${NC}"
nmcli connection down "$CONNECTION_NAME" 2>/dev/null || true
sleep 2
nmcli connection up "$CONNECTION_NAME"

echo -e "${GREEN}✓ Connection restarted${NC}"

echo ""
echo -e "${GREEN}=== Configuration Complete ===${NC}"
echo ""
echo "Verifying configuration..."
sleep 2

# Show results
echo ""
echo -e "${YELLOW}Current interface status:${NC}"
ip addr show eth0

echo ""
echo -e "${YELLOW}Connection details:${NC}"
nmcli device show eth0 | grep -E "GENERAL.STATE|IP4.ADDRESS|IP4.GATEWAY"

echo ""
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo ""
echo "Your Raspberry Pi should now have:"
echo "  - Static IP: $STATIC_IP"
echo "  - No gateway (direct connection)"
echo "  - No DHCP attempts"
echo ""
echo "Test connectivity to laptop:"
echo "  ping $LAPTOP_IP"
echo ""
echo "Note: The loopback 'connected (externally)' status is normal and can be ignored."
