#!/bin/bash
# Install missing system tools for Zuck Agent

echo "🔧 Installing missing system tools..."

# Update package list
sudo apt-get update

# Install tools
# whois - for whois_lookup
# tshark - for network analysis (wireshark-common)
# dnsutils - for dig and nslookup
# aircrack-ng - for wifi tools
# traceroute - for network tracing
# net-tools - for ifconfig, netstat
sudo apt-get install -y whois tshark dnsutils aircrack-ng traceroute net-tools

# Set permissions for dumpcap (used by tshark) to allow non-root capture if needed
# sudo usermod -aG wireshark $USER

echo ""
echo "✅ Installation complete!"
echo "Note: For tshark to capture packets without sudo, run: sudo dpkg-reconfigure wireshark-common"
echo "and select 'Yes', then add your user to the wireshark group."
