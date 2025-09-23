#!/bin/bash
# THrpC Node initialization script for Ubuntu 22.04
# Tiny Hyper Cats Community - High-Performance RPC Infrastructure

set -e

echo "=== THrpC Node Setup ==="

# Update system
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y \
    curl \
    wget \
    jq \
    htop \
    unzip

# Mount and format EBS volume for blockchain data
if [ -b /dev/nvme1n1 ]; then
    mkfs -t ext4 /dev/nvme1n1 || true
    mkdir -p /home/ubuntu/hl
    mount /dev/nvme1n1 /home/ubuntu/hl
    echo '/dev/nvme1n1 /home/ubuntu/hl ext4 defaults,nofail 0 2' >> /etc/fstab
fi

# Set ownership
chown -R ubuntu:ubuntu /home/ubuntu/hl

# Download Hyperliquid visor binary
cd /home/ubuntu
curl https://binaries.hyperliquid.xyz/Mainnet/hl-visor > hl-visor
chmod +x hl-visor

# Create systemd service for node
cat > /etc/systemd/system/hyperliquid-node.service << 'EOF'
[Unit]
Description=Hyperliquid Node
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu
ExecStart=/home/ubuntu/hl-visor run-non-validator --evm
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable hyperliquid-node
systemctl start hyperliquid-node

echo "=== THrpC Node Setup Complete ==="