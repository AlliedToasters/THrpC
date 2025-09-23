#!/bin/bash
# THrpC Node initialization script for Ubuntu 24.04
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
    unzip \
    gpg

# Mount and format EBS volume for blockchain data
if [ -b /dev/nvme1n1 ]; then
    mkfs -t ext4 /dev/nvme1n1 || true
    mkdir -p /home/ubuntu/hl
    mount /dev/nvme1n1 /home/ubuntu/hl
    echo '/dev/nvme1n1 /home/ubuntu/hl ext4 defaults,nofail 0 2' >> /etc/fstab
fi

# Set ownership
chown -R ubuntu:ubuntu /home/ubuntu/hl

# Create data directories
sudo -u ubuntu mkdir -p /home/ubuntu/hl/hyperliquid_data
sudo -u ubuntu mkdir -p /home/ubuntu/hl/data

# Download Hyperliquid visor binary
cd /home/ubuntu
sudo -u ubuntu curl https://binaries.hyperliquid.xyz/Mainnet/hl-visor > hl-visor
chmod +x hl-visor
chown ubuntu:ubuntu hl-visor

# Import Hyperliquid GPG public key
sudo -u ubuntu wget https://raw.githubusercontent.com/hyperliquid-dex/node/main/pub_key.asc
sudo -u ubuntu gpg --import pub_key.asc

# Create visor config file
sudo -u ubuntu bash -c 'cat > /home/ubuntu/visor.json << VISOR_EOF
{
  "chain": "Mainnet"
}
VISOR_EOF'

# Create node config with EVM enabled
sudo -u ubuntu bash -c 'cat > /home/ubuntu/hl/hyperliquid_data/node_config.json << NODE_EOF
{
  "evm": true
}
NODE_EOF'

# Create systemd service for node
cat > /etc/systemd/system/hyperliquid-node.service << 'SERVICE_EOF'
[Unit]
Description=Hyperliquid Node
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu
Environment="HOME=/home/ubuntu"
ExecStart=/home/ubuntu/hl-visor run-non-validator
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Enable and start service
systemctl daemon-reload
systemctl enable hyperliquid-node
systemctl start hyperliquid-node

echo "=== THrpC Node Setup Complete ==="
echo "Monitor logs with: sudo journalctl -u hyperliquid-node -f"
echo "Note: Node needs to find peers and sync. This can take 10-30 minutes to start."
echo "EVM RPC on port 3001 will be available after substantial sync progress."