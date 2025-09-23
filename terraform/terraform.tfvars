aws_region           = "ap-northeast-1"  # Tokyo, colocate with node
environment          = "prod"
project_name         = "thrpc"
node_instance_type   = "c6i.2xlarge"
node_volume_size     = 500

# NFT contract addresses (you can add more collections later)
nft_contract_addresses = [
  "0xCC3D60fF11a268606C6a57bD6Db74b4208f1D30c"  # Tiny Hyper Cats
]

# Your IPv4 address for SSH access
allowed_ssh_cidr     = "174.174.5.178/32"