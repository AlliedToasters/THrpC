################################################################################
# THrpC - NFT-Gated RPC Infrastructure
# Open Source Infrastructure for Tiny Hyper Cats Community
# High-Performance RPC Access for the Hyperliquid Ecosystem
################################################################################

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  # Store state in S3 (recommended for production)
  backend "s3" {
    bucket = "thrpc-terraform-state"  # Change this to your bucket name!
    key    = "thrpc/terraform.tfstate"
    region = "us-west-2"  # Must match where you created the bucket
    encrypt = true
  }
}

################################################################################
# Variables - Customize these for your deployment
################################################################################

variable "aws_region" {
  description = "AWS region for deployment (Tokyo recommended for Hyperliquid)"
  type        = string
  default     = "ap-northeast-1"  # Tokyo
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "thrpc"
}

variable "node_instance_type" {
  description = "EC2 instance type for Hyperliquid node"
  type        = string
  default     = "c6i.2xlarge"  # 8 vCPU, 16GB RAM
}

variable "node_volume_size" {
  description = "EBS volume size in GB for blockchain data"
  type        = number
  default     = 500
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into node (your IP)"
  type        = string
  default     = "0.0.0.0/0"  # Change this to your IP for security!
}

variable "nft_contract_addresses" {
  description = "List of NFT contract addresses for access gating (Tiny Hyper Cats and any partner collections)"
  type        = list(string)
  # You'll set this via terraform.tfvars or environment variable
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key for EC2 access"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "jwt_secret_name" {
  description = "AWS Secrets Manager secret name for JWT signing"
  type        = string
  default     = "thrpc-jwt-secret-prod"
}

################################################################################
# Provider Configuration
################################################################################

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Purpose     = "NFT-Gated RPC Infrastructure"
    }
  }
}

################################################################################
# VPC and Networking
################################################################################

# Create VPC for isolated network
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Internet Gateway for public access
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Public subnets for node and ALB
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-a"
  }
}

resource "aws_subnet" "public_c" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}c"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-c"
  }
}

# Route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_c" {
  subnet_id      = aws_subnet.public_c.id
  route_table_id = aws_route_table.public.id
}

################################################################################
# Security Groups
################################################################################

# Security group for Hyperliquid node
resource "aws_security_group" "node" {
  name        = "${var.project_name}-node-sg"
  description = "Security group for Hyperliquid node"
  vpc_id      = aws_vpc.main.id

  # SSH access (restrict this to your IP!)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
    description = "SSH access"
  }

  # Hyperliquid consensus ports (must be open to public for validator communication)
  ingress {
    from_port   = 4000
    to_port     = 4000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Hyperliquid consensus"
  }

  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Hyperliquid consensus"
  }

  ingress {
    from_port   = 6000
    to_port     = 6000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Hyperliquid consensus"
  }

  ingress {
    from_port   = 7000
    to_port     = 7000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Hyperliquid consensus"
  }

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Hyperliquid gossip - must be public"
  }

  ingress {
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Hyperliquid gossip - must be public"
  }

  # EVM RPC port (only from ALB)
  ingress {
    from_port       = 3001
    to_port         = 3001
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "EVM RPC from ALB"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-node-sg"
  }
}

# Security group for Application Load Balancer
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  # HTTPS from Lambda
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.lambda.id]
    description     = "HTTPS from Lambda"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-alb-sg"
  }
}

# Security group for Lambda functions
resource "aws_security_group" "lambda" {
  name        = "${var.project_name}-lambda-sg"
  description = "Security group for Lambda functions"
  vpc_id      = aws_vpc.main.id

  # Allow all outbound (Lambda needs to reach ALB, DynamoDB, etc)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = {
    Name = "${var.project_name}-lambda-sg"
  }
}

################################################################################
# EC2 Instance for Hyperliquid Node
################################################################################

# Get latest Ubuntu 24.04 AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# SSH key pair
resource "aws_key_pair" "node" {
  key_name   = "${var.project_name}-node-key"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

# EC2 instance for Hyperliquid node
resource "aws_instance" "node" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.node_instance_type
  key_name      = aws_key_pair.node.key_name
  subnet_id     = aws_subnet.public_a.id

  vpc_security_group_ids = [aws_security_group.node.id]

  # Root volume for OS
  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  # Additional volume for blockchain data
  ebs_block_device {
    device_name = "/dev/sdf"
    volume_size = var.node_volume_size
    volume_type = "gp3"
    iops        = 3000
    throughput  = 125
    encrypted   = true
  }

  user_data = templatefile("${path.module}/scripts/node_setup.sh", {
    environment = var.environment
  })

  iam_instance_profile = aws_iam_instance_profile.node.name

  tags = {
    Name = "${var.project_name}-node"
    Role = "hyperliquid-node"
  }

  # Ensure node keeps running
  monitoring              = true
  disable_api_termination = false
}

# Elastic IP for consistent node address
resource "aws_eip" "node" {
  domain   = "vpc"
  instance = aws_instance.node.id

  tags = {
    Name = "${var.project_name}-node-eip"
  }
}

################################################################################
# IAM Roles and Policies
################################################################################

# IAM role for EC2 node
resource "aws_iam_role" "node" {
  name = "${var.project_name}-node-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Allow node to write logs to CloudWatch
resource "aws_iam_role_policy_attachment" "node_cloudwatch" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "node" {
  name = "${var.project_name}-node-profile"
  role = aws_iam_role.node.name
}

# IAM role for Lambda functions
resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Lambda basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Lambda VPC execution policy
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Custom policy for Lambda to access DynamoDB and Secrets Manager
resource "aws_iam_role_policy" "lambda_custom" {
  name = "${var.project_name}-lambda-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.auth_cache.arn,
          aws_dynamodb_table.rate_limits.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.jwt.arn
      }
    ]
  })
}

################################################################################
# Application Load Balancer
################################################################################

resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = true  # Internal - only Lambda can access
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_c.id]

  tags = {
    Name = "${var.project_name}-alb"
  }
}

resource "aws_lb_target_group" "node" {
  name     = "${var.project_name}-node-tg"
  port     = 3001
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    path                = "/"
    port                = "3001"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
  }

  tags = {
    Name = "${var.project_name}-node-tg"
  }
}

resource "aws_lb_target_group_attachment" "node" {
  target_group_arn = aws_lb_target_group.node.arn
  target_id        = aws_instance.node.id
  port             = 3001
}

resource "aws_lb_listener" "node" {
  load_balancer_arn = aws_lb.main.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.alb.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.node.arn
  }
}

# Self-signed certificate for ALB (internal use)
resource "aws_acm_certificate" "alb" {
  private_key      = tls_private_key.alb.private_key_pem
  certificate_body = tls_self_signed_cert.alb.cert_pem

  lifecycle {
    create_before_destroy = true
  }
}

resource "tls_private_key" "alb" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "alb" {
  private_key_pem = tls_private_key.alb.private_key_pem

  subject {
    common_name  = "${var.project_name}-alb.local"
    organization = var.project_name
  }

  validity_period_hours = 87600  # 10 years

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

################################################################################
# DynamoDB Tables
################################################################################

# Auth cache table - stores verified NFT holders
resource "aws_dynamodb_table" "auth_cache" {
  name         = "${var.project_name}-auth-cache"
  billing_mode = "PAY_PER_REQUEST"  # On-demand pricing
  hash_key     = "wallet_address"

  attribute {
    name = "wallet_address"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}-auth-cache"
  }
}

# Rate limiting table
resource "aws_dynamodb_table" "rate_limits" {
  name         = "${var.project_name}-rate-limits"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "identifier"
  range_key    = "timestamp"

  attribute {
    name = "identifier"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "N"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}-rate-limits"
  }
}

################################################################################
# Secrets Manager
################################################################################

# JWT signing secret
resource "aws_secretsmanager_secret" "jwt" {
  name                    = var.jwt_secret_name
  description             = "JWT signing secret for RPC authentication"
  recovery_window_in_days = 7

  tags = {
    Name = "${var.project_name}-jwt-secret"
  }
}

# Generate random secret value
resource "random_password" "jwt" {
  length  = 64
  special = true
}

resource "aws_secretsmanager_secret_version" "jwt" {
  secret_id     = aws_secretsmanager_secret.jwt.id
  secret_string = random_password.jwt.result
}

################################################################################
# Lambda Functions (Placeholder - will be deployed separately)
################################################################################

# Lambda function for NFT authentication
resource "aws_lambda_function" "auth" {
  filename         = "${path.module}/../lambda/auth/auth.zip"
  function_name    = "${var.project_name}-auth"
  role            = aws_iam_role.lambda.arn
  handler         = "handler.authenticate"
  source_code_hash = fileexists("${path.module}/../lambda/auth/auth.zip") ? filebase64sha256("${path.module}/../lambda/auth/auth.zip") : ""
  runtime         = "python3.11"
  timeout         = 30
  memory_size     = 256

  environment {
    variables = {
      NFT_CONTRACT_ADDRESSES = jsonencode(var.nft_contract_addresses)
      AUTH_CACHE_TABLE       = aws_dynamodb_table.auth_cache.name
      JWT_SECRET_NAME        = aws_secretsmanager_secret.jwt.name
      NODE_RPC_URL           = "https://${aws_eip.node.public_ip}:3001"
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.public_a.id, aws_subnet.public_c.id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  tags = {
    Name = "${var.project_name}-auth-lambda"
  }
}

# Lambda function for RPC proxy
resource "aws_lambda_function" "rpc_proxy" {
  filename         = "${path.module}/../lambda/rpc_proxy/rpc_proxy.zip"
  function_name    = "${var.project_name}-rpc-proxy"
  role            = aws_iam_role.lambda.arn
  handler         = "handler.proxy_request"
  source_code_hash = fileexists("${path.module}/../lambda/rpc_proxy/rpc_proxy.zip") ? filebase64sha256("${path.module}/../lambda/rpc_proxy/rpc_proxy.zip") : ""
  runtime         = "python3.11"
  timeout         = 30
  memory_size     = 256

  environment {
    variables = {
      RATE_LIMIT_TABLE = aws_dynamodb_table.rate_limits.name
      JWT_SECRET_NAME  = aws_secretsmanager_secret.jwt.name
      ALB_URL          = "https://${aws_lb.main.dns_name}"
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.public_a.id, aws_subnet.public_c.id]
    security_group_ids = [aws_security_group.lambda.id]
  }

  tags = {
    Name = "${var.project_name}-rpc-proxy-lambda"
  }
}

################################################################################
# API Gateway
################################################################################

resource "aws_apigatewayv2_api" "main" {
  name          = "${var.project_name}-api"
  protocol_type = "HTTP"
  description   = "NFT-Gated RPC API"

  cors_configuration {
    allow_origins = ["*"]  # Adjust for production
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["content-type", "authorization"]
  }
}

# Auth endpoint
resource "aws_apigatewayv2_integration" "auth" {
  api_id             = aws_apigatewayv2_api.main.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.auth.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "auth" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /auth"
  target    = "integrations/${aws_apigatewayv2_integration.auth.id}"
}

# RPC endpoint
resource "aws_apigatewayv2_integration" "rpc" {
  api_id             = aws_apigatewayv2_api.main.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.rpc_proxy.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "rpc" {
  api_id    = aws_apigatewayv2_api.main.id
  route_key = "POST /rpc"
  target    = "integrations/${aws_apigatewayv2_integration.rpc.id}"
}

# Deployment stage
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.main.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gateway.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }
}

# Lambda permissions for API Gateway
resource "aws_lambda_permission" "auth" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.auth.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "rpc_proxy" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rpc_proxy.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.main.execution_arn}/*/*"
}

################################################################################
# CloudWatch Logs
################################################################################

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.project_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "auth_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.auth.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "rpc_proxy_lambda" {
  name              = "/aws/lambda/${aws_lambda_function.rpc_proxy.function_name}"
  retention_in_days = 30
}

################################################################################
# Outputs
################################################################################

output "api_endpoint" {
  description = "API Gateway endpoint URL"
  value       = aws_apigatewayv2_api.main.api_endpoint
}

output "node_public_ip" {
  description = "Public IP of Hyperliquid node"
  value       = aws_eip.node.public_ip
}

output "node_instance_id" {
  description = "EC2 instance ID of Hyperliquid node"
  value       = aws_instance.node.id
}

output "alb_dns_name" {
  description = "DNS name of Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "auth_cache_table" {
  description = "Name of DynamoDB auth cache table"
  value       = aws_dynamodb_table.auth_cache.name
}

output "rate_limit_table" {
  description = "Name of DynamoDB rate limit table"
  value       = aws_dynamodb_table.rate_limits.name
}