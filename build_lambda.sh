#!/bin/bash
# Clean Lambda deployment script for THrpC

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Base directories
PROJECT_ROOT=$(pwd)
LAMBDA_DIR="${PROJECT_ROOT}/lambda"
BUILD_DIR="${PROJECT_ROOT}/build"

# Clean previous builds
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# Function to build clean Lambda package
build_lambda() {
    local function_name=$1
    local source_dir="${LAMBDA_DIR}/${function_name}"
    local build_path="${BUILD_DIR}/${function_name}"
    
    echo -e "${YELLOW}Building ${function_name}...${NC}"
    
    # Create clean build directory
    mkdir -p ${build_path}
    
    # Copy only handler and requirements
    cp ${source_dir}/handler.py ${build_path}/
    
    # Install dependencies in build directory
    if [ -f ${source_dir}/requirements.txt ]; then
        pip install -r ${source_dir}/requirements.txt -t ${build_path}/ --quiet --upgrade
    fi
    
    # Create deployment package
    cd ${build_path}
    zip -r ${function_name}.zip . -q
    
    # Move to Lambda source directory for Terraform
    mv ${function_name}.zip ${source_dir}/
    
    cd ${PROJECT_ROOT}
    echo -e "${GREEN}✓ Built ${source_dir}/${function_name}.zip${NC}"
}

# Build both functions
build_lambda "auth"
build_lambda "rpc_proxy"

# Clean build directory
rm -rf ${BUILD_DIR}

echo -e "${GREEN}✓ Lambda packages ready for deployment${NC}"
echo ""
echo "Next steps:"
echo "1. cd terraform"
echo "2. terraform apply -auto-approve"