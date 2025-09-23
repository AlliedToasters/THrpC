import json
import os
import time
import boto3
import jwt
from datetime import datetime, timedelta
from eth_account.messages import encode_defunct
from eth_account import Account
from web3 import Web3

# Initialize clients
secrets_client = boto3.client('secretsmanager')
dynamodb = boto3.resource('dynamodb')
auth_cache_table = dynamodb.Table(os.environ['AUTH_CACHE_TABLE'])

def get_jwt_secret():
    """Retrieve JWT secret from AWS Secrets Manager"""
    secret_name = os.environ['JWT_SECRET_NAME']
    response = secrets_client.get_secret_value(SecretId=secret_name)
    return response['SecretString']

def verify_signature(message, signature, address):
    """Verify that the signature was created by the given address"""
    try:
        # Create the message hash that was signed
        message_hash = encode_defunct(text=message)
        
        # Recover the address from the signature
        recovered_address = Account.recover_message(message_hash, signature=signature)
        
        # Compare addresses (case-insensitive)
        return recovered_address.lower() == address.lower()
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

def check_nft_ownership(address, rpc_url):
    """Check if address owns required NFT on Hyperliquid"""
    try:
        # Initialize Web3 connection to Hyperliquid node
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        
        # Get NFT contract addresses from environment
        nft_contracts = json.loads(os.environ['NFT_CONTRACT_ADDRESSES'])
        
        # For each NFT contract, check if user has balance
        for contract_address in nft_contracts:
            # Minimal ERC721 ABI for balanceOf
            abi = [
                {
                    "inputs": [{"name": "owner", "type": "address"}],
                    "name": "balanceOf",
                    "outputs": [{"name": "", "type": "uint256"}],
                    "type": "function",
                    "constant": True
                }
            ]
            
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(contract_address),
                abi=abi
            )
            
            # Check balance
            balance = contract.functions.balanceOf(
                Web3.to_checksum_address(address)
            ).call()
            
            if balance > 0:
                print(f"Address {address} owns NFT from {contract_address}")
                return True, contract_address
        
        return False, None
    except Exception as e:
        print(f"NFT ownership check failed: {e}")
        # Temporary bypass for testing - REMOVE IN PRODUCTION
        if os.environ.get('BYPASS_NFT_CHECK') == 'true':
            print("WARNING: NFT check bypassed for testing")
            return True, "testing"
        return False, None

def authenticate(event, context):
    """Authenticate user and return JWT if they own required NFT"""
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        address = body.get('address')
        signature = body.get('signature')
        message = body.get('message')
        
        # Validate input
        if not all([address, signature, message]):
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'error': 'Missing required fields: address, signature, message'
                })
            }
        
        # Check if message includes timestamp (prevent replay attacks)
        try:
            message_parts = message.split('|')
            if len(message_parts) < 2:
                raise ValueError("Invalid message format")
            
            timestamp = int(message_parts[1])
            current_time = int(time.time())
            
            # Message must be signed within last 5 minutes
            if abs(current_time - timestamp) > 300:
                return {
                    'statusCode': 401,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'Message expired'})
                }
        except (ValueError, IndexError):
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Invalid message format'})
            }
        
        # Verify signature
        if not verify_signature(message, signature, address):
            return {
                'statusCode': 401,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Invalid signature'})
            }
        
        # Check cache first
        try:
            cache_response = auth_cache_table.get_item(
                Key={'wallet_address': address.lower()}
            )
            
            if 'Item' in cache_response:
                cached_item = cache_response['Item']
                if cached_item.get('expires_at', 0) > current_time:
                    print(f"Using cached auth for {address}")
                    # Return cached JWT
                    return {
                        'statusCode': 200,
                        'headers': {'Content-Type': 'application/json'},
                        'body': json.dumps({
                            'token': cached_item['jwt_token'],
                            'cached': True
                        })
                    }
        except Exception as e:
            print(f"Cache check failed: {e}")
        
        # Check NFT ownership
        node_rpc_url = os.environ['NODE_RPC_URL']
        has_nft, nft_contract = check_nft_ownership(address, node_rpc_url)
        
        if not has_nft:
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'error': 'No qualifying NFT found in wallet'
                })
            }
        
        # Generate JWT
        jwt_secret = get_jwt_secret()
        token_payload = {
            'address': address.lower(),
            'nft_contract': nft_contract,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        
        token = jwt.encode(token_payload, jwt_secret, algorithm='HS256')
        
        # Cache the result
        try:
            auth_cache_table.put_item(
                Item={
                    'wallet_address': address.lower(),
                    'jwt_token': token,
                    'nft_contract': nft_contract,
                    'created_at': current_time,
                    'expires_at': current_time + 86400  # 24 hours
                }
            )
        except Exception as e:
            print(f"Failed to cache auth: {e}")
        
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'token': token,
                'expires_in': 86400,
                'nft_contract': nft_contract
            })
        }
        
    except Exception as e:
        print(f"Authentication error: {e}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal server error'})
        }