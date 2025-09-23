import json
import os
import time
import boto3
import jwt
import requests
from datetime import datetime

# Initialize clients
secrets_client = boto3.client('secretsmanager')
dynamodb = boto3.resource('dynamodb')
rate_limit_table = dynamodb.Table(os.environ['RATE_LIMIT_TABLE'])

def get_jwt_secret():
    """Retrieve JWT secret from AWS Secrets Manager"""
    secret_name = os.environ['JWT_SECRET_NAME']
    response = secrets_client.get_secret_value(SecretId=secret_name)
    return response['SecretString']

def check_rate_limit(identifier, limit=100, window=3600):
    """Check if request is within rate limits"""
    try:
        current_time = int(time.time())
        window_start = current_time - window
        
        # Query recent requests
        response = rate_limit_table.query(
            KeyConditionExpression='identifier = :id AND #ts > :start',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':id': identifier,
                ':start': window_start
            }
        )
        
        request_count = len(response.get('Items', []))
        
        if request_count >= limit:
            return False, request_count
        
        # Log this request
        rate_limit_table.put_item(
            Item={
                'identifier': identifier,
                'timestamp': current_time,
                'expires_at': current_time + window
            }
        )
        
        return True, request_count + 1
    except Exception as e:
        print(f"Rate limit check failed: {e}")
        # Fail open for now
        return True, 0

def proxy_request(event, context):
    """Proxy RPC requests to Hyperliquid node with auth and rate limiting"""
    try:
        # Check for authorization header
        headers = event.get('headers', {})
        auth_header = headers.get('authorization', '') or headers.get('Authorization', '')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return {
                'statusCode': 401,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Missing or invalid authorization header'})
            }
        
        # Extract and verify JWT
        token = auth_header.replace('Bearer ', '')
        jwt_secret = get_jwt_secret()
        
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
            address = payload.get('address')
            nft_contract = payload.get('nft_contract')
        except jwt.ExpiredSignatureError:
            return {
                'statusCode': 401,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Token expired'})
            }
        except jwt.InvalidTokenError as e:
            return {
                'statusCode': 401,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': f'Invalid token: {str(e)}'})
            }
        
        # Check rate limits
        within_limit, request_count = check_rate_limit(address)
        
        if not within_limit:
            return {
                'statusCode': 429,
                'headers': {
                    'Content-Type': 'application/json',
                    'X-RateLimit-Limit': '100',
                    'X-RateLimit-Remaining': '0',
                    'X-RateLimit-Reset': str(int(time.time()) + 3600)
                },
                'body': json.dumps({
                    'error': 'Rate limit exceeded',
                    'limit': 100,
                    'window': '1 hour',
                    'retry_after': 3600
                })
            }
        
        # Parse RPC request
        try:
            rpc_request = json.loads(event.get('body', '{}'))
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Invalid JSON in request body'})
            }
        
        # Validate RPC request structure
        if not isinstance(rpc_request, dict):
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Request body must be a JSON object'})
            }
        
        # Check for required RPC fields
        if 'jsonrpc' not in rpc_request or 'method' not in rpc_request:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32600,
                        'message': 'Invalid Request'
                    },
                    'id': rpc_request.get('id')
                })
            }
        
        # List of allowed RPC methods (can be expanded)
        allowed_methods = [
            'eth_chainId',
            'eth_blockNumber',
            'eth_getBalance',
            'eth_getTransactionCount',
            'eth_getBlockByNumber',
            'eth_getBlockByHash',
            'eth_getTransactionByHash',
            'eth_getTransactionReceipt',
            'eth_call',
            'eth_estimateGas',
            'eth_gasPrice',
            'eth_getCode',
            'eth_getStorageAt',
            'eth_getLogs',
            'net_version',
            'web3_clientVersion'
        ]
        
        # Check if method is allowed
        method = rpc_request.get('method')
        if method not in allowed_methods:
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32601,
                        'message': f'Method not allowed: {method}'
                    },
                    'id': rpc_request.get('id')
                })
            }
        
        # Forward request to Hyperliquid node
        node_url = os.environ['NODE_RPC_URL']
        
        try:
            response = requests.post(
                node_url,
                json=rpc_request,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            # Log successful request
            print(f"RPC request from {address}: {method}")
            
            # Return the response from the node
            return {
                'statusCode': response.status_code,
                'headers': {
                    'Content-Type': 'application/json',
                    'X-RateLimit-Limit': '100',
                    'X-RateLimit-Remaining': str(100 - request_count),
                    'X-RateLimit-Reset': str(int(time.time()) + 3600)
                },
                'body': response.text
            }
            
        except requests.exceptions.Timeout:
            return {
                'statusCode': 504,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32000,
                        'message': 'Request timeout'
                    },
                    'id': rpc_request.get('id')
                })
            }
        except requests.exceptions.RequestException as e:
            print(f"Error forwarding request to node: {e}")
            return {
                'statusCode': 502,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32000,
                        'message': 'Internal proxy error'
                    },
                    'id': rpc_request.get('id')
                })
            }
        
    except Exception as e:
        print(f"Proxy error: {e}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32603,
                    'message': 'Internal error'
                },
                'id': None
            })
        }