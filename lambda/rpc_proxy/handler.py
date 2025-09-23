import json
import os
import boto3
import jwt
import requests
from datetime import datetime

secrets_client = boto3.client('secretsmanager')
dynamodb = boto3.resource('dynamodb')

def get_jwt_secret():
    secret_name = os.environ['JWT_SECRET_NAME']
    response = secrets_client.get_secret_value(SecretId=secret_name)
    return response['SecretString']

def proxy_request(event, context):
    """Proxy RPC requests to Hyperliquid node"""
    try:
        # Verify JWT
        auth_header = event.get('headers', {}).get('authorization', '')
        if not auth_header.startswith('Bearer '):
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Missing authorization'})
            }
        
        token = auth_header.replace('Bearer ', '')
        jwt_secret = get_jwt_secret()
        
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Token expired'})
            }
        except jwt.InvalidTokenError:
            return {
                'statusCode': 401,
                'body': json.dumps({'error': 'Invalid token'})
            }
        
        # TODO: Check rate limits
        
        # Forward to node
        alb_url = os.environ['ALB_URL']
        response = requests.post(
            f"{alb_url}/evm",
            json=json.loads(event['body']),
            timeout=30
        )
        
        return {
            'statusCode': response.status_code,
            'body': response.text
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
