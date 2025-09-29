# Managed by Terraform
import json
import logging
import os
from typing import Dict, Any, Optional
from decimal import Decimal
from datetime import datetime

import jwt
from jwt import PyJWKClient

from panorama_datamodel import db_session
from panorama_datamodel.exceptions import NotFoundError, ValidationError, DatabaseError

from endpoints import rules, mitre, cve, filters

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Cognito Configuration
COGNITO_REGION = os.environ.get('COGNITO_REGION', 'us-east-2')
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID', '')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID', '')
DISABLE_AUTH = os.environ.get('DISABLE_AUTH', '').lower() == 'true'

# Initialize JWT client
jwks_client = None
if COGNITO_USER_POOL_ID and not DISABLE_AUTH:
    jwks_url = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    jwks_client = PyJWKClient(jwks_url)


class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def validate_token(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate Cognito JWT token"""
    if DISABLE_AUTH:
        return {'sub': 'test-user', 'email': 'test@example.com'}
    
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header or not jwks_client:
        return None
    
    try:
        token = auth_header.replace('Bearer ', '')
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        
        decoded = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            issuer=f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        )
        
        return decoded
    except jwt.ExpiredSignatureError:
        logger.error("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return None
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None


def create_response(status_code: int, body: Any) -> Dict[str, Any]:
    """Create API Gateway response"""
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Content-Type": "application/json"
        },
        "body": json.dumps(body, cls=JSONEncoder)
    }


# Public endpoints
PUBLIC_PATHS = {'/health'}

ROUTES = {
    'GET': {
        '/health': lambda e, p, u: {'status': 'healthy'},
        '/rules': lambda e, p, u: rules.search_rules(p),
        '/rules/{rule_id}': lambda e, p, u: rules.get_rule(e['pathParameters']['rule_id']),
        '/mitre/matrix': lambda e, p, u: mitre.get_matrix(p),
        '/mitre/techniques': lambda e, p, u: mitre.get_techniques(p),
        '/mitre/techniques/{technique_id}': lambda e, p, u: mitre.get_technique_detail(e['pathParameters']['technique_id']), 
        '/cves': lambda e, p, u: cve.search_cves(p),
        '/cves/{cve_id}': lambda e, p, u: cve.get_cve(e['pathParameters']['cve_id']),
        '/filters': lambda e, p, u: filters.get_all_filters()
    }
}


def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """Lambda handler"""
    
    logger.info(f"Raw event: {json.dumps(event)}")
    logger.info(f"Query params: {event.get('queryStringParameters')}")
    logger.info(f"Multi-value params: {event.get('multiValueQueryStringParameters')}")
    
    # Debug auth configuration
    logger.info(f"DISABLE_AUTH: {DISABLE_AUTH}")
    logger.info(f"COGNITO_USER_POOL_ID: {COGNITO_USER_POOL_ID}")
    logger.info(f"COGNITO_CLIENT_ID: {COGNITO_CLIENT_ID}")
    logger.info(f"jwks_client initialized: {jwks_client is not None}")

    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/').rstrip('/')
    
    if method == 'OPTIONS':
        return create_response(200, {})
    
    # Authentication check
    user_context = None
    if path not in PUBLIC_PATHS and not DISABLE_AUTH:
        user_context = validate_token(event)
        if not user_context:
            return create_response(401, {"error": "Unauthorized"})
    
    # Route handling
    routes = ROUTES.get(method, {})
    
    # Direct path match
    if path in routes:
        try:
            params = event.get('queryStringParameters') or {}
            result = routes[path](event, params, user_context)
            return create_response(200, result)
        except NotFoundError as e:
            return create_response(404, {"error": str(e)})
        except ValidationError as e:
            return create_response(400, {"error": str(e)})
        except DatabaseError as e:
            logger.error(f"Database error: {e}")
            return create_response(500, {"error": "Database error"})
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return create_response(500, {"error": "Internal server error"})
    
    # Pattern match for parameterized routes
    for route_pattern, handler in routes.items():
        if '{' in route_pattern:
            pattern_parts = route_pattern.split('/')
            path_parts = path.split('/')
            
            if len(pattern_parts) == len(path_parts):
                params_match = {}
                match = True
                
                for i, part in enumerate(pattern_parts):
                    if part.startswith('{') and part.endswith('}'):
                        param_name = part[1:-1]
                        params_match[param_name] = path_parts[i]
                    elif part != path_parts[i]:
                        match = False
                        break
                
                if match:
                    event['pathParameters'] = params_match
                    try:
                        params = event.get('queryStringParameters') or {}
                        result = handler(event, params, user_context)
                        return create_response(200, result)
                    except NotFoundError as e:
                        return create_response(404, {"error": str(e)})
                    except ValidationError as e:
                        return create_response(400, {"error": str(e)})
                    except DatabaseError as e:
                        logger.error(f"Database error: {e}")
                        return create_response(500, {"error": "Database error"})
                    except Exception as e:
                        logger.error(f"Unexpected error: {e}", exc_info=True)
                        return create_response(500, {"error": "Internal server error"})
    
    return create_response(404, {"error": "Not found"})