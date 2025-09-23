import json
import logging
import os
from typing import Dict, Any, Optional
from decimal import Decimal
from datetime import datetime

# Conditional JWT import
try:
    import jwt
    from jwt import PyJWKClient
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logging.warning("PyJWT not available - authentication disabled")

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

# Initialize JWT client if available
jwks_client = None
if JWT_AVAILABLE and COGNITO_USER_POOL_ID and not DISABLE_AUTH:
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
    
    if not JWT_AVAILABLE:
        logger.error("JWT validation requested but PyJWT not available")
        return None
    
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
        
        return {
            'sub': decoded.get('sub'),
            'email': decoded.get('email'),
            'username': decoded.get('cognito:username'),
            'groups': decoded.get('cognito:groups', [])
        }
    except Exception as e:
        logger.warning(f"Token validation failed: {e}")
        return None


def parse_params(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract query parameters"""
    params = {}
    
    multi_params = event.get('multiValueQueryStringParameters') or {}
    
    for key, values in multi_params.items():
        if not values:
            continue
            
        if key in {'rule_types', 'severities', 'tags', 'mitre_techniques', 'cve_ids', 'platforms'}:
            if len(values) > 1:
                params[key] = values
            elif ',' in values[0]:
                params[key] = [v.strip() for v in values[0].split(',')]
            else:
                params[key] = values
        else:
            value = values[0]
            
            if key in {'offset', 'limit'}:
                try:
                    params[key] = int(value)
                except ValueError:
                    pass
            elif key in {'is_active', 'include_stats', 'include_content'}:
                params[key] = value.lower() in ('true', '1', 'yes')
            else:
                params[key] = value
    
    params.setdefault('offset', 0)
    params.setdefault('limit', 25)
    params['limit'] = min(params['limit'], 1000)
    
    return params


def create_response(status: int, body: Any) -> Dict[str, Any]:
    """Create API Gateway response"""
    return {
        "statusCode": status,
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
        '/cves': lambda e, p, u: cve.search_cves(p),
        '/cves/{cve_id}': lambda e, p, u: cve.get_cve(e['pathParameters']['cve_id']),
        '/filters': lambda e, p, u: filters.get_all_filters()
    }
}


def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """Lambda handler"""
    
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
    
    try:
        params = parse_params(event)
        
        if user_context:
            params['user_context'] = user_context
        
        routes = ROUTES.get(method, {})
        
        if path in routes:
            result = routes[path](event, params, user_context)
            return create_response(200, result)
        
        # Path parameter matching
        for route_pattern, handler in routes.items():
            if '{' in route_pattern:
                pattern_parts = route_pattern.split('/')
                path_parts = path.split('/')
                
                if len(pattern_parts) == len(path_parts):
                    matches = True
                    path_params = {}
                    
                    for pattern_part, path_part in zip(pattern_parts, path_parts):
                        if pattern_part.startswith('{') and pattern_part.endswith('}'):
                            param_name = pattern_part[1:-1]
                            path_params[param_name] = path_part
                        elif pattern_part != path_part:
                            matches = False
                            break
                    
                    if matches:
                        event['pathParameters'] = path_params
                        result = handler(event, params, user_context)
                        return create_response(200, result)
        
        return create_response(404, {"error": f"Endpoint not found: {method} {path}"})
        
    except Exception as e:
        logger.error(f"Request error: {e}", exc_info=True)
        return create_response(500, {"error": "Internal server error"})