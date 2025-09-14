import json
import logging
import re
import os
from typing import Dict, Any, Optional

try:
    import jwt
    from jwt import PyJWKClient
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logging.warning("PyJWT not available - authentication will fail")

from panorama_datamodel import db_session
from panorama_datamodel.exceptions import NotFoundError, ValidationError, DatabaseError

from api_utils.response_helpers import create_api_response, create_error_response
from api_utils.parameter_parser import ParameterParser
from endpoints import rules, mitre, cve, filters, statistics, issues

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Cognito Configuration
COGNITO_REGION = os.environ.get('COGNITO_REGION', '')
COGNITO_USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID', '')
COGNITO_CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID', '')
DISABLE_AUTH = os.environ.get('DISABLE_AUTH', 'false').lower() == 'true'

# Initialize JWT client
jwks_client = None
if JWT_AVAILABLE and not DISABLE_AUTH and COGNITO_USER_POOL_ID:
    jwks_url = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
    jwks_client = PyJWKClient(jwks_url)


def validate_jwt_token(token: str) -> Dict[str, Any]:
    """Validate Cognito JWT token"""
    if not JWT_AVAILABLE:
        raise ValidationError("JWT validation not available")
    
    if not jwks_client:
        raise ValidationError("JWT client not initialized")
    
    try:
        if token.startswith('Bearer '):
            token = token[7:]
        
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
        raise ValidationError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValidationError(f"Invalid token: {e}")


def extract_user_context(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract user context from JWT token"""
    auth_header = event.get('headers', {}).get('Authorization', '')
    
    if not auth_header:
        return None
    
    try:
        user_data = validate_jwt_token(auth_header)
        return {
            'sub': user_data.get('sub'),
            'email': user_data.get('email'),
            'username': user_data.get('cognito:username'),
            'groups': user_data.get('cognito:groups', [])
        }
    except ValidationError as e:
        logger.error(f"Token validation failed: {e}")
        return None


def add_cors_headers(response: Dict[str, Any]) -> Dict[str, Any]:
    """Add CORS headers to response"""
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": True,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
        "Access-Control-Max-Age": "86400",
        "Content-Type": "application/json"
    }
    
    if "headers" in response:
        response["headers"].update(cors_headers)
    else:
        response["headers"] = cors_headers
    
    return response


def handle_options_request() -> Dict[str, Any]:
    """Handle CORS preflight requests"""
    return add_cors_headers({
        "statusCode": 200,
        "body": json.dumps({"message": "OK"})
    })


def route_request(
    http_method: str,
    path: str,
    params: Dict[str, Any],
    path_params: Dict[str, str],
    event: Dict[str, Any]
) -> Dict[str, Any]:
    """Route incoming requests to appropriate endpoint handlers"""
    
    normalized_path = path.rstrip('/')
    
    try:
        # Public endpoints
        if http_method == 'GET' and normalized_path in ['/health', '']:
            return create_api_response(200, {
                "status": "healthy",
                "service": "saint-api",
                "version": "2.0",
                "auth_enabled": not DISABLE_AUTH
            })
        
        if http_method == 'GET' and normalized_path == '/api/docs':
            return create_api_response(200, {
                "title": "SAINT API Documentation",
                "version": "2.0",
                "auth_required": not DISABLE_AUTH,
                "endpoints": {
                    "rules": "GET /rules - Search detection rules",
                    "rule_details": "GET /rules/{id} - Get rule details",
                    "rule_stats": "GET /rules/stats - Get statistics",
                    "rule_enrichment": "GET /rules/enrichment - Get enrichment stats",
                    "rule_export": "GET /rules/export - Export rules",
                    "mitre_matrix": "GET /mitre/matrix - Get MITRE matrix",
                    "mitre_coverage": "GET /mitre/coverage - Get coverage",
                    "mitre_techniques": "GET /mitre/techniques - List techniques",
                    "mitre_tactics": "GET /mitre/tactics - List tactics",
                    "cves": "GET /cves - Search CVEs",
                    "cve_details": "GET /cves/{id} - Get CVE details",
                    "cve_stats": "GET /cves/stats - Get CVE statistics",
                    "filters": "GET /filters/options - Get filter options",
                    "analytics_dashboard": "GET /analytics/dashboard - Dashboard data",
                    "analytics_trends": "GET /analytics/trends - Trend analysis",
                    "deprecated_statistics": "GET /deprecated/statistics - Deprecation metrics",
                    "deprecated_affected": "GET /deprecated/affected-rules - List affected rules",
                    "deprecated_check": "GET /deprecated/check-rule - Check specific rule",
                    "deprecated_update": "POST /deprecated/update-mappings - Update mappings",
                    "search": "GET /search - Global search"
                }
            })
        
        # Rule endpoints
        if http_method == 'GET' and normalized_path == '/rules':
            return rules.search_rules(params)
        
        if http_method == 'GET' and normalized_path == '/rules/stats':
            return statistics.handle_get_stats(params)
        
        if http_method == 'GET' and normalized_path == '/rules/enrichment':
            return rules.get_enrichment_stats(params)
        
        if http_method == 'GET' and normalized_path == '/rules/export':
            return rules.export_rules(params)
        
        # Rule detail with path parameter
        if http_method == 'GET' and re.match(r'^/rules/[^/]+$', normalized_path):
            rule_id = path_params.get('rule_id')
            if not rule_id:
                # Extract from path if not in path_params
                rule_id = normalized_path.split('/')[-1]
            return rules.get_rule_details(rule_id)
        
        # Rule issue creation
        if http_method == 'POST' and re.match(r'^/rules/[^/]+/issues$', normalized_path):
            rule_id = path_params.get('rule_id')
            if not rule_id:
                rule_id = normalized_path.split('/')[-2]
            body = json.loads(event.get('body', '{}'))
            return issues.create_rule_issue(rule_id, body, params.get('user_context'))
        
        # MITRE endpoints
        if http_method == 'GET' and normalized_path == '/mitre/matrix':
            return mitre.get_mitre_matrix(params)
        
        if http_method == 'GET' and normalized_path == '/mitre/coverage':
            return mitre.get_coverage_analysis(params)
        
        if http_method == 'GET' and normalized_path == '/mitre/techniques':
            return mitre.get_techniques_list(params)
        
        if http_method == 'GET' and normalized_path == '/mitre/tactics':
            return mitre.get_tactics_list(params)
        
        # CVE endpoints
        if http_method == 'GET' and normalized_path == '/cves':
            return cve.search_cves(params)
        
        if http_method == 'GET' and normalized_path == '/cves/stats':
            return cve.get_cve_stats(params)
        
        # CVE detail with path parameter
        if http_method == 'GET' and re.match(r'^/cves/CVE-\d{4}-\d+$', normalized_path):
            cve_id = path_params.get('cve_id')
            if not cve_id:
                cve_id = normalized_path.split('/')[-1]
            return cve.get_cve_details(cve_id)
        
        # Filter endpoints
        if http_method == 'GET' and normalized_path == '/filters/options':
            return filters.get_filter_options()
        
        # Analytics endpoints
        if http_method == 'GET' and normalized_path == '/analytics/dashboard':
            return statistics.get_dashboard_data(params)
        
        if http_method == 'GET' and normalized_path == '/analytics/trends':
            return statistics.get_trend_analysis(params)
        
        # Deprecated techniques endpoints
        if http_method == 'GET' and normalized_path == '/deprecated/statistics':
            return deprecated_techniques.get_deprecated_statistics(params)
        
        if http_method == 'GET' and normalized_path == '/deprecated/affected-rules':
            return deprecated_techniques.get_rules_with_deprecated_techniques(params)
        
        if http_method == 'GET' and normalized_path == '/deprecated/check-rule':
            if 'rule_id' not in params:
                params['rule_id'] = path_params.get('rule_id')
            return deprecated_techniques.check_rule_deprecated_techniques(params)
        
        if http_method == 'POST' and normalized_path == '/deprecated/update-mappings':
            body = json.loads(event.get('body', '{}'))
            return deprecated_techniques.update_deprecated_mappings(body)
        
        # Global search
        if http_method == 'GET' and normalized_path == '/search':
            return handle_global_search(params)
        
        # No matching route
        return create_error_response(404, f"Endpoint not found: {http_method} {path}")
        
    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        return create_error_response(400, str(e))
    except NotFoundError as e:
        logger.warning(f"Resource not found: {e}")
        return create_error_response(404, str(e))
    except DatabaseError as e:
        logger.error(f"Database error: {e}", exc_info=True)
        return create_error_response(503, "Database temporarily unavailable")
    except Exception as e:
        logger.error(f"Unexpected error in routing: {e}", exc_info=True)
        return create_error_response(500, "Internal server error")


def handle_global_search(params: Dict[str, Any]) -> Dict[str, Any]:
    """Handle global search across multiple entity types"""
    try:
        query = params.get('query', '')
        if not query:
            return create_error_response(400, "Query parameter required")
        
        results = {
            'query': query,
            'rules': [],
            'techniques': [],
            'cves': []
        }
        
        # Determine search type based on query pattern
        if query.upper().startswith('T'):
            # Search MITRE techniques
            data = mitre.get_techniques_list({'search': query, 'limit': 5})
            if data.get('statusCode') == 200:
                body = json.loads(data.get('body', '{}'))
                results['techniques'] = body.get('techniques', [])[:5]
        
        if query.upper().startswith('CVE'):
            # Search CVEs
            data = cve.search_cves({'query': query, 'limit': 5})
            if data.get('statusCode') == 200:
                body = json.loads(data.get('body', '{}'))
                results['cves'] = body.get('data', [])[:5]
        
        # Always search rules
        data = rules.search_rules({'query': query, 'limit': 5})
        if data.get('statusCode') == 200:
            body = json.loads(data.get('body', '{}'))
            results['rules'] = body.get('items', [])[:5]
        
        return create_api_response(200, results)
        
    except Exception as e:
        logger.error(f"Error in global search: {e}", exc_info=True)
        return create_error_response(500, "Search failed")


def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """Main Lambda handler with Cognito authentication"""
    
    logger.info(f"Request: {event.get('httpMethod')} {event.get('path')}")
    
    # Parse request
    http_method = event.get('httpMethod', '').upper()
    path = event.get('path', '/')
    params = ParameterParser.parse_api_gateway_event(event)
    path_params = ParameterParser.extract_path_parameters(event)
    
    # Handle CORS preflight
    if http_method == 'OPTIONS':
        return handle_options_request()
    
    # Public endpoints that don't require auth
    public_endpoints = ['/health', '/api/docs', '/']
    is_public = any(path.rstrip('/') == ep or path.startswith(ep) for ep in public_endpoints)
    
    # Validate authentication for protected endpoints
    user_context = None
    if not is_public:
        # Check if JWT is available when auth is required
        if not JWT_AVAILABLE and not DISABLE_AUTH:
            logger.error("JWT library not available but auth is required")
            return add_cors_headers({
                "statusCode": 503,
                "body": json.dumps({"error": "Authentication service unavailable"})
            })
        
        user_context = extract_user_context(event)
        if not user_context and not DISABLE_AUTH:
            logger.warning(f"Unauthorized access attempt to {path}")
            return add_cors_headers({
                "statusCode": 401,
                "body": json.dumps({"error": "Unauthorized - valid JWT token required"})
            })
    
    # Add user context to params for downstream use
    if user_context:
        params['user_context'] = user_context
        logger.info(f"Authenticated user: {user_context.get('email', 'unknown')}")
    
    try:
        # Route to endpoints
        response = route_request(http_method, path, params, path_params, event)
        return add_cors_headers(response)
    except Exception as e:
        logger.error(f"Request error: {e}", exc_info=True)
        return add_cors_headers(create_error_response(500, "Internal server error"))