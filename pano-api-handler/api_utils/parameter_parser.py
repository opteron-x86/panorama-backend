"""
Centralized parameter parsing and validation for API Gateway events
"""

from typing import Dict, Any, List, Optional, Union
import logging

logger = logging.getLogger(__name__)


class ParameterParser:
    """Centralized parameter parsing and validation"""
    
    # Single-value parameters - always take first value
    SINGLE_VALUE_PARAMS = {
        'query', 'offset', 'limit', 'sort_by', 'sort_dir',
        'is_active', 'has_mitre', 'has_cves', 'enrichment_score_min',
        'start_date', 'end_date', 'rule_id', 'technique_id', 'cve_id',
        'format', 'include_content', 'include_details', 'search'
    }
    
    # Array parameters - can have multiple values
    ARRAY_PARAMS = {
        'rule_types', 'severities', 'rule_sources', 'tags',
        'rule_platforms', 'mitre_techniques', 'mitre_tactics',
        'cve_ids', 'siem_platforms', 'aors', 'data_sources',
        'info_controls', 'validation_status', 'platforms'
    }
    
    # Type conversion mappings
    INTEGER_PARAMS = {'offset', 'limit', 'enrichment_score_min'}
    BOOLEAN_PARAMS = {
        'is_active', 'has_mitre', 'has_cves', 
        'include_details', 'include_content'
    }
    
    # Default values
    DEFAULTS = {
        'offset': 0,
        'limit': 25,
        'sort_by': 'updated_date',
        'sort_dir': 'desc'
    }
    
    # Validation limits
    MAX_LIMIT = 1000
    MIN_LIMIT = 1
    
    @classmethod
    def parse_api_gateway_event(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse parameters from API Gateway event
        
        Uses multiValueQueryStringParameters as source of truth
        """
        params = {}
        
        # multiValueQueryStringParameters is the authoritative source
        multi_params = event.get('multiValueQueryStringParameters') or {}
        
        for key, values in multi_params.items():
            if not values:  # Skip empty lists
                continue
            
            if key in cls.SINGLE_VALUE_PARAMS:
                # Single value parameters - take first value
                params[key] = values[0]
            elif key in cls.ARRAY_PARAMS:
                # Array parameters - handle multiple values or comma-separated
                if len(values) > 1:
                    params[key] = values
                elif ',' in values[0]:
                    # Split comma-separated values
                    params[key] = [v.strip() for v in values[0].split(',')]
                else:
                    params[key] = values
            else:
                # Unknown parameter - log warning but include it
                logger.warning(f"Unknown parameter: {key}")
                params[key] = values[0] if len(values) == 1 else values
        
        # Apply type conversions
        params = cls._convert_types(params)
        
        # Apply defaults for required parameters
        for key, default in cls.DEFAULTS.items():
            params.setdefault(key, default)
        
        # Validate and enforce limits
        params = cls._validate_limits(params)
        
        return params
    
    @classmethod
    def _convert_types(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert parameter types to expected formats"""
        
        # Integer conversions
        for key in cls.INTEGER_PARAMS:
            if key in params:
                try:
                    params[key] = int(params[key])
                except (ValueError, TypeError):
                    logger.warning(f"Invalid integer value for {key}: {params[key]}")
                    # Use default if available, otherwise remove
                    if key in cls.DEFAULTS:
                        params[key] = cls.DEFAULTS[key]
                    else:
                        del params[key]
        
        # Boolean conversions
        for key in cls.BOOLEAN_PARAMS:
            if key in params:
                value = params[key]
                if isinstance(value, str):
                    params[key] = value.lower() in ('true', '1', 'yes', 'on')
                elif not isinstance(value, bool):
                    # Invalid boolean value - remove
                    logger.warning(f"Invalid boolean value for {key}: {value}")
                    del params[key]
        
        return params
    
    @classmethod
    def _validate_limits(cls, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and enforce parameter limits"""
        
        # Limit validation
        if 'limit' in params:
            params['limit'] = max(cls.MIN_LIMIT, min(params['limit'], cls.MAX_LIMIT))
        
        # Offset validation
        if 'offset' in params:
            params['offset'] = max(0, params['offset'])
        
        # Sort direction validation
        if 'sort_dir' in params:
            if params['sort_dir'] not in ('asc', 'desc'):
                params['sort_dir'] = 'desc'
        
        return params
    
    @classmethod
    def extract_path_parameters(cls, event: Dict[str, Any]) -> Dict[str, str]:
        """
        Extract and validate path parameters from API Gateway event
        
        Path parameters are always strings
        """
        path_params = event.get('pathParameters') or {}
        validated = {}
        
        for key, value in path_params.items():
            if value is not None:
                # Convert to string and strip whitespace
                validated[key] = str(value).strip()
        
        return validated
    
    @classmethod
    def parse_request_body(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse JSON body from API Gateway event
        
        Handles base64 encoding if necessary
        """
        import json
        import base64
        
        body = event.get('body')
        if not body:
            return {}
        
        try:
            # Check if body is base64 encoded
            if event.get('isBase64Encoded', False):
                body = base64.b64decode(body).decode('utf-8')
            
            # Parse JSON
            if isinstance(body, str):
                return json.loads(body)
            else:
                return body
                
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse request body: {e}")
            return {}
    
    @classmethod
    def validate_required_params(
        cls, 
        params: Dict[str, Any], 
        required: List[str]
    ) -> tuple[bool, Optional[str]]:
        """
        Validate that required parameters are present
        
        Returns (is_valid, error_message)
        """
        missing = [p for p in required if not params.get(p)]
        
        if missing:
            return False, f"Missing required parameters: {', '.join(missing)}"
        
        return True, None