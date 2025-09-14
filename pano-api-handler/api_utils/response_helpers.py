"""
API Gateway response helpers
"""

import json
from decimal import Decimal
from datetime import datetime
from typing import Any, Dict, Optional


class CustomJSONEncoder(json.JSONEncoder):
    """Handle Decimal and datetime serialization"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def create_api_response(status_code: int, body: Any) -> Dict[str, Any]:
    """Create standardized API Gateway response"""
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": True,
            "Content-Type": "application/json"
        },
        "body": json.dumps(body, cls=CustomJSONEncoder)
    }


def create_error_response(
    status_code: int, 
    error_message: str, 
    details: Optional[Any] = None
) -> Dict[str, Any]:
    """Create standardized error response"""
    error_body = {"error": error_message}
    if details:
        error_body["details"] = details
    return create_api_response(status_code, error_body)