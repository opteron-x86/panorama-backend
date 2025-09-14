"""
Rule issues management endpoints
"""

import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

from panorama_datamodel import db_session
from panorama_datamodel.models import DetectionRule
from api_utils.response_helpers import create_api_response, create_error_response

logger = logging.getLogger(__name__)

# In production, this would integrate with an issue tracking system
# For now, we'll simulate with local storage or database table
ISSUE_TRACKING_ENABLED = False


def create_rule_issue(
    rule_id: str, 
    body: Dict[str, Any], 
    user_context: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Create an issue for a specific rule"""
    try:
        # Validate required fields
        title = body.get('title')
        description = body.get('description')
        issue_type = body.get('issueType')
        
        if not all([title, description, issue_type]):
            return create_error_response(
                400, 
                "Missing required fields: title, description, issueType"
            )
        
        # Validate issue type
        valid_types = ['false_positive', 'enhancement', 'bug', 'question']
        if issue_type not in valid_types:
            return create_error_response(
                400, 
                f"Invalid issueType. Must be one of: {', '.join(valid_types)}"
            )
        
        with db_session() as session:
            # Verify rule exists
            rule = session.query(DetectionRule).filter(
                DetectionRule.rule_id == rule_id
            ).first()
            
            if not rule:
                return create_error_response(404, f"Rule {rule_id} not found")
            
            # Generate issue ID
            issue_id = str(uuid.uuid4())
            
            # Prepare issue data
            issue_data = {
                'id': issue_id,
                'rule_id': rule_id,
                'rule_name': rule.name,
                'title': title,
                'description': description,
                'issue_type': issue_type,
                'status': 'open',
                'created_at': datetime.now().isoformat(),
                'created_by': user_context.get('email') if user_context else 'anonymous',
                'event_source': body.get('eventSource'),
                'event_timestamp': body.get('eventTimestamp'),
                'metadata': {
                    'rule_severity': rule.severity,
                    'rule_type': rule.rule_type,
                    'rule_source': rule.source.name if rule.source else None
                }
            }
            
            # In production, this would create an issue in Jira/GitHub/etc
            if ISSUE_TRACKING_ENABLED:
                # Integration with external issue tracker
                pass
            else:
                # Log the issue for now
                logger.info(f"Issue created for rule {rule_id}: {json.dumps(issue_data)}")
            
            # Generate response
            response_data = {
                'message': f"Issue created successfully for rule {rule_id}",
                'issue_url': f"https://issues.example.com/{issue_id}",
                'rule_id': rule_id
            }
            
            return create_api_response(201, response_data)
            
    except Exception as e:
        logger.error(f"Error creating issue for rule {rule_id}: {e}", exc_info=True)
        return create_error_response(500, "Failed to create issue")


def get_rule_issues(rule_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Get issues for a specific rule"""
    try:
        with db_session() as session:
            # Verify rule exists
            rule = session.query(DetectionRule).filter(
                DetectionRule.rule_id == rule_id
            ).first()
            
            if not rule:
                return create_error_response(404, f"Rule {rule_id} not found")
            
            # In production, fetch from issue tracking system
            # For now, return empty list
            issues = []
            
            response_data = {
                'rule_id': rule_id,
                'issues': issues,
                'total': 0
            }
            
            return create_api_response(200, response_data)
            
    except Exception as e:
        logger.error(f"Error fetching issues for rule {rule_id}: {e}", exc_info=True)
        return create_error_response(500, "Failed to fetch issues")


def update_rule_issue(
    rule_id: str, 
    issue_id: str, 
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Update an existing issue"""
    try:
        # In production, update in issue tracking system
        if ISSUE_TRACKING_ENABLED:
            pass
        else:
            logger.info(f"Issue {issue_id} updated for rule {rule_id}")
        
        response_data = {
            'message': f"Issue {issue_id} updated successfully",
            'rule_id': rule_id,
            'issue_id': issue_id
        }
        
        return create_api_response(200, response_data)
        
    except Exception as e:
        logger.error(f"Error updating issue {issue_id}: {e}", exc_info=True)
        return create_error_response(500, "Failed to update issue")