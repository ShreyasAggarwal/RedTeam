"""
Security module for RedTeam framework.
Provides PII detection, credential scanning, data sanitization, audit logging,
rate limiting, and access control.
"""

from .pii_detector import PIIDetector
from .credential_scanner import CredentialScanner
from .sanitizer import DataSanitizer
from .audit_logger import AuditLogger, get_audit_logger
from .rate_limiter import RateLimiter, MultiRateLimiter, get_model_rate_limiter
from .access_control import (
    AccessControl, User, Role, Permission,
    get_access_control, require_permission
)

__all__ = [
    'PIIDetector',
    'CredentialScanner',
    'DataSanitizer',
    'AuditLogger',
    'get_audit_logger',
    'RateLimiter',
    'MultiRateLimiter',
    'get_model_rate_limiter',
    'AccessControl',
    'User',
    'Role',
    'Permission',
    'get_access_control',
    'require_permission',
]
