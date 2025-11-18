"""
Data Sanitizer module for comprehensive data cleaning.
"""

import json
from typing import Dict, Any, Union
from .pii_detector import PIIDetector
from .credential_scanner import CredentialScanner


class DataSanitizer:
    """Comprehensive data sanitization combining PII and credential redaction."""

    def __init__(self):
        """Initialize sanitizer with PII and credential scanners."""
        self.pii_detector = PIIDetector()
        self.credential_scanner = CredentialScanner()

    def sanitize(self, text: str, redact_pii: bool = True, redact_credentials: bool = True) -> Dict[str, Any]:
        """
        Sanitize text by removing PII and credentials.

        Args:
            text: Text to sanitize
            redact_pii: Whether to redact PII
            redact_credentials: Whether to redact credentials

        Returns:
            Dictionary with sanitized text and metadata
        """
        sanitized_text = text
        pii_found = {}
        credentials_found = {}

        if redact_pii:
            sanitized_text, pii_counts = self.pii_detector.redact(sanitized_text)
            pii_found = self.pii_detector.detect(text)

        if redact_credentials:
            credentials_found = self.credential_scanner.scan(sanitized_text)
            sanitized_text = self.credential_scanner.redact_credentials(sanitized_text)

        return {
            'sanitized_text': sanitized_text,
            'original_length': len(text),
            'sanitized_length': len(sanitized_text),
            'pii_found': pii_found,
            'credentials_found': credentials_found,
            'has_sensitive_data': bool(pii_found or credentials_found)
        }

    def sanitize_json(self, data: Union[Dict, list], fields_to_sanitize: list = None) -> Dict[str, Any]:
        """
        Sanitize JSON data structures.

        Args:
            data: JSON data (dict or list)
            fields_to_sanitize: List of field names to sanitize (None = all string fields)

        Returns:
            Dictionary with sanitized data and metadata
        """
        if fields_to_sanitize is None:
            fields_to_sanitize = ['prompt', 'response', 'text', 'content', 'message']

        sanitized_data = self._sanitize_recursive(data, fields_to_sanitize)

        return {
            'sanitized_data': sanitized_data,
            'fields_sanitized': fields_to_sanitize
        }

    def _sanitize_recursive(self, obj: Any, fields: list) -> Any:
        """
        Recursively sanitize data structures.

        Args:
            obj: Object to sanitize
            fields: Fields to sanitize

        Returns:
            Sanitized object
        """
        if isinstance(obj, dict):
            return {
                key: self._sanitize_field(key, value, fields) if isinstance(value, str) and key in fields
                else self._sanitize_recursive(value, fields)
                for key, value in obj.items()
            }
        elif isinstance(obj, list):
            return [self._sanitize_recursive(item, fields) for item in obj]
        else:
            return obj

    def _sanitize_field(self, field_name: str, value: str, fields: list) -> str:
        """
        Sanitize a single field value.

        Args:
            field_name: Name of the field
            value: Field value
            fields: List of fields to sanitize

        Returns:
            Sanitized value
        """
        if field_name not in fields:
            return value

        result = self.sanitize(value)
        return result['sanitized_text']

    def scan_only(self, text: str) -> Dict[str, Any]:
        """
        Scan text for sensitive data without redacting.

        Args:
            text: Text to scan

        Returns:
            Scan results
        """
        pii = self.pii_detector.detect(text)
        credentials = self.credential_scanner.assess_risk(text)

        return {
            'has_pii': bool(pii),
            'has_credentials': credentials['total_credentials'] > 0,
            'pii_summary': self.pii_detector.get_pii_summary(text),
            'credential_risk': credentials,
            'overall_risk': self._calculate_overall_risk(pii, credentials)
        }

    def _calculate_overall_risk(self, pii: Dict, credentials: Dict) -> str:
        """
        Calculate overall risk level.

        Args:
            pii: PII detection results
            credentials: Credential scan results

        Returns:
            Risk level string
        """
        cred_risk = credentials.get('risk_level', 'LOW')

        if cred_risk == 'CRITICAL':
            return 'CRITICAL'

        pii_count = len(pii)
        if pii_count > 5 or cred_risk == 'HIGH':
            return 'HIGH'
        elif pii_count > 2 or cred_risk == 'MEDIUM':
            return 'MEDIUM'
        elif pii_count > 0:
            return 'LOW'
        else:
            return 'NONE'


def sanitize_text(text: str) -> str:
    """
    Convenience function to sanitize text.

    Args:
        text: Text to sanitize

    Returns:
        Sanitized text
    """
    sanitizer = DataSanitizer()
    result = sanitizer.sanitize(text)
    return result['sanitized_text']
