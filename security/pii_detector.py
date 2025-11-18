"""
PII Detection module for identifying and scrubbing personally identifiable information.
"""

import re
from typing import Dict, List, Tuple


class PIIDetector:
    """Detects and redacts PII from text using pattern matching."""

    # Regex patterns for common PII types
    PATTERNS = {
        'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'PHONE_US': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
        'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
        'CREDIT_CARD': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'IP_ADDRESS': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'DATE_OF_BIRTH': r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b',
        'ZIP_CODE': r'\b\d{5}(?:-\d{4})?\b',
        'PASSPORT': r'\b[A-Z]{1,2}\d{6,9}\b',
        'DRIVER_LICENSE': r'\b[A-Z]{1,2}\d{5,8}\b',
    }

    # Additional name patterns
    NAME_PREFIXES = ['mr', 'mrs', 'ms', 'dr', 'prof']

    def __init__(self):
        """Initialize the PII detector with compiled patterns."""
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.PATTERNS.items()
        }

    def detect(self, text: str) -> Dict[str, List[str]]:
        """
        Detect PII in the given text.

        Args:
            text: Text to scan for PII

        Returns:
            Dictionary mapping PII type to list of detected instances
        """
        findings = {}

        for pii_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                findings[pii_type] = list(set(matches))  # Remove duplicates

        return findings

    def redact(self, text: str, placeholder: str = '[REDACTED]') -> Tuple[str, Dict[str, int]]:
        """
        Redact PII from text.

        Args:
            text: Text to redact
            placeholder: Replacement string for PII

        Returns:
            Tuple of (redacted_text, counts_by_type)
        """
        redacted_text = text
        counts = {}

        for pii_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(redacted_text)
            if matches:
                counts[pii_type] = len(matches)
                # Replace each match with placeholder
                redacted_text = pattern.sub(f'{placeholder}_{pii_type}', redacted_text)

        return redacted_text, counts

    def has_pii(self, text: str) -> bool:
        """
        Quick check if text contains any PII.

        Args:
            text: Text to check

        Returns:
            True if PII detected, False otherwise
        """
        for pattern in self.compiled_patterns.values():
            if pattern.search(text):
                return True
        return False

    def get_pii_summary(self, text: str) -> Dict[str, int]:
        """
        Get summary count of PII types found.

        Args:
            text: Text to analyze

        Returns:
            Dictionary mapping PII type to count
        """
        summary = {}

        for pii_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                summary[pii_type] = len(matches)

        return summary


def sanitize_pii(text: str, aggressive: bool = False) -> str:
    """
    Convenience function to sanitize PII from text.

    Args:
        text: Text to sanitize
        aggressive: If True, use more aggressive redaction

    Returns:
        Sanitized text
    """
    detector = PIIDetector()
    redacted_text, _ = detector.redact(text)
    return redacted_text
