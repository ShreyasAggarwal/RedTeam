"""
Credential Scanner module for detecting API keys, tokens, and secrets.
"""

import re
from typing import Dict, List, Set


class CredentialScanner:
    """Scans text for exposed credentials and API keys."""

    # Regex patterns for various credential types
    PATTERNS = {
        'OPENAI_API_KEY': r'sk-[a-zA-Z0-9]{48}',
        'ANTHROPIC_API_KEY': r'sk-ant-[a-zA-Z0-9\-]{95,}',
        'GOOGLE_API_KEY': r'AIza[0-9A-Za-z\-_]{35}',
        'AWS_ACCESS_KEY': r'AKIA[0-9A-Z]{16}',
        'AWS_SECRET_KEY': r'aws_secret_access_key\s*=\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
        'GITHUB_TOKEN': r'gh[pousr]_[A-Za-z0-9]{36}',
        'SLACK_TOKEN': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
        'STRIPE_API_KEY': r'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
        'JWT_TOKEN': r'eyJ[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2}',
        'BASIC_AUTH': r'(?:basic|bearer)\s+[A-Za-z0-9+/=]{20,}',
        'PRIVATE_KEY': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        'GENERIC_SECRET': r'(?:secret|password|passwd|pwd|token|api[_-]?key)["\s:=]+["\']?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:,.<>?]{8,})["\']?',
    }

    # High-entropy string detection (potential secrets)
    HIGH_ENTROPY_PATTERN = r'\b[A-Za-z0-9+/=]{32,}\b'

    def __init__(self):
        """Initialize the credential scanner with compiled patterns."""
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.PATTERNS.items()
        }
        self.entropy_pattern = re.compile(self.HIGH_ENTROPY_PATTERN)

    def scan(self, text: str) -> Dict[str, List[str]]:
        """
        Scan text for exposed credentials.

        Args:
            text: Text to scan

        Returns:
            Dictionary mapping credential type to list of detected instances
        """
        findings = {}

        for cred_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Handle tuple results from groups
                if isinstance(matches[0], tuple):
                    matches = [m[0] if isinstance(m, tuple) else m for m in matches]
                findings[cred_type] = list(set(matches))  # Remove duplicates

        return findings

    def scan_high_entropy(self, text: str, min_entropy: float = 4.5) -> List[str]:
        """
        Detect high-entropy strings that might be secrets.

        Args:
            text: Text to scan
            min_entropy: Minimum Shannon entropy threshold

        Returns:
            List of high-entropy strings
        """
        matches = self.entropy_pattern.findall(text)
        high_entropy_matches = []

        for match in matches:
            if self._calculate_entropy(match) >= min_entropy:
                high_entropy_matches.append(match)

        return list(set(high_entropy_matches))

    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            string: String to analyze

        Returns:
            Entropy value
        """
        if not string:
            return 0.0

        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        length = len(string)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability ** 0.5)  # Simplified entropy

        return entropy

    def has_credentials(self, text: str) -> bool:
        """
        Quick check if text contains any credentials.

        Args:
            text: Text to check

        Returns:
            True if credentials detected, False otherwise
        """
        for pattern in self.compiled_patterns.values():
            if pattern.search(text):
                return True
        return False

    def redact_credentials(self, text: str, placeholder: str = '[CREDENTIAL_REDACTED]') -> str:
        """
        Redact credentials from text.

        Args:
            text: Text to redact
            placeholder: Replacement string

        Returns:
            Redacted text
        """
        redacted_text = text

        for cred_type, pattern in self.compiled_patterns.items():
            redacted_text = pattern.sub(f'{placeholder}_{cred_type}', redacted_text)

        return redacted_text

    def get_credential_summary(self, text: str) -> Dict[str, int]:
        """
        Get summary count of credential types found.

        Args:
            text: Text to analyze

        Returns:
            Dictionary mapping credential type to count
        """
        summary = {}

        for cred_type, pattern in self.compiled_patterns.items():
            matches = pattern.findall(text)
            if matches:
                summary[cred_type] = len(matches)

        return summary

    def assess_risk(self, text: str) -> Dict[str, any]:
        """
        Comprehensive risk assessment for exposed credentials.

        Args:
            text: Text to assess

        Returns:
            Risk assessment dictionary
        """
        credentials = self.scan(text)
        high_entropy = self.scan_high_entropy(text)

        total_credentials = sum(len(v) for v in credentials.values())
        high_risk_types = ['OPENAI_API_KEY', 'AWS_ACCESS_KEY', 'PRIVATE_KEY', 'STRIPE_API_KEY']
        high_risk_count = sum(len(credentials.get(t, [])) for t in high_risk_types)

        risk_level = 'LOW'
        if high_risk_count > 0:
            risk_level = 'CRITICAL'
        elif total_credentials > 3:
            risk_level = 'HIGH'
        elif total_credentials > 0:
            risk_level = 'MEDIUM'

        return {
            'risk_level': risk_level,
            'total_credentials': total_credentials,
            'high_risk_credentials': high_risk_count,
            'credential_types': list(credentials.keys()),
            'high_entropy_strings': len(high_entropy),
            'findings': credentials
        }


def scan_for_credentials(text: str) -> Dict[str, any]:
    """
    Convenience function to scan text for credentials.

    Args:
        text: Text to scan

    Returns:
        Risk assessment dictionary
    """
    scanner = CredentialScanner()
    return scanner.assess_risk(text)
