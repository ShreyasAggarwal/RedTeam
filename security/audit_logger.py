"""
Audit Logging system for tracking all security-relevant operations.
"""

import json
import hashlib
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class AuditLogger:
    """Immutable audit logging system with cryptographic verification."""

    def __init__(self, log_file: str = "data/audit.log"):
        """
        Initialize audit logger.

        Args:
            log_file: Path to audit log file
        """
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._previous_hash = self._get_last_hash()

    def log(self, event_type: str, user: str, action: str, details: Dict[str, Any] = None,
            severity: str = "INFO") -> str:
        """
        Log an audit event.

        Args:
            event_type: Type of event (e.g., 'ATTACK_RUN', 'MODEL_QUERY', 'DATA_ACCESS')
            user: User or system performing the action
            action: Description of the action
            details: Additional event details
            severity: Event severity (INFO, WARNING, ERROR, CRITICAL)

        Returns:
            Event hash for verification
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'

        event = {
            'timestamp': timestamp,
            'event_type': event_type,
            'user': user,
            'action': action,
            'severity': severity,
            'details': details or {},
            'previous_hash': self._previous_hash
        }

        # Calculate hash for this event
        event_hash = self._calculate_hash(event)
        event['event_hash'] = event_hash

        # Write to log file (append-only)
        with self.lock:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
            self._previous_hash = event_hash

        return event_hash

    def log_attack_execution(self, user: str, attack_id: str, model: str,
                           success: bool, details: Dict = None) -> str:
        """
        Log an attack execution event.

        Args:
            user: User executing the attack
            attack_id: ID of the attack
            model: Model being tested
            success: Whether attack was successful
            details: Additional details

        Returns:
            Event hash
        """
        return self.log(
            event_type='ATTACK_EXECUTION',
            user=user,
            action=f'Executed attack {attack_id} against {model}',
            details={
                'attack_id': attack_id,
                'model': model,
                'success': success,
                **(details or {})
            },
            severity='INFO' if not success else 'WARNING'
        )

    def log_data_access(self, user: str, resource: str, access_type: str = 'READ') -> str:
        """
        Log data access event.

        Args:
            user: User accessing data
            resource: Resource being accessed
            access_type: Type of access (READ, WRITE, DELETE)

        Returns:
            Event hash
        """
        return self.log(
            event_type='DATA_ACCESS',
            user=user,
            action=f'{access_type} access to {resource}',
            details={'resource': resource, 'access_type': access_type},
            severity='INFO'
        )

    def log_security_event(self, user: str, event: str, severity: str = 'WARNING',
                          details: Dict = None) -> str:
        """
        Log a security event.

        Args:
            user: User associated with event
            event: Description of security event
            severity: Event severity
            details: Additional details

        Returns:
            Event hash
        """
        return self.log(
            event_type='SECURITY_EVENT',
            user=user,
            action=event,
            details=details,
            severity=severity
        )

    def log_model_query(self, user: str, model: str, prompt_hash: str,
                       response_length: int, details: Dict = None) -> str:
        """
        Log a model query event.

        Args:
            user: User making the query
            model: Model being queried
            prompt_hash: Hash of the prompt (not the prompt itself)
            response_length: Length of response
            details: Additional details

        Returns:
            Event hash
        """
        return self.log(
            event_type='MODEL_QUERY',
            user=user,
            action=f'Queried {model}',
            details={
                'model': model,
                'prompt_hash': prompt_hash,
                'response_length': response_length,
                **(details or {})
            },
            severity='INFO'
        )

    def verify_log_integrity(self) -> Dict[str, Any]:
        """
        Verify the integrity of the audit log by checking hash chain.

        Returns:
            Dictionary with verification results
        """
        if not self.log_file.exists():
            return {'valid': True, 'message': 'No log file exists yet'}

        events = []
        with open(self.log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))

        if not events:
            return {'valid': True, 'message': 'Log file is empty'}

        # Verify hash chain
        previous_hash = None
        for i, event in enumerate(events):
            # Check if previous_hash matches
            if event.get('previous_hash') != previous_hash:
                return {
                    'valid': False,
                    'message': f'Hash chain broken at event {i}',
                    'event': event
                }

            # Verify event hash
            stored_hash = event.get('event_hash')
            event_copy = {k: v for k, v in event.items() if k != 'event_hash'}
            calculated_hash = self._calculate_hash(event_copy)

            if stored_hash != calculated_hash:
                return {
                    'valid': False,
                    'message': f'Event hash mismatch at event {i}',
                    'event': event
                }

            previous_hash = stored_hash

        return {
            'valid': True,
            'message': f'Log integrity verified. {len(events)} events checked.',
            'total_events': len(events)
        }

    def get_events(self, event_type: Optional[str] = None, user: Optional[str] = None,
                   severity: Optional[str] = None, limit: int = 100) -> list:
        """
        Retrieve audit events with optional filtering.

        Args:
            event_type: Filter by event type
            user: Filter by user
            severity: Filter by severity
            limit: Maximum number of events to return

        Returns:
            List of matching events
        """
        if not self.log_file.exists():
            return []

        events = []
        with open(self.log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    event = json.loads(line)

                    # Apply filters
                    if event_type and event.get('event_type') != event_type:
                        continue
                    if user and event.get('user') != user:
                        continue
                    if severity and event.get('severity') != severity:
                        continue

                    events.append(event)

                    if len(events) >= limit:
                        break

        return events

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about audit log.

        Returns:
            Dictionary with log statistics
        """
        if not self.log_file.exists():
            return {'total_events': 0}

        events = []
        with open(self.log_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))

        # Calculate statistics
        event_types = {}
        users = {}
        severities = {}

        for event in events:
            et = event.get('event_type', 'UNKNOWN')
            event_types[et] = event_types.get(et, 0) + 1

            u = event.get('user', 'UNKNOWN')
            users[u] = users.get(u, 0) + 1

            s = event.get('severity', 'INFO')
            severities[s] = severities.get(s, 0) + 1

        return {
            'total_events': len(events),
            'event_types': event_types,
            'users': users,
            'severities': severities,
            'first_event': events[0]['timestamp'] if events else None,
            'last_event': events[-1]['timestamp'] if events else None
        }

    def _calculate_hash(self, event: Dict) -> str:
        """
        Calculate SHA-256 hash of event.

        Args:
            event: Event dictionary

        Returns:
            Hex hash string
        """
        # Create deterministic string representation
        event_str = json.dumps(event, sort_keys=True)
        return hashlib.sha256(event_str.encode('utf-8')).hexdigest()

    def _get_last_hash(self) -> Optional[str]:
        """
        Get the hash of the last event in the log.

        Returns:
            Last event hash or None
        """
        if not self.log_file.exists():
            return None

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                if lines:
                    last_event = json.loads(lines[-1])
                    return last_event.get('event_hash')
        except Exception:
            pass

        return None


# Global audit logger instance
_audit_logger = None


def get_audit_logger(log_file: str = "data/audit.log") -> AuditLogger:
    """
    Get or create the global audit logger instance.

    Args:
        log_file: Path to audit log file

    Returns:
        AuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(log_file)
    return _audit_logger
