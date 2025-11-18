"""
Rate Limiter for preventing API abuse.
"""

import time
import threading
from collections import deque
from typing import Dict, Optional


class RateLimiter:
    """Token bucket rate limiter with sliding window."""

    def __init__(self, max_requests: int = 60, time_window: int = 60):
        """
        Initialize rate limiter.

        Args:
            max_requests: Maximum number of requests allowed in time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = threading.Lock()

    def allow_request(self, identifier: str = "default") -> bool:
        """
        Check if a request is allowed.

        Args:
            identifier: Unique identifier for the requester

        Returns:
            True if request is allowed, False otherwise
        """
        current_time = time.time()

        with self.lock:
            # Remove old requests outside the time window
            while self.requests and self.requests[0] <= current_time - self.time_window:
                self.requests.popleft()

            # Check if we're within the limit
            if len(self.requests) < self.max_requests:
                self.requests.append(current_time)
                return True

            return False

    def wait_if_needed(self, identifier: str = "default", max_wait: float = 10.0) -> bool:
        """
        Wait until a request is allowed or max_wait is exceeded.

        Args:
            identifier: Unique identifier for the requester
            max_wait: Maximum time to wait in seconds

        Returns:
            True if request was allowed, False if max_wait exceeded
        """
        start_time = time.time()

        while time.time() - start_time < max_wait:
            if self.allow_request(identifier):
                return True
            time.sleep(0.1)  # Small sleep to avoid busy waiting

        return False

    def get_remaining_requests(self) -> int:
        """
        Get the number of remaining requests in current window.

        Returns:
            Number of remaining requests
        """
        current_time = time.time()

        with self.lock:
            # Remove old requests
            while self.requests and self.requests[0] <= current_time - self.time_window:
                self.requests.popleft()

            return max(0, self.max_requests - len(self.requests))

    def get_reset_time(self) -> float:
        """
        Get the time until the rate limit resets.

        Returns:
            Time in seconds until reset
        """
        current_time = time.time()

        with self.lock:
            if not self.requests:
                return 0.0

            oldest_request = self.requests[0]
            reset_time = oldest_request + self.time_window - current_time
            return max(0.0, reset_time)

    def reset(self):
        """Reset the rate limiter."""
        with self.lock:
            self.requests.clear()


class MultiRateLimiter:
    """Rate limiter supporting multiple identifiers (users, API keys, etc.)."""

    def __init__(self, max_requests: int = 60, time_window: int = 60,
                 global_max: Optional[int] = None):
        """
        Initialize multi-rate limiter.

        Args:
            max_requests: Max requests per identifier
            time_window: Time window in seconds
            global_max: Optional global max across all identifiers
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.global_max = global_max
        self.limiters: Dict[str, RateLimiter] = {}
        self.global_limiter = RateLimiter(global_max, time_window) if global_max else None
        self.lock = threading.Lock()

    def allow_request(self, identifier: str) -> bool:
        """
        Check if a request is allowed for the given identifier.

        Args:
            identifier: Unique identifier for the requester

        Returns:
            True if request is allowed, False otherwise
        """
        # Check global limit first
        if self.global_limiter and not self.global_limiter.allow_request():
            return False

        # Get or create limiter for this identifier
        with self.lock:
            if identifier not in self.limiters:
                self.limiters[identifier] = RateLimiter(self.max_requests, self.time_window)

        limiter = self.limiters[identifier]
        return limiter.allow_request(identifier)

    def wait_if_needed(self, identifier: str, max_wait: float = 10.0) -> bool:
        """
        Wait until a request is allowed or max_wait is exceeded.

        Args:
            identifier: Unique identifier for the requester
            max_wait: Maximum time to wait in seconds

        Returns:
            True if request was allowed, False if max_wait exceeded
        """
        start_time = time.time()

        while time.time() - start_time < max_wait:
            if self.allow_request(identifier):
                return True
            time.sleep(0.1)

        return False

    def get_stats(self, identifier: str) -> Dict[str, any]:
        """
        Get rate limiter statistics for an identifier.

        Args:
            identifier: Identifier to get stats for

        Returns:
            Dictionary with statistics
        """
        with self.lock:
            if identifier not in self.limiters:
                return {
                    'remaining_requests': self.max_requests,
                    'reset_time': 0.0,
                    'max_requests': self.max_requests,
                    'time_window': self.time_window
                }

        limiter = self.limiters[identifier]
        return {
            'remaining_requests': limiter.get_remaining_requests(),
            'reset_time': limiter.get_reset_time(),
            'max_requests': self.max_requests,
            'time_window': self.time_window
        }

    def reset_identifier(self, identifier: str):
        """
        Reset rate limiter for a specific identifier.

        Args:
            identifier: Identifier to reset
        """
        with self.lock:
            if identifier in self.limiters:
                self.limiters[identifier].reset()

    def reset_all(self):
        """Reset all rate limiters."""
        with self.lock:
            for limiter in self.limiters.values():
                limiter.reset()
            if self.global_limiter:
                self.global_limiter.reset()


# Global rate limiter instances
_model_rate_limiter = None
_api_rate_limiter = None


def get_model_rate_limiter(max_requests: int = 60, time_window: int = 60) -> MultiRateLimiter:
    """
    Get or create the global model rate limiter.

    Args:
        max_requests: Max requests per model
        time_window: Time window in seconds

    Returns:
        MultiRateLimiter instance
    """
    global _model_rate_limiter
    if _model_rate_limiter is None:
        _model_rate_limiter = MultiRateLimiter(max_requests, time_window, global_max=100)
    return _model_rate_limiter


def get_api_rate_limiter(max_requests: int = 100, time_window: int = 60) -> MultiRateLimiter:
    """
    Get or create the global API rate limiter.

    Args:
        max_requests: Max requests per API key
        time_window: Time window in seconds

    Returns:
        MultiRateLimiter instance
    """
    global _api_rate_limiter
    if _api_rate_limiter is None:
        _api_rate_limiter = MultiRateLimiter(max_requests, time_window)
    return _api_rate_limiter
