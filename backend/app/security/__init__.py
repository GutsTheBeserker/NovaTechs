"""Security, privacy validation, and rate limiting module.

Enforces zero-PII ingress safeguards, disallowing raw query strings with secrets,
passwords, or authorization tokens from ever entering backend memory.
"""

from __future__ import annotations

import math
import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Tuple


class PrivacyValidator:
    """Enforces zero-PII ingress safeguards on incoming feature and URL payloads."""

    DISALLOWED_KEYS = {
        "password",
        "pass",
        "pwd",
        "token",
        "auth",
        "cookie",
        "session",
        "secret",
        "user",
        "username",
        "email",
        "bearer",
        "apikey",
        "api_key",
        "access_token",
        "refresh_token",
    }

    DISALLOWED_SCHEMES = {"javascript:", "data:", "file:", "vbscript:", "blob:"}

    @classmethod
    def sanitize_and_validate(cls, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """Verify that payload does not contain unauthorized PII keys or dangerous schemes.

        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not isinstance(payload, dict):
            return False, "Payload must be a JSON object"

        # Check for forbidden sensitive keys at top level and nested
        def check_keys(d: Dict[str, Any]) -> Tuple[bool, str]:
            for key, val in d.items():
                normalized = str(key).strip().lower()
                if normalized in cls.DISALLOWED_KEYS:
                    return False, f"Privacy violation: sensitive key '{key}' is disallowed"
                if isinstance(val, dict):
                    valid, err = check_keys(val)
                    if not valid:
                        return False, err
            return True, ""

        valid, err = check_keys(payload)
        if not valid:
            return False, err

        # If a URL is submitted, ensure it's not a dangerous scheme
        if "url" in payload:
            url_str = str(payload["url"]).strip().lower()
            if len(url_str) > 2048:
                return False, "Validation error: URL length exceeds maximum permitted limit (2048 characters)"
            for scheme in cls.DISALLOWED_SCHEMES:
                if url_str.startswith(scheme):
                    return False, f"Validation error: disallowed URL scheme '{scheme}'"

        # If features dict is present, validate numeric constraints
        if "features" in payload:
            feats = payload["features"]
            if not isinstance(feats, dict):
                return False, "Validation error: 'features' must be an object"
            for f_name, f_val in feats.items():
                if not isinstance(f_val, (int, float)) or isinstance(f_val, bool):
                    return False, f"Validation error: feature '{f_name}' must be a numerical value"
                if math.isnan(f_val) or math.isinf(f_val):
                    return False, f"Validation error: feature '{f_name}' has invalid NaN or Infinity value"
                if f_val < 0.0:
                    return False, f"Validation error: feature '{f_name}' cannot be negative ({f_val})"

        return True, "Payload passed privacy validation"


class InMemoryRateLimiter:
    """Sliding window in-memory rate limiter per client identifier (IP address)."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> Tuple[bool, int]:
        """Check if client is permitted to make a request.

        Returns:
            Tuple[bool, int]: (is_allowed, retry_after_seconds)
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Prune outdated timestamps
        timestamps = [ts for ts in self._requests[client_id] if ts > window_start]
        self._requests[client_id] = timestamps

        if len(timestamps) >= self.max_requests:
            oldest = timestamps[0]
            retry_after = max(1, int(oldest + self.window_seconds - now))
            return False, retry_after

        # Record this request
        timestamps.append(now)
        return True, 0

    def reset(self) -> None:
        """Clear all rate limit buckets (useful for tests)."""
        self._requests.clear()
