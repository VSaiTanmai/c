"""
Inter-Agent Message Integrity — HMAC-SHA256 signing and verification.

Provides tamper-proof Kafka message integrity between CLIF pipeline stages
(Triage → Hunter → Verifier). Each agent signs outgoing messages with a
shared secret key and verifies incoming signatures.

The HMAC is computed over the message value bytes and attached as a
Kafka header named 'x-clif-hmac'. Receiving agents verify the header
before processing the message. Invalid/missing signatures are logged
and the message is sent to the dead-letter topic.

Security: The shared key MUST be injected via the CLIF_HMAC_KEY
environment variable. Never hardcode production keys.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

# Header name used in Kafka message headers
HMAC_HEADER = "x-clif-hmac"

# Shared secret — injected via environment variable
_HMAC_KEY: Optional[bytes] = None


def _get_key() -> bytes:
    """Load and cache the HMAC key from the environment."""
    global _HMAC_KEY
    if _HMAC_KEY is not None:
        return _HMAC_KEY

    key_str = os.environ.get("CLIF_HMAC_KEY", "")
    if not key_str:
        log.warning(
            "CLIF_HMAC_KEY not set — using default key. "
            "Set CLIF_HMAC_KEY in production for inter-agent integrity."
        )
        # Default key for development only — NOT for production
        key_str = "clif-dev-hmac-key-change-in-production"

    _HMAC_KEY = key_str.encode("utf-8")
    return _HMAC_KEY


def sign(message_bytes: bytes) -> str:
    """
    Compute HMAC-SHA256 signature for a message.

    Args:
        message_bytes: Raw Kafka message value (bytes).

    Returns:
        Hex-encoded HMAC-SHA256 signature string.
    """
    key = _get_key()
    return hmac.new(key, message_bytes, hashlib.sha256).hexdigest()


def verify(message_bytes: bytes, signature: str) -> bool:
    """
    Verify an HMAC-SHA256 signature for a message.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        message_bytes: Raw Kafka message value (bytes).
        signature: Hex-encoded HMAC-SHA256 signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    key = _get_key()
    expected = hmac.new(key, message_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def make_headers(message_bytes: bytes) -> list:
    """
    Create Kafka headers list with HMAC signature.

    Returns list of (header_name, header_value_bytes) tuples
    compatible with both confluent-kafka and aiokafka.
    """
    sig = sign(message_bytes)
    return [(HMAC_HEADER, sig.encode("utf-8"))]


def extract_and_verify(
    message_value: bytes,
    headers: Optional[list],
) -> bool:
    """
    Extract HMAC header from Kafka message headers and verify.

    Args:
        message_value: Raw Kafka message value (bytes).
        headers: Kafka message headers list (may be None).

    Returns:
        True if signature is present and valid, False otherwise.
    """
    if not headers:
        log.warning("No headers on message — HMAC verification failed")
        return False

    for name, value in headers:
        header_name = name if isinstance(name, str) else name.decode("utf-8")
        if header_name == HMAC_HEADER:
            sig = value if isinstance(value, str) else value.decode("utf-8")
            return verify(message_value, sig)

    log.warning("HMAC header '%s' not found in message headers", HMAC_HEADER)
    return False
