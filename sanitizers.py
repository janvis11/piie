"""
PII Sanitization Module

Transforms detected PII according to policy actions.
Supports redaction, pseudonymization, and blocking.
"""

import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from detectors import PIIMatch, EntityType


class SanitizationAction(Enum):
    """Available sanitization actions."""
    ALLOW = "allow"           # Keep original
    REDACT = "redact"         # Replace with placeholder
    PSEUDONYMIZE = "pseudonymize"  # Replace with consistent token
    BLOCK = "block"           # Reject the entire input


@dataclass
class SanitizationResult:
    """Result of sanitizing a single PII entity."""
    original: str
    sanitized: str
    action: SanitizationAction
    entity_type: EntityType
    token: Optional[str] = None  # For pseudonymization


class PseudonymizationEngine:
    """
    Generates consistent tokens for PII values.

    Same input always produces same token, enabling:
    - Cross-request correlation (if needed)
    - Debugging while maintaining privacy
    """

    def __init__(self, salt: str = "pii-safe-default"):
        self.salt = salt
        self._cache: Dict[str, str] = {}

    def generate_token(self, value: str, entity_type: EntityType) -> str:
        """
        Generate a consistent token for a PII value.

        Args:
            value: The original PII value
            entity_type: Type of the entity

        Returns:
            A deterministic token like USER_01, EMAIL_02, etc.
        """
        # Check cache first
        cache_key = f"{value}:{entity_type.value}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Generate deterministic hash
        hash_input = f"{self.salt}:{value}:{entity_type.value}"
        hash_digest = hashlib.sha256(hash_input.encode()).hexdigest()

        # Create short token (first 8 chars of hash)
        token = f"{entity_type.value}_{hash_digest[:8].upper()}"

        # Cache for future use
        self._cache[cache_key] = token

        return token


class PIISanitizer:
    """
    Main sanitizer class that applies policies to detected PII.
    """

    # Redaction placeholders by entity type
    REDACTION_TEMPLATES = {
        EntityType.EMAIL: "[EMAIL_REDACTED]",
        EntityType.PHONE: "[PHONE_REDACTED]",
        EntityType.IP_ADDRESS: "[IP_REDACTED]",
        EntityType.SSN: "[SSN_REDACTED]",
        EntityType.CREDIT_CARD: "[CARD_REDACTED]",
        EntityType.NAME: "[NAME_REDACTED]",
        EntityType.CUSTOM: "[REDACTED]",
    }

    def __init__(self, pseudonym_engine: Optional[PseudonymizationEngine] = None):
        """
        Initialize the sanitizer.

        Args:
            pseudonym_engine: Optional custom engine for token generation
        """
        self.pseudonym_engine = pseudonym_engine or PseudonymizationEngine()

    def sanitize(
        self,
        text: str,
        matches: List[PIIMatch],
        policy_action: SanitizationAction
    ) -> SanitizationResult:
        """
        Apply sanitization to a single PII match.

        Args:
            text: Original text containing the PII
            matches: List of detected PII matches
            policy_action: Action to apply from the policy

        Returns:
            SanitizationResult with the transformed text
        """
        if not matches:
            return SanitizationResult(
                original=text,
                sanitized=text,
                action=SanitizationAction.ALLOW,
                entity_type=EntityType.CUSTOM
            )

        # Sort matches by position (reverse) to replace from end first
        sorted_matches = sorted(matches, key=lambda m: m.start_pos, reverse=True)

        result = text

        for match in sorted_matches:
            if policy_action == SanitizationAction.REDACT:
                replacement = self.REDACTION_TEMPLATES.get(
                    match.entity_type, "[REDACTED]"
                )
            elif policy_action == SanitizationAction.PSEUDONYMIZE:
                replacement = self.pseudonym_engine.generate_token(
                    match.value, match.entity_type
                )
            elif policy_action == SanitizationAction.ALLOW:
                replacement = match.value  # Keep original
            elif policy_action == SanitizationAction.BLOCK:
                # Block action is handled at a higher level
                replacement = "[BLOCKED]"
            else:
                replacement = "[UNKNOWN]"

            # Replace in result
            result = (
                result[:match.start_pos] +
                replacement +
                result[match.end_pos:]
            )

        return SanitizationResult(
            original=text,
            sanitized=result,
            action=policy_action,
            entity_type=matches[0].entity_type if matches else EntityType.CUSTOM
        )

    def should_block(self, matches: List[PIIMatch], block_types: List[EntityType]) -> bool:
        """
        Check if input should be blocked based on detected PII.

        Args:
            matches: List of detected PII matches
            block_types: Entity types that trigger blocking

        Returns:
            True if any match should cause blocking
        """
        for match in matches:
            if match.entity_type in block_types:
                return True
        return False

    def calculate_risk_score(self, matches: List[PIIMatch]) -> float:
        """
        Calculate a privacy risk score for the detected PII.

        Args:
            matches: List of detected PII matches

        Returns:
            Risk score from 0.0 (no risk) to 1.0 (high risk)
        """
        # Risk weights by entity type
        RISK_WEIGHTS = {
            EntityType.SSN: 1.0,
            EntityType.CREDIT_CARD: 1.0,
            EntityType.EMAIL: 0.5,
            EntityType.PHONE: 0.5,
            EntityType.IP_ADDRESS: 0.3,
            EntityType.NAME: 0.4,
            EntityType.CUSTOM: 0.2,
        }

        if not matches:
            return 0.0

        # Sum up risk weights
        total_risk = sum(
            RISK_WEIGHTS.get(m.entity_type, 0.2)
            for m in matches
        )

        # Normalize to 0-1 range (cap at 1.0)
        return min(total_risk, 1.0)
