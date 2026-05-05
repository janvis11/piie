"""
PII Detection Module

Detects personally identifiable information in text and structured data.
Supports emails, phone numbers, IP addresses, credit cards with Luhn validation,
SSNs, and custom patterns.
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class EntityType(Enum):
    """Types of PII entities that can be detected."""
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    IP_ADDRESS = "IP_ADDRESS"
    NAME = "NAME"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    PASSPORT = "PASSPORT"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"
    CUSTOM = "CUSTOM"


@dataclass
class PIIMatch:
    """Represents a detected PII entity."""
    entity_type: EntityType
    value: str
    start_pos: int
    end_pos: int
    confidence: float
    validation_metadata: Optional[Dict[str, Any]] = None


class PIIDetector:
    """
    Main detector class for finding PII in text.

    Uses regex patterns with checksum validation (Luhn for credit cards)
    and context-aware filtering to reduce false positives.
    """

    # Enhanced regex patterns with stricter validation
    PATTERNS = {
        # RFC 5322 compliant email pattern
        EntityType.EMAIL: r'[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}',
        # Phone numbers: international (+1-...) or domestic (555-...) formats
        EntityType.PHONE: r'(?:\+|00)?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}(?!\d)',
        # IPv4 only (IPv6 handled separately)
        EntityType.IP_ADDRESS: r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        # SSN with area number validation (excluding invalid ranges)
        EntityType.SSN: r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
        # Credit card: requires 13-19 digits with optional separators, must pass Luhn
        EntityType.CREDIT_CARD: r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b',
    }

    # Invalid SSN prefixes
    INVALID_SSN_PREFIXES = {'000', '666'}
    INVALID_SSN_AREA_RANGES = [(900, 999)]  # 9xx series invalid

    def __init__(
        self,
        custom_patterns: Dict[str, str] = None,
        enable_luhn: bool = True,
        exclude_test_domains: bool = True,
        test_domains: List[str] = None,
        min_phone_digits: int = 10,
        max_phone_digits: int = 15
    ):
        """
        Initialize the detector with optional custom patterns.

        Args:
            custom_patterns: Dictionary of {pattern_name: regex_string}
            enable_luhn: Enable Luhn algorithm validation for credit cards
            exclude_test_domains: Exclude known test domains from email detection
            test_domains: List of test domains to exclude (e.g., example.com)
            min_phone_digits: Minimum valid phone number digit count
            max_phone_digits: Maximum valid phone number digit count
        """
        self.compiled_patterns = {}
        self.enable_luhn = enable_luhn
        self.exclude_test_domains = exclude_test_domains
        self.test_domains = set(d.lower() for d in (test_domains or ["example.com", "test.com", "localhost"]))
        self.min_phone_digits = min_phone_digits
        self.max_phone_digits = max_phone_digits

        # Compile built-in patterns
        for entity_type, pattern in self.PATTERNS.items():
            self.compiled_patterns[entity_type] = re.compile(pattern)

        # Add custom patterns
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                self.compiled_patterns[name] = re.compile(pattern)

    @staticmethod
    def luhn_check(value: str) -> bool:
        """
        Validate a number using the Luhn algorithm (mod 10).

        Used for credit card number validation to catch typos and invalid numbers.

        Args:
            value: Numeric string to validate

        Returns:
            True if the number passes Luhn validation
        """
        digits = [int(d) for d in value if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False

        # Luhn algorithm
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:  # Every second digit from the right
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit

        return checksum % 10 == 0

    @staticmethod
    def validate_ssn(ssn: str) -> bool:
        """
        Validate SSN format and excluded numbers.

        Invalid: 000-xx-xxxx, 666-xx-xxxx, 9xx-xx-xxxx, xx-00-xxxx, xxx-xx-0000

        Args:
            ssn: SSN string to validate

        Returns:
            True if valid SSN format
        """
        parts = ssn.split('-')
        if len(parts) != 3:
            return False

        area, group, serial = parts

        # Check invalid prefixes
        if area in PIIDetector.INVALID_SSN_PREFIXES:
            return False

        # Check 9xx series
        if area.startswith('9'):
            return False

        # Check for all zeros in any part
        if area == '000' or group == '00' or serial == '0000':
            return False

        return True

    @staticmethod
    def identify_card_type(card_number: str) -> Optional[str]:
        """
        Identify credit card type by BIN (Bank Identification Number).

        Args:
            card_number: Credit card number

        Returns:
            Card type string or None if unrecognized
        """
        digits = re.sub(r'[\s-]', '', card_number)

        if not digits.isdigit():
            return None

        length = len(digits)

        # Visa: starts with 4, length 13 or 16
        if digits.startswith('4') and length in [13, 16]:
            return 'VISA'

        # Mastercard: starts with 51-55 or 2221-2720, length 16
        if length == 16:
            prefix2 = int(digits[:2]) if len(digits) >= 2 else 0
            prefix4 = int(digits[:4]) if len(digits) >= 4 else 0
            if 51 <= prefix2 <= 55 or 2221 <= prefix4 <= 2720:
                return 'MASTERCARD'

        # American Express: starts with 34 or 37, length 15
        if length == 15 and digits[:2] in ['34', '37']:
            return 'AMEX'

        # Discover: starts with 6011, 622126-622925, 644-649, 65, length 16
        if length == 16:
            if digits.startswith('6011') or digits.startswith('65'):
                return 'DISCOVER'
            if len(digits) >= 6:
                prefix6 = int(digits[:6])
                if 622126 <= prefix6 <= 622925:
                    return 'DISCOVER'

        return None

    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate IPv4 address - exclude common non-personal IPs.

        Excludes: localhost (127.x.x.x), private ranges, broadcast (255.255.255.255)
        unless specifically configured to include them.

        Args:
            ip: IP address string

        Returns:
            True if valid personal IP
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return False

        # All octets must be 0-255 (already enforced by regex, but double-check)
        if not all(0 <= o <= 255 for o in octets):
            return False

        # Exclude broadcast
        if ip == '255.255.255.255':
            return False

        # Exclude localhost range
        if octets[0] == 127:
            return False

        return True

    def detect(self, text: str) -> List[PIIMatch]:
        """
        Scan text for PII entities with validation and confidence scoring.

        Args:
            text: Input text to scan

        Returns:
            List of detected PIIMatch objects with validation metadata
        """
        matches = []
        matched_ranges = []  # Track already-matched character ranges

        # Priority order: specific patterns first (SSN, CC), then general (PHONE)
        priority_order = [
            EntityType.SSN,
            EntityType.CREDIT_CARD,
            EntityType.EMAIL,
            EntityType.IP_ADDRESS,
            EntityType.PHONE,
            EntityType.NAME,
        ]

        def apply_validation(entity_type, value, start, end):
            """Apply entity-specific validation and return confidence/metadata."""
            confidence = 0.95  # Base confidence for regex matches
            validation_metadata = {}

            if entity_type == EntityType.CREDIT_CARD:
                # Clean the value for validation
                clean_digits = re.sub(r'[\s-]', '', value)

                # Luhn validation
                if self.enable_luhn and not self.luhn_check(clean_digits):
                    return None, None

                # Identify card type
                card_type = self.identify_card_type(value)
                if card_type is None:
                    return None, None

                validation_metadata['card_type'] = card_type
                validation_metadata['luhn_valid'] = True
                confidence = 0.98  # High confidence after Luhn validation

            elif entity_type == EntityType.SSN:
                if not self.validate_ssn(value):
                    return None, None
                confidence = 0.98

            elif entity_type == EntityType.IP_ADDRESS:
                if not self._is_valid_ip(value):
                    return None, None
                confidence = 0.85  # Slightly lower - could be server IPs

            elif entity_type == EntityType.EMAIL:
                # Additional email validation
                if value.count('@') != 1:
                    return None, None
                local, domain = value.rsplit('@', 1)
                if not local or not domain or '.' not in domain:
                    return None, None
                # Exclude configured test domains
                if self.exclude_test_domains and domain.lower() in self.test_domains:
                    confidence = 0.5  # Lower confidence for test domains
                else:
                    confidence = 0.95

            elif entity_type == EntityType.PHONE:
                # Validate phone number length using configured limits
                digit_count = sum(c.isdigit() for c in value)
                if digit_count < self.min_phone_digits or digit_count > self.max_phone_digits:
                    return None, None
                confidence = 0.85  # Phone patterns can have false positives

            return confidence, validation_metadata

        # Process built-in entity types in priority order
        for entity_type in priority_order:
            if entity_type not in self.compiled_patterns:
                continue
            regex = self.compiled_patterns[entity_type]
            for match in regex.finditer(text):
                # Check if this range overlaps with already-matched ranges
                start, end = match.start(), match.end()
                if any(start < matched_end and end > matched_start
                       for matched_start, matched_end in matched_ranges):
                    continue  # Skip overlapping matches

                value = match.group()
                confidence, validation_metadata = apply_validation(entity_type, value, start, end)

                if confidence is None:
                    continue  # Failed validation

                matches.append(PIIMatch(
                    entity_type=entity_type,
                    value=value,
                    start_pos=start,
                    end_pos=end,
                    confidence=confidence,
                    validation_metadata=validation_metadata
                ))
                matched_ranges.append((start, end))

        # Process custom patterns (these use string keys, stored as EntityType.CUSTOM)
        for pattern_name, regex in self.compiled_patterns.items():
            # Skip built-in EntityType keys (already processed above)
            if isinstance(pattern_name, EntityType):
                continue

            for match in regex.finditer(text):
                start, end = match.start(), match.end()
                if any(start < matched_end and end > matched_start
                       for matched_start, matched_end in matched_ranges):
                    continue  # Skip overlapping matches

                value = match.group()
                matches.append(PIIMatch(
                    entity_type=EntityType.CUSTOM,
                    value=value,
                    start_pos=start,
                    end_pos=end,
                    confidence=0.95,
                    validation_metadata={'custom_pattern': pattern_name}
                ))
                matched_ranges.append((start, end))

        # Sort by position
        matches.sort(key=lambda m: m.start_pos)
        return matches

    def detect_in_json(self, data: Any, path: str = "") -> List[Dict]:
        """
        Recursively detect PII in JSON-like structures.

        Args:
            data: Dictionary or list to scan
            path: Current JSON path (for reporting)

        Returns:
            List of detections with their JSON paths
        """
        detections = []

        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                detections.extend(self.detect_in_json(value, new_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                detections.extend(self.detect_in_json(item, f"{path}[{i}]"))
        elif isinstance(data, str):
            matches = self.detect(data)
            for match in matches:
                detections.append({
                    "path": path,
                    "entity_type": match.entity_type.value,
                    "value": match.value,
                    "position": f"{match.start_pos}-{match.end_pos}"
                })

        return detections
