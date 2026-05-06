"""
Configuration loader for PII-Safe.

Loads and validates privacy policies from YAML configuration files
and environment variables.
"""

import os
import yaml
import secrets
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class SecurityConfig:
    """Security-related configuration."""
    secret_key: str = ""
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst: int = 10
    max_request_size_kb: int = 1024
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    enable_rate_limit: bool = True
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 100
    # Additional security settings
    enable_security_headers: bool = True
    enable_request_size_limit: bool = True
    strip_server_headers: bool = True
    secure_cookies: bool = True
    session_timeout_seconds: int = 3600
    max_json_depth: int = 10  # Prevent deeply nested JSON attacks
    allowed_content_types: List[str] = field(default_factory=lambda: ["application/json", "text/plain"])


@dataclass
class AuthConfig:
    """Authentication configuration."""
    default_tenant_id: str = "default"
    default_tenant_name: str = "Default Tenant"
    default_api_key_scopes: List[str] = field(default_factory=lambda: ["admin"])
    dev_mode_auto_create_default_key: bool = True


@dataclass
class AuditConfig:
    """Audit logging configuration."""
    audit_log_enabled: bool = True
    audit_log_retention_days: int = 90
    audit_log_pii_redaction: bool = True


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    environment: str = "development"
    log_level: str = "INFO"


@dataclass
class PseudonymizationConfig:
    """Pseudonymization configuration."""
    salt: str = ""  # Must be set in production


@dataclass
class DetectorConfig:
    """PII Detector configuration."""
    enable_luhn_validation: bool = True
    exclude_test_domains: bool = True
    test_domains: List[str] = field(default_factory=lambda: ["example.com", "test.com", "localhost"])
    enable_ssn_validation: bool = True
    enable_card_type_identification: bool = True
    min_phone_digits: int = 10
    max_phone_digits: int = 15


@dataclass
class SanitizerConfig:
    """PII Sanitizer configuration."""
    default_redaction_prefix: str = ""  # Empty means use entity type default
    pseudonym_token_length: int = 8  # Length of hash in tokens


@dataclass
class MiddlewareConfig:
    """Middleware behavior configuration."""
    exclude_paths: List[str] = field(default_factory=lambda: [
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/sanitize",
        "/batch",
        "/policy",
        "/audit",
        "/auth",
    ])
    enable_request_logging: bool = True
    enable_response_headers: bool = True
    max_audit_log_size: int = 10000  # Max entries before rotation


@dataclass
class RiskScoringConfig:
    """Risk scoring configuration."""
    # Weights by entity type (higher = more sensitive)
    ssn_weight: float = 1.0
    credit_card_weight: float = 1.0
    email_weight: float = 0.5
    phone_weight: float = 0.5
    ip_address_weight: float = 0.3
    name_weight: float = 0.4
    custom_weight: float = 0.2
    risk_score_threshold_block: float = 0.9  # Auto-block if risk exceeds this


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load privacy policy configuration from YAML file.

    Args:
        config_path: Path to the YAML configuration file

    Returns:
        Dictionary containing policy rules and settings

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config format is invalid
    """
    path = Path(config_path)

    if not path.exists():
        return create_default_config()

    with open(path, 'r') as f:
        config = yaml.safe_load(f)

    validate_config(config)
    return config


def create_default_config() -> Dict[str, Any]:
    """Create a default configuration with safe defaults."""
    return {
        "policies": [
            {
                "name": "redact_emails",
                "entity_types": ["EMAIL"],
                "action": "redact"
            },
            {
                "name": "redact_phones",
                "entity_types": ["PHONE"],
                "action": "redact"
            },
            {
                "name": "redact_ips",
                "entity_types": ["IP_ADDRESS"],
                "action": "redact"
            }
        ],
        "audit_logging": True,
        "risk_scoring": True
    }


def validate_config(config: Dict[str, Any]) -> None:
    """Validate the configuration structure."""
    if "policies" not in config:
        raise ValueError("Configuration must contain 'policies' key")

    valid_actions = {"allow", "redact", "pseudonymize", "block"}

    for policy in config["policies"]:
        if "name" not in policy:
            raise ValueError("Each policy must have a 'name'")
        if "entity_types" not in policy:
            raise ValueError("Each policy must have 'entity_types'")
        if "action" not in policy:
            raise ValueError("Each policy must have 'action'")
        if policy["action"].lower() not in valid_actions:
            raise ValueError(f"Invalid action: {policy['action']}")


def get_security_config() -> SecurityConfig:
    """Load security configuration from environment variables."""
    cors_raw = os.getenv("CORS_ORIGINS", '["*"]')
    try:
        cors_origins = yaml.safe_load(cors_raw) if isinstance(cors_raw, str) else cors_raw
    except (yaml.YAMLError, TypeError):
        cors_origins = ["*"]

    scopes_raw = os.getenv("DEFAULT_API_KEY_SCOPES", "admin")
    try:
        default_scopes = yaml.safe_load(scopes_raw) if isinstance(scopes_raw, str) else scopes_raw
        if isinstance(default_scopes, str):
            default_scopes = [s.strip() for s in default_scopes.split(",")]
    except (yaml.YAMLError, TypeError):
        default_scopes = ["admin"]

    allowed_content_types_raw = os.getenv("SECURITY_ALLOWED_CONTENT_TYPES", "application/json,text/plain")
    allowed_content_types = [ct.strip() for ct in allowed_content_types_raw.split(",")] if allowed_content_types_raw else []

    return SecurityConfig(
        secret_key=os.getenv("SECRET_KEY", ""),
        rate_limit_requests_per_minute=int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60")),
        rate_limit_burst=int(os.getenv("RATE_LIMIT_BURST", "10")),
        max_request_size_kb=int(os.getenv("MAX_REQUEST_SIZE_KB", "1024")),
        cors_origins=cors_origins,
        enable_rate_limit=os.getenv("ENABLE_RATE_LIMIT", "true").lower() == "true",
        rate_limit_window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
        rate_limit_max_requests=int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100")),
        enable_security_headers=os.getenv("SECURITY_ENABLE_HEADERS", "true").lower() == "true",
        enable_request_size_limit=os.getenv("SECURITY_ENABLE_SIZE_LIMIT", "true").lower() == "true",
        strip_server_headers=os.getenv("SECURITY_STRIP_SERVER_HEADERS", "true").lower() == "true",
        secure_cookies=os.getenv("SECURITY_SECURE_COOKIES", "true").lower() == "true",
        session_timeout_seconds=int(os.getenv("SECURITY_SESSION_TIMEOUT", "3600")),
        max_json_depth=int(os.getenv("SECURITY_MAX_JSON_DEPTH", "10")),
        allowed_content_types=allowed_content_types
    )


def get_auth_config() -> AuthConfig:
    """Load authentication configuration from environment variables."""
    scopes_raw = os.getenv("DEFAULT_API_KEY_SCOPES", "admin")
    try:
        default_scopes = yaml.safe_load(scopes_raw) if isinstance(scopes_raw, str) else scopes_raw
        if isinstance(default_scopes, str):
            default_scopes = [s.strip() for s in default_scopes.split(",")]
    except (yaml.YAMLError, TypeError):
        default_scopes = ["admin"]

    return AuthConfig(
        default_tenant_id=os.getenv("DEFAULT_TENANT_ID", "default"),
        default_tenant_name=os.getenv("DEFAULT_TENANT_NAME", "Default Tenant"),
        default_api_key_scopes=default_scopes,
        dev_mode_auto_create_default_key=os.getenv("DEV_MODE_AUTO_CREATE_DEFAULT_KEY", "true").lower() == "true"
    )


def get_audit_config() -> AuditConfig:
    """Load audit configuration from environment variables."""
    return AuditConfig(
        audit_log_enabled=os.getenv("AUDIT_LOG_ENABLED", "true").lower() == "true",
        audit_log_retention_days=int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90")),
        audit_log_pii_redaction=os.getenv("AUDIT_LOG_PII_REDACTION", "true").lower() == "true"
    )


def get_server_config() -> ServerConfig:
    """Load server configuration from environment variables."""
    return ServerConfig(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        workers=int(os.getenv("WORKERS", "4")),
        environment=os.getenv("PII_SAFE_ENV", "development"),
        log_level=os.getenv("LOG_LEVEL", "INFO")
    )


def get_pseudonymization_config() -> PseudonymizationConfig:
    """Load pseudonymization configuration from environment variables."""
    salt = os.getenv("PSEUDONYMIZATION_SALT")
    if not salt:
        # Generate a random salt for development if not set
        if os.getenv("PII_SAFE_ENV", "development") == "development":
            salt = secrets.token_hex(16)
        else:
            raise ValueError(
                "PSEUDONYMIZATION_SALT must be set in production. "
                "Use a secure random value (min 32 chars)."
            )
    return PseudonymizationConfig(salt=salt)


def get_detector_config() -> DetectorConfig:
    """Load detector configuration from environment variables."""
    test_domains_raw = os.getenv("DETECTOR_TEST_DOMAINS", "example.com,test.com,localhost")
    test_domains = [d.strip() for d in test_domains_raw.split(",")] if test_domains_raw else []

    return DetectorConfig(
        enable_luhn_validation=os.getenv("DETECTOR_ENABLE_LUHN", "true").lower() == "true",
        exclude_test_domains=os.getenv("DETECTOR_EXCLUDE_TEST_DOMAINS", "true").lower() == "true",
        test_domains=test_domains,
        enable_ssn_validation=os.getenv("DETECTOR_ENABLE_SSN_VALIDATION", "true").lower() == "true",
        enable_card_type_identification=os.getenv("DETECTOR_ENABLE_CARD_TYPE", "true").lower() == "true",
        min_phone_digits=int(os.getenv("DETECTOR_MIN_PHONE_DIGITS", "10")),
        max_phone_digits=int(os.getenv("DETECTOR_MAX_PHONE_DIGITS", "15"))
    )


def get_sanitizer_config() -> SanitizerConfig:
    """Load sanitizer configuration from environment variables."""
    return SanitizerConfig(
        default_redaction_prefix=os.getenv("SANITIZER_REDACTION_PREFIX", ""),
        pseudonym_token_length=int(os.getenv("SANITIZER_TOKEN_LENGTH", "8"))
    )


def get_middleware_config() -> MiddlewareConfig:
    """Load middleware configuration from environment variables."""
    exclude_paths_raw = os.getenv(
        "MIDDLEWARE_EXCLUDE_PATHS",
        "/,/health,/docs,/redoc,/openapi.json,/sanitize,/batch,/policy,/audit,/auth",
    )
    exclude_paths = [p.strip() for p in exclude_paths_raw.split(",")] if exclude_paths_raw else []

    return MiddlewareConfig(
        exclude_paths=exclude_paths,
        enable_request_logging=os.getenv("MIDDLEWARE_ENABLE_LOGGING", "true").lower() == "true",
        enable_response_headers=os.getenv("MIDDLEWARE_ENABLE_HEADERS", "true").lower() == "true",
        max_audit_log_size=int(os.getenv("MIDDLEWARE_MAX_AUDIT_SIZE", "10000"))
    )


def get_risk_scoring_config() -> RiskScoringConfig:
    """Load risk scoring configuration from environment variables."""
    return RiskScoringConfig(
        ssn_weight=float(os.getenv("RISK_SSN_WEIGHT", "1.0")),
        credit_card_weight=float(os.getenv("RISK_CC_WEIGHT", "1.0")),
        email_weight=float(os.getenv("RISK_EMAIL_WEIGHT", "0.5")),
        phone_weight=float(os.getenv("RISK_PHONE_WEIGHT", "0.5")),
        ip_address_weight=float(os.getenv("RISK_IP_WEIGHT", "0.3")),
        name_weight=float(os.getenv("RISK_NAME_WEIGHT", "0.4")),
        custom_weight=float(os.getenv("RISK_CUSTOM_WEIGHT", "0.2")),
        risk_score_threshold_block=float(os.getenv("RISK_BLOCK_THRESHOLD", "0.9"))
    )


def get_all_config() -> Dict[str, Any]:
    """
    Get all configuration from environment and YAML files.

    Returns:
        Complete configuration dictionary
    """
    security = get_security_config()
    auth = get_auth_config()
    audit = get_audit_config()
    server = get_server_config()
    pseudo = get_pseudonymization_config()
    detector = get_detector_config()
    sanitizer = get_sanitizer_config()
    middleware = get_middleware_config()
    risk = get_risk_scoring_config()

    return {
        "security": {
            "secret_key": security.secret_key,
            "rate_limit_requests_per_minute": security.rate_limit_requests_per_minute,
            "rate_limit_burst": security.rate_limit_burst,
            "max_request_size_kb": security.max_request_size_kb,
            "cors_origins": security.cors_origins,
            "enable_rate_limit": security.enable_rate_limit,
            "rate_limit_window_seconds": security.rate_limit_window_seconds,
            "rate_limit_max_requests": security.rate_limit_max_requests,
        },
        "auth": {
            "default_tenant_id": auth.default_tenant_id,
            "default_tenant_name": auth.default_tenant_name,
            "default_api_key_scopes": auth.default_api_key_scopes,
            "dev_mode_auto_create_default_key": auth.dev_mode_auto_create_default_key,
        },
        "audit": {
            "enabled": audit.audit_log_enabled,
            "retention_days": audit.audit_log_retention_days,
            "pii_redaction": audit.audit_log_pii_redaction,
        },
        "server": {
            "host": server.host,
            "port": server.port,
            "workers": server.workers,
            "environment": server.environment,
            "log_level": server.log_level,
        },
        "pseudonymization": {
            "salt": pseudo.salt,
        },
        "detector": {
            "enable_luhn_validation": detector.enable_luhn_validation,
            "exclude_test_domains": detector.exclude_test_domains,
            "test_domains": detector.test_domains,
            "enable_ssn_validation": detector.enable_ssn_validation,
            "enable_card_type_identification": detector.enable_card_type_identification,
            "min_phone_digits": detector.min_phone_digits,
            "max_phone_digits": detector.max_phone_digits,
        },
        "sanitizer": {
            "default_redaction_prefix": sanitizer.default_redaction_prefix,
            "pseudonym_token_length": sanitizer.pseudonym_token_length,
        },
        "middleware": {
            "exclude_paths": middleware.exclude_paths,
            "enable_request_logging": middleware.enable_request_logging,
            "enable_response_headers": middleware.enable_response_headers,
            "max_audit_log_size": middleware.max_audit_log_size,
        },
        "risk_scoring": {
            "ssn_weight": risk.ssn_weight,
            "credit_card_weight": risk.credit_card_weight,
            "email_weight": risk.email_weight,
            "phone_weight": risk.phone_weight,
            "ip_address_weight": risk.ip_address_weight,
            "name_weight": risk.name_weight,
            "custom_weight": risk.custom_weight,
            "block_threshold": risk.risk_score_threshold_block,
        },
        "policies": load_config("config/policy.yaml").get("policies", []),
    }
