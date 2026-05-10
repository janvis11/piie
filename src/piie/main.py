"""
PIIE: Privacy Middleware for Agentic AI Systems

Main entry point for the PIIE application.
Initializes and runs the FastAPI server with privacy middleware.
"""

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    SLOWAPI_AVAILABLE = True
except ImportError:
    SLOWAPI_AVAILABLE = False

from .middleware.pii_middleware import PIIMiddleware
from .middleware.auth import AuthMiddleware, init_default_auth
from .config import (
    get_all_config,
    get_security_config,
    get_auth_config,
    get_audit_config,
    get_server_config,
)
from .security import (
    validate_content_type,
    validate_json_payload,
    ContentTypeError,
    JSONDepthError,
    generate_secure_token,
)

# Import routers
from .routes.sanitize import router as sanitize_router
from .routes.batch import router as batch_router
from .routes.policy import router as policy_router
from .routes.audit import router as audit_router
from .routes.auth import router as auth_router


# Configure logging
server_config = get_server_config()
logging.basicConfig(
    level=getattr(logging, server_config.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown events."""
    # Startup
    logger.info("Starting PIIE service...")

    config = get_all_config()
    security_config = get_security_config()
    auth_config = get_auth_config()

    # Validate security configuration in production
    if config["server"]["environment"] == "production":
        if not security_config.secret_key or len(security_config.secret_key) < 32:
            logger.warning(
                "SECURITY WARNING: SECRET_KEY is not set or too short in production. "
                "Set a strong SECRET_KEY (min 32 chars) in environment variables."
            )

    # Initialize default auth for development if enabled
    default_api_key = None
    if auth_config["dev_mode_auto_create_default_key"]:
        try:
            default_api_key = init_default_auth()
            logger.info("Default development tenant and API key created")
        except Exception as e:
            logger.warning(f"Could not create default tenant: {e}")

    if default_api_key:
        logger.info(f"Default API Key: {default_api_key[:8]}... (store securely)")

    yield

    # Shutdown
    logger.info("Shutting down PIIE service...")


app = FastAPI(
    title="PIIE",
    description="Privacy Layer for Agentic AI Systems - Detects, manages, and sanitizes PII",
    version="0.1.0",
    contact={
        "name": "Janvi Singh",
        "url": "https://github.com/janvis11"
    },
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Load configuration
config = get_all_config()
security_config = get_security_config()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=security_config.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate Limiter
if SLOWAPI_AVAILABLE and security_config.enable_rate_limit:
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[
            f"{security_config.rate_limit_max_requests}/{security_config.rate_limit_window_seconds}seconds"
        ]
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Initialize and attach auth middleware (must be before PII middleware)
app.add_middleware(AuthMiddleware)

# Initialize and attach PII middleware
app.add_middleware(PIIMiddleware, config=config)

# Include routers
app.include_router(sanitize_router)
app.include_router(batch_router)
app.include_router(policy_router)
app.include_router(audit_router)
app.include_router(auth_router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "piie",
        "version": "0.1.0",
        "environment": config["server"]["environment"]
    }


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "PIIE",
        "description": "Privacy Layer for Agentic AI Systems",
        "version": "0.1.0",
        "environment": config["server"]["environment"],
        "docs": "/docs",
        "endpoints": {
            "sanitize": "/sanitize",
            "batch": "/batch",
            "policy": "/policy",
            "audit": "/audit",
            "auth": "/auth",
            "health": "/health"
        },
        "security": {
            "rate_limiting": security_config.enable_rate_limit,
            "pii_redaction_in_logs": config["audit"]["pii_redaction"],
        }
    }


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)

    if security_config.enable_security_headers:
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Remove server identification headers
    if security_config.strip_server_headers:
        for header in ("Server", "X-Powered-By"):
            if header in response.headers:
                del response.headers[header]

    return response


@app.middleware("http")
async def request_size_middleware(request: Request, call_next):
    """Limit request body size to prevent DoS attacks."""
    max_size = security_config.max_request_size_kb * 1024  # Convert to bytes

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > max_size:
        return JSONResponse(
            status_code=status.HTTP_413_PAYLOAD_TOO_LARGE,
            content={
                "error": "Payload too large",
                "detail": f"Maximum request size is {security_config.max_request_size_kb}KB"
            }
        )

    return await call_next(request)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=server_config.host,
        port=server_config.port,
        workers=server_config.workers if server_config.environment == "production" else 1,
        log_level=server_config.log_level.lower()
    )
