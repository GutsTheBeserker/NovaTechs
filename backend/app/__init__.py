"""Flask Application Factory for Adaptive Phishing Detection Backend."""

from __future__ import annotations

import re
from flask import Flask, request, Response
from app.config import get_config, Config
from app.routes.health import health_bp
from app.routes.analyze import analyze_bp
from app.security import InMemoryRateLimiter

ALLOWED_ORIGIN_PATTERNS = [
    re.compile(r"^chrome-extension://[a-z]{32}$"),
    re.compile(r"^http://127\.0\.0\.1(:\d+)?$"),
    re.compile(r"^http://localhost(:\d+)?$"),
]


def create_app(config_class: type[Config] | None = None) -> Flask:
    """Instantiate and configure the Flask application instance."""
    app = Flask(__name__)

    # Load configuration
    selected_config = config_class or get_config()
    app.config.from_object(selected_config)

    # Attach in-memory sliding window rate limiter
    app.rate_limiter = InMemoryRateLimiter(max_requests=60, window_seconds=60)

    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(analyze_bp)

    @app.before_request
    def handle_cors_preflight():
        """Handle CORS OPTIONS preflight requests cleanly."""
        if request.method == "OPTIONS":
            origin = request.headers.get("Origin", "")
            is_allowed = any(p.match(origin) for p in ALLOWED_ORIGIN_PATTERNS) or app.config.get("CORS_ALLOWED_ORIGINS") == "*"
            resp = Response(status=204)
            if is_allowed:
                resp.headers["Access-Control-Allow-Origin"] = origin or "*"
                resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
                resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                resp.headers["Access-Control-Max-Age"] = "86400"
            return resp

    @app.after_request
    def set_security_and_cors_headers(response):
        """Inject strict defensive and CORS headers on all outgoing responses."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"

        # Restrict CORS to authorized extension or local development origins
        origin = request.headers.get("Origin", "")
        if origin and any(p.match(origin) for p in ALLOWED_ORIGIN_PATTERNS):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        elif app.config.get("CORS_ALLOWED_ORIGINS") == "*":
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"

        return response

    return app
