"""Development server startup script."""

import sys
from pathlib import Path

# Ensure backend folder is in Python system path
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app import create_app
from app.config import DevelopmentConfig

app = create_app(DevelopmentConfig)

if __name__ == "__main__":
    host = app.config.get("HOST", "127.0.0.1")
    port = app.config.get("PORT", 5000)
    print(f"[*] Starting PhishGuard Backend Service on http://{host}:{port}")
    app.run(host=host, port=port, debug=True)
