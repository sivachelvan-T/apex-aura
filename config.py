"""Central application configuration."""

import os


class Config:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    DB_PATH = os.environ.get(
        "DB_PATH",
        os.path.join(BASE_DIR, "apex_aura.db"),
    )
    UPLOAD_DIR = os.environ.get(
        "UPLOAD_DIR",
        os.path.join(BASE_DIR, "uploads"),
    )
    KEY_PATH = os.path.join(BASE_DIR, "secret.key")

    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
    MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    DTI_THRESHOLD = 0.43

    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Set these in Render. Defaults are only for local/demo setup.
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin").strip()
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123!")
