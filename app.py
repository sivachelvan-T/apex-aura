"""Apex Aura — Loan Appeal DTI Recalculator."""

import os
import secrets

from flask import Flask, redirect, session, url_for

from config import Config
import db as db_module
from routes.auth import bp as auth_bp
from routes.appeals import bp as appeals_bp
from routes.admin import bp as admin_bp


def create_app():
    app = Flask(__name__)

    # SECRET_KEY should be set in Render. A random fallback keeps local setup
    # simple, but sessions will not survive a process restart without it.
    app.secret_key = Config.SECRET_KEY or secrets.token_hex(32)

    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_UPLOAD_BYTES
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = (
        os.environ.get("SESSION_COOKIE_SECURE", "1").lower()
        in {"1", "true", "yes"}
    )

    os.makedirs(Config.UPLOAD_DIR, exist_ok=True)

    app.teardown_appcontext(db_module.close_db)

    app.register_blueprint(auth_bp)
    app.register_blueprint(appeals_bp)
    app.register_blueprint(admin_bp)

    @app.route("/")
    def index():
        if session.get("officer_id"):
            return redirect(url_for("appeals.dashboard"))
        return redirect(url_for("auth.login"))

    @app.errorhandler(400)
    def bad_request(error):
        return (
            f"<h3>400 — {error.description}</h3>"
            "<p><a href='/'>Back</a></p>",
            400,
        )

    @app.errorhandler(403)
    def forbidden(error):
        return (
            f"<h3>403 — {error.description}</h3>"
            "<p><a href='/'>Back</a></p>",
            403,
        )

    @app.errorhandler(404)
    def not_found(error):
        return (
            "<h3>404 — Page not found</h3><p><a href='/'>Back</a></p>",
            404,
        )

    # Required for gunicorn app:app.
    db_module.init_db()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
