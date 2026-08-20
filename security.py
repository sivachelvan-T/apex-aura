"""Security controls: encryption, authentication, CSRF, and uploads."""

import os
import secrets
import uuid
from functools import wraps

from flask import abort, flash, redirect, request, session, url_for
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename

from config import Config


# ---------------------------------------------------------------------------
# Encryption at rest
# ---------------------------------------------------------------------------

def _load_or_create_key():
    env_key = os.environ.get("FERNET_KEY")
    if env_key:
        try:
            key = env_key.encode("utf-8")
            Fernet(key)
            return key
        except Exception as exc:
            raise RuntimeError(
                "FERNET_KEY is invalid. Generate a valid Fernet key and "
                "set it in the Render Environment Variables."
            ) from exc

    if os.path.exists(Config.KEY_PATH):
        with open(Config.KEY_PATH, "rb") as file:
            key = file.read()
            Fernet(key)
            return key

    key = Fernet.generate_key()
    parent = os.path.dirname(Config.KEY_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(Config.KEY_PATH, "wb") as file:
        file.write(key)
    try:
        os.chmod(Config.KEY_PATH, 0o600)
    except OSError:
        pass
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt_value(value):
    return _fernet.encrypt(str(value).encode("utf-8")).decode("utf-8")


def decrypt_value(token):
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError):
        return "‹unreadable›"


# ---------------------------------------------------------------------------
# Authentication and authorization
# ---------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        import models

        user_id = session.get("officer_id")
        if not user_id:
            return redirect(url_for("auth.login", next=request.path))

        row = models.get_officer(user_id)
        if row is None or not row["active"]:
            session.clear()
            flash("Your account is inactive. Contact the administrator.", "error")
            return redirect(url_for("auth.login"))

        session["officer_name"] = row["username"]
        session["role"] = row["role"]
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403, description="Administrator privileges are required.")
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        abort(400, description="Invalid or missing CSRF token.")


# ---------------------------------------------------------------------------
# Upload validation
# ---------------------------------------------------------------------------

def allowed_extension(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in Config.ALLOWED_EXTENSIONS
    )


def content_matches_extension(file_bytes, extension):
    extension = extension.lower()

    if extension == "pdf":
        return file_bytes.startswith(b"%PDF-")

    if extension in {"jpg", "jpeg"}:
        return file_bytes.startswith(b"\xff\xd8\xff")

    if extension == "png":
        return file_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    return False


def save_pay_stub(file_storage):
    if not file_storage or not file_storage.filename:
        raise ValueError("No pay stub was selected.")

    filename = secure_filename(file_storage.filename)
    if not filename or not allowed_extension(filename):
        raise ValueError("Only PNG, JPG, JPEG, and PDF pay stubs are accepted.")

    file_bytes = file_storage.read()

    if not file_bytes:
        raise ValueError("The uploaded file is empty.")

    if len(file_bytes) > Config.MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 5 MB limit.")

    extension = filename.rsplit(".", 1)[1].lower()
    if not content_matches_extension(file_bytes, extension):
        raise ValueError(
            "The file content does not match its extension. Upload rejected."
        )

    os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}_{filename}"

    with open(os.path.join(Config.UPLOAD_DIR, stored_name), "wb") as file:
        file.write(file_bytes)

    return stored_name
