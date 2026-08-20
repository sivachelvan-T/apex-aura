import re

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from security import check_csrf, get_csrf_token
import models


bp = Blueprint("auth", __name__)

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,50}")


def _validate_credentials(username, password, confirm=None):
    if not USERNAME_RE.fullmatch(username):
        return (
            "Username must be 3–50 characters: letters, numbers, dot, "
            "underscore, or hyphen."
        )

    if len(password) < 8:
        return "Password must be at least 8 characters."

    if confirm is not None and password != confirm:
        return "Passwords do not match."

    return None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        row = models.get_officer_by_username(username)

        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["officer_id"] = row["id"]
            session["officer_name"] = row["username"]
            session["role"] = row["role"]

            return redirect(
                request.args.get("next") or url_for("appeals.dashboard")
            )

        flash("Incorrect username or password.", "error")

    return render_template("login.html", csrf_token=get_csrf_token())


@bp.route("/register", methods=["GET", "POST"])
def register():
    """Public registration always creates a Loan Officer."""
    if request.method == "POST":
        check_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        error = _validate_credentials(username, password, confirm)

        if error:
            flash(error, "error")
        elif username.lower() == Config.ADMIN_USERNAME.lower():
            flash("That username is reserved.", "error")
        elif models.username_exists(username):
            flash("That username is already taken.", "error")
        else:
            row = models.create_user(
                username,
                generate_password_hash(password),
                role="officer",
            )
            session.clear()
            session["officer_id"] = row["id"]
            session["officer_name"] = row["username"]
            session["role"] = row["role"]
            flash("Loan Officer account created.", "success")
            return redirect(url_for("appeals.dashboard"))

    return render_template("register.html", csrf_token=get_csrf_token())


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
