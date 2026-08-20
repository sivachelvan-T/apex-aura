import re

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash

import models
from security import admin_required, check_csrf, get_csrf_token


bp = Blueprint("admin", __name__)

USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,50}")
ALLOWED_ROLES = {"admin", "officer"}


def _validate_new_user(username, password, confirm_password, role):
    if not USERNAME_RE.fullmatch(username):
        return (
            "Username must be 3–50 characters: letters, numbers, dot, "
            "underscore, or hyphen."
        )
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if password != confirm_password:
        return "Passwords do not match."
    if role not in ALLOWED_ROLES:
        return "Invalid privilege selection."
    if models.username_exists(username):
        return "That username is already taken."
    return None


@bp.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    users = [dict(row) for row in models.list_officers()]
    return render_template(
        "admin_users.html",
        users=users,
        csrf_token=get_csrf_token(),
    )


@bp.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_create_user():
    check_csrf()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    role = request.form.get("role", "officer").strip().lower()

    error = _validate_new_user(
        username, password, confirm_password, role
    )

    if error:
        flash(error, "error")
        return redirect(url_for("admin.admin_users"))

    try:
        models.create_user(
            username,
            generate_password_hash(password),
            role=role,
        )
    except Exception:
        flash("Could not create the user. The username may already exist.", "error")
        return redirect(url_for("admin.admin_users"))

    flash(
        f"User '{username}' created with "
        f"{'Administrator' if role == 'admin' else 'Loan Officer'} privileges.",
        "success",
    )
    return redirect(url_for("admin.admin_users"))


@bp.route("/admin/users/<int:user_id>/status", methods=["POST"])
@admin_required
def admin_change_status(user_id):
    check_csrf()

    user = models.get_officer(user_id)
    if user is None:
        abort(404)

    if user_id == session.get("officer_id"):
        abort(400, description="You cannot deactivate your own account.")

    desired_active = request.form.get("active") == "1"

    # Never allow the last active administrator to be removed.
    if (
        not desired_active
        and user["role"] == "admin"
        and user["active"]
        and models.count_active_admins() <= 1
    ):
        abort(400, description="At least one active administrator is required.")

    models.set_user_active(user_id, desired_active)
    flash(
        f"User '{user['username']}' is now "
        f"{'active' if desired_active else 'inactive'}.",
        "success",
    )
    return redirect(url_for("admin.admin_users"))


@bp.route("/admin/users/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_change_role(user_id):
    check_csrf()

    user = models.get_officer(user_id)
    if user is None:
        abort(404)

    if user_id == session.get("officer_id"):
        abort(400, description="You cannot change your own privilege level.")

    new_role = request.form.get("role", "").strip().lower()
    if new_role not in ALLOWED_ROLES:
        abort(400, description="Invalid privilege selection.")

    if (
        new_role == "officer"
        and user["role"] == "admin"
        and user["active"]
        and models.count_active_admins() <= 1
    ):
        abort(400, description="At least one active administrator is required.")

    models.update_user_role(user_id, new_role)
    flash(
        f"User '{user['username']}' privileges changed to "
        f"{'Administrator' if new_role == 'admin' else 'Loan Officer'}.",
        "success",
    )
    return redirect(url_for("admin.admin_users"))
