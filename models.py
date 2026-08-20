"""Parameterized data-access functions for users and appeals."""

from db import get_db


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def get_officer_by_username(username):
    return get_db().execute(
        "SELECT * FROM officers WHERE lower(username) = lower(?) AND active = 1",
        (username,),
    ).fetchone()


def get_officer(officer_id):
    return get_db().execute(
        "SELECT * FROM officers WHERE id = ?",
        (officer_id,),
    ).fetchone()


def username_exists(username):
    return get_db().execute(
        "SELECT id FROM officers WHERE lower(username) = lower(?)",
        (username,),
    ).fetchone() is not None


def create_user(username, password_hash, role="officer"):
    if role not in {"admin", "officer"}:
        raise ValueError("Invalid user role.")

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO officers (username, password_hash, role, active)
        VALUES (?, ?, ?, 1)
        """,
        (username, password_hash, role),
    )
    db.commit()
    return get_officer(cursor.lastrowid)


def create_officer(username, password_hash, role="officer"):
    # Backward-compatible name used by older code.
    return create_user(username, password_hash, role)


def list_officers():
    return get_db().execute(
        """
        SELECT id, username, role, active
        FROM officers
        ORDER BY CASE WHEN role = 'admin' THEN 0 ELSE 1 END, username
        """
    ).fetchall()


def count_active_admins():
    row = get_db().execute(
        "SELECT COUNT(*) AS count FROM officers "
        "WHERE role = 'admin' AND active = 1"
    ).fetchone()
    return int(row["count"])


def update_user_role(user_id, role):
    if role not in {"admin", "officer"}:
        raise ValueError("Invalid user role.")

    db = get_db()
    db.execute(
        "UPDATE officers SET role = ? WHERE id = ?",
        (role, user_id),
    )
    db.commit()


def set_user_active(user_id, active):
    db = get_db()
    db.execute(
        "UPDATE officers SET active = ? WHERE id = ?",
        (1 if active else 0, user_id),
    )
    db.commit()


def deactivate_officer(officer_id):
    set_user_active(officer_id, False)


# ---------------------------------------------------------------------------
# Appeals
# ---------------------------------------------------------------------------

def create_appeal(
    officer_id,
    created_at,
    applicant_name_enc,
    monthly_net_income_enc,
    existing_monthly_debt_enc,
    proposed_loan_payment_enc,
    prior_dti_enc,
    pay_stub_filename,
    recalculated_dti,
    recommendation,
):
    db = get_db()
    db.execute(
        """
        INSERT INTO appeals (
            created_at,
            officer_id,
            applicant_name_enc,
            monthly_net_income_enc,
            existing_monthly_debt_enc,
            proposed_loan_payment_enc,
            prior_dti_enc,
            pay_stub_filename,
            officer_verified,
            recalculated_dti,
            recommendation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            created_at,
            officer_id,
            applicant_name_enc,
            monthly_net_income_enc,
            existing_monthly_debt_enc,
            proposed_loan_payment_enc,
            prior_dti_enc,
            pay_stub_filename,
            recalculated_dti,
            recommendation,
        ),
    )
    db.commit()


def list_appeals():
    return get_db().execute(
        "SELECT * FROM appeals ORDER BY created_at DESC"
    ).fetchall()


def get_appeal(appeal_id):
    return get_db().execute(
        "SELECT * FROM appeals WHERE id = ?",
        (appeal_id,),
    ).fetchone()


def set_appeal_decision(appeal_id, decision):
    db = get_db()
    db.execute(
        "UPDATE appeals SET officer_decision = ? WHERE id = ?",
        (decision, appeal_id),
    )
    db.commit()
