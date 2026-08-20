from datetime import datetime

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

import models
from config import Config
from security import (
    check_csrf,
    decrypt_value,
    encrypt_value,
    get_csrf_token,
    login_required,
    save_pay_stub,
)


bp = Blueprint("appeals", __name__)


def recalculate_dti(existing_monthly_debt, proposed_loan_payment, monthly_net_income):
    if monthly_net_income <= 0:
        raise ValueError("Monthly net income must be greater than zero.")

    total_debt = existing_monthly_debt + proposed_loan_payment
    dti = total_debt / monthly_net_income
    clears = dti <= Config.DTI_THRESHOLD

    recommendation = (
        "Recommend reconsideration — new DTI clears the 43% threshold"
        if clears
        else
        "Recommend upholding denial — new DTI still exceeds the 43% threshold"
    )

    return round(dti, 4), recommendation, clears


@bp.route("/dashboard")
@login_required
def dashboard():
    rows = models.list_appeals()
    appeals = []

    for row in rows:
        appeals.append(
            {
                "id": row["id"],
                "applicant_name": decrypt_value(row["applicant_name_enc"]),
                "created_at": row["created_at"],
                "recalculated_dti": row["recalculated_dti"],
                "officer_verified": row["officer_verified"],
                "clears": (
                    row["recalculated_dti"] is not None
                    and row["recalculated_dti"] <= Config.DTI_THRESHOLD
                ),
            }
        )

    return render_template("dashboard.html", appeals=appeals)


@bp.route("/appeals/new", methods=["GET", "POST"])
@login_required
def new_appeal():
    if request.method == "POST":
        check_csrf()

        try:
            applicant_name = request.form.get("applicant_name", "").strip()
            if not applicant_name:
                raise ValueError("Applicant name is required.")

            prior_dti = float(request.form.get("prior_dti", "nan"))
            monthly_net_income = float(
                request.form.get("monthly_net_income", "nan")
            )
            existing_monthly_debt = float(
                request.form.get("existing_monthly_debt", "nan")
            )
            proposed_loan_payment = float(
                request.form.get("proposed_loan_payment", "nan")
            )

            values = (
                prior_dti,
                monthly_net_income,
                existing_monthly_debt,
                proposed_loan_payment,
            )

            if not all(value == value for value in values):
                raise ValueError("All financial figures are required.")

            if any(value < 0 for value in values):
                raise ValueError("Figures cannot be negative.")

            if not request.form.get("officer_verified"):
                raise ValueError(
                    "You must confirm the income figure against the uploaded document."
                )

            stored_filename = save_pay_stub(request.files.get("pay_stub"))

            dti, recommendation, _ = recalculate_dti(
                existing_monthly_debt,
                proposed_loan_payment,
                monthly_net_income,
            )

            models.create_appeal(
                officer_id=session["officer_id"],
                created_at=datetime.utcnow().isoformat(timespec="seconds"),
                applicant_name_enc=encrypt_value(applicant_name),
                monthly_net_income_enc=encrypt_value(monthly_net_income),
                existing_monthly_debt_enc=encrypt_value(existing_monthly_debt),
                proposed_loan_payment_enc=encrypt_value(proposed_loan_payment),
                prior_dti_enc=encrypt_value(prior_dti),
                pay_stub_filename=stored_filename,
                recalculated_dti=dti,
                recommendation=recommendation,
            )

            flash("Appeal recalculated and saved.", "success")
            return redirect(url_for("appeals.dashboard"))

        except ValueError as exc:
            flash(str(exc), "error")

    return render_template(
        "new_appeal.html",
        csrf_token=get_csrf_token(),
    )


@bp.route("/appeals/<int:appeal_id>")
@login_required
def view_appeal(appeal_id):
    row = models.get_appeal(appeal_id)

    if row is None:
        abort(404)

    appeal = {
        "id": row["id"],
        "created_at": row["created_at"],
        "applicant_name": decrypt_value(row["applicant_name_enc"]),
        "monthly_net_income": float(
            decrypt_value(row["monthly_net_income_enc"])
        ),
        "existing_monthly_debt": float(
            decrypt_value(row["existing_monthly_debt_enc"])
        ),
        "proposed_loan_payment": float(
            decrypt_value(row["proposed_loan_payment_enc"])
        ),
        "prior_dti": float(decrypt_value(row["prior_dti_enc"])),
        "pay_stub_filename": row["pay_stub_filename"],
        "recalculated_dti": row["recalculated_dti"],
        "recommendation": row["recommendation"],
        "officer_decision": row["officer_decision"],
        "clears": (
            row["recalculated_dti"] is not None
            and row["recalculated_dti"] <= Config.DTI_THRESHOLD
        ),
    }

    return render_template(
        "view_appeal.html",
        appeal=appeal,
        csrf_token=get_csrf_token(),
    )


@bp.route("/appeals/<int:appeal_id>/decide", methods=["POST"])
@login_required
def decide_appeal(appeal_id):
    check_csrf()

    if models.get_appeal(appeal_id) is None:
        abort(404)

    decision = request.form.get("decision")
    if decision not in {"approved", "denied"}:
        abort(400, description="Invalid decision.")

    models.set_appeal_decision(appeal_id, decision)
    flash("Decision recorded.", "success")

    return redirect(
        url_for("appeals.view_appeal", appeal_id=appeal_id)
    )


@bp.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(Config.UPLOAD_DIR, filename)
