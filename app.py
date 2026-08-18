"""
Apex Aura — Loan Appeal DTI Recalculator
=========================================
Problem (Team 321, Zero Hunger & Economic Growth):
  When a personal loan is rejected for high Debt-to-Income (DTI), the
  applicant can appeal with a new pay stub. Officers need a fast, honest
  way to recheck ONE metric — Monthly Net Income — against ONE document —
  the pay stub — and see whether the appeal now clears the bank's DTI
  threshold.

Design decisions baked in from the mentor notes for this team:
  1. The system NEVER invents a field value. There is no blind OCR
     auto-fill. The officer must view the uploaded pay stub and manually
     type the figures on it, then explicitly tick "I verified this
     against the document above" before a recommendation is generated.
  2. Scope stays to exactly what was promised: one document (pay stub),
     one metric (Monthly Net Income), one recalculated ratio (DTI).
  3. The tool produces a RECOMMENDATION, never a final decision. Every
     result is labelled "Recommendation only — officer decision required."

Security technique implemented (headline control):
  ENCRYPTION AT REST — every sensitive financial figure and the
  applicant's name are encrypted with Fernet (AES-128-CBC + HMAC) before
  they ever touch the SQLite file, and decrypted only in memory for an
  authenticated officer's screen. If the database file alone were
  copied or leaked, the applicant's financial data is unreadable
  without the separate key file (secret.key), which is generated with
  restrictive file permissions and never stored in the database.

Supporting hygiene controls (so the headline control isn't undermined
elsewhere): session-based authentication with hashed passwords,
CSRF tokens on every POST, parameterized SQL (no string-built queries),
an upload allowlist that checks real file content (magic bytes) rather
than trusting the filename extension, secure_filename + random prefixes
against path traversal / overwrite, and a file-size cap.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000  (demo login: officer / ChangeMe123!)
"""

import os
import io
import sqlite3
import secrets
import uuid
from datetime import datetime
from contextlib import closing

from flask import (
    Flask, request, session, redirect, url_for, g,
    render_template_string, flash, abort, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken

# --------------------------------------------------------------------------
# App & config
# --------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# DB_PATH / UPLOAD_DIR default to local files for `python app.py` on your own
# machine. On a host with an ephemeral filesystem (Render's free tier, most
# PaaS free tiers), set these env vars to a mounted persistent-disk path —
# e.g. DB_PATH=/var/data/apex_aura.db, UPLOAD_DIR=/var/data/uploads — or the
# database and uploaded pay stubs disappear on every restart/redeploy.
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "apex_aura.db"))
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))
KEY_PATH = os.path.join(BASE_DIR, "secret.key")

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB
DTI_THRESHOLD = 0.43  # standard back-end DTI ceiling used for the demo

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
# In production, set SECRET_KEY via environment variable so sessions
# survive a restart. Falling back to a random key here so the app is
# still safe (if less convenient) if someone forgets to set it.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# --------------------------------------------------------------------------
# SECURITY CONTROL #1 — Encryption at rest
# --------------------------------------------------------------------------

def _load_or_create_key() -> bytes:
    """Resolve the Fernet key: env var first, then a local key file.

    On an ephemeral host (Render's free tier, most PaaS free tiers), a
    key file written to local disk is gone after the next restart or
    redeploy — and every row encrypted under the old key becomes
    permanently unreadable the moment that happens. Setting the
    FERNET_KEY environment variable in the platform's dashboard makes
    the key survive redeploys with zero code changes.

    Generate one locally with:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

    Keeping the key OUTSIDE the database either way means a leaked/copied
    database file is just ciphertext — useless without this key. In a
    larger production setup this key belongs in a real secrets manager
    (AWS KMS, Vault, Render's own secret files), not a bare env var;
    this is the honest MVP substitute.
    """
    env_key = os.environ.get("FERNET_KEY")
    if env_key:
        return env_key.encode("utf-8")

    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    # Restrict permissions to the owner only (no-op on some filesystems,
    # e.g. Windows, but harmless there).
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt_value(value) -> str:
    """Encrypt any scalar value (stored as its string form)."""
    return _fernet.encrypt(str(value).encode("utf-8")).decode("utf-8")


def decrypt_value(token: str) -> str:
    """Decrypt a stored token back to its original string."""
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        # Data was tampered with, or the key file was swapped out.
        return "‹unreadable›"


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS officers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS appeals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                officer_id INTEGER NOT NULL,

                -- Encrypted (sensitive) columns — never stored in plaintext.
                applicant_name_enc TEXT NOT NULL,
                monthly_net_income_enc TEXT NOT NULL,
                existing_monthly_debt_enc TEXT NOT NULL,
                proposed_loan_payment_enc TEXT NOT NULL,
                prior_dti_enc TEXT NOT NULL,

                -- Non-sensitive / operational columns.
                pay_stub_filename TEXT NOT NULL,
                officer_verified INTEGER NOT NULL DEFAULT 0,
                recalculated_dti REAL,
                recommendation TEXT,
                officer_decision TEXT NOT NULL DEFAULT 'pending',

                FOREIGN KEY (officer_id) REFERENCES officers (id)
            )
            """
        )
        # Seed one demo officer account if none exists yet.
        existing = db.execute("SELECT COUNT(*) FROM officers").fetchone()
        if existing[0] == 0:
            db.execute(
                "INSERT INTO officers (username, password_hash) VALUES (?, ?)",
                ("officer", generate_password_hash("ChangeMe123!")),
            )
        db.commit()


# --------------------------------------------------------------------------
# SECURITY CONTROL (supporting) — auth, CSRF, safe uploads
# --------------------------------------------------------------------------

def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("officer_id"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def check_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        abort(400, description="Invalid or missing CSRF token.")


def allowed_extension(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def content_matches_extension(file_bytes: bytes, extension: str) -> bool:
    """Check the file's real content using magic bytes."""

    extension = extension.lower()

    # PDF
    if extension == "pdf":
        return file_bytes.startswith(b"%PDF-")

    # JPEG
    if extension in {"jpg", "jpeg"}:
        return file_bytes.startswith(b"\xff\xd8\xff")

    # PNG
    if extension == "png":
        return file_bytes.startswith(
            b"\x89PNG\r\n\x1a\n"
        )

    return False


def save_pay_stub(file_storage) -> str:
    """Validate and persist an uploaded pay stub. Returns the stored filename."""
    if not file_storage or file_storage.filename == "":
        raise ValueError("No file was selected.")

    filename = secure_filename(file_storage.filename)
    if not allowed_extension(filename):
        raise ValueError("Only PNG, JPG, and PDF pay stubs are accepted.")

    file_bytes = file_storage.read()
    if len(file_bytes) == 0:
        raise ValueError("The uploaded file is empty.")
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise ValueError("File exceeds the 5 MB limit.")

    extension = filename.rsplit(".", 1)[1].lower()
    if not content_matches_extension(file_bytes, extension):
        raise ValueError(
            "The file's content doesn't match its extension — upload rejected."
        )

    # Random prefix defeats path traversal and filename collisions/overwrites.
    stored_name = f"{uuid.uuid4().hex}_{filename}"
    with open(os.path.join(UPLOAD_DIR, stored_name), "wb") as f:
        f.write(file_bytes)
    return stored_name


# --------------------------------------------------------------------------
# DTI logic
# --------------------------------------------------------------------------

def recalculate_dti(existing_monthly_debt: float, proposed_loan_payment: float,
                     monthly_net_income: float):
    if monthly_net_income <= 0:
        raise ValueError("Monthly net income must be greater than zero.")
    total_debt = existing_monthly_debt + proposed_loan_payment
    dti = total_debt / monthly_net_income
    clears = dti <= DTI_THRESHOLD
    recommendation = (
        "Recommend reconsideration — new DTI clears the 43% threshold"
        if clears else
        "Recommend upholding denial — new DTI still exceeds the 43% threshold"
    )
    return round(dti, 4), recommendation, clears


# --------------------------------------------------------------------------
# Templates (single file, ledger-styled)
# --------------------------------------------------------------------------

BASE_CSS = """
:root {
  --ink: #16241D;
  --paper: #ECEFE8;
  --paper-raised: #F6F7F2;
  --line: #C7CDBE;
  --muted: #667064;
  --verified: #2F6B4F;
  --alert: #B23A2E;
  --pending: #C9922B;
  --accent-ink: #0F3D2E;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font-family: 'IBM Plex Sans', system-ui, sans-serif;
  line-height: 1.5;
}
h1, h2, h3 { font-family: 'Fraunces', Georgia, serif; margin: 0 0 .4em; }
.mono { font-family: 'IBM Plex Mono', monospace; }
a { color: var(--accent-ink); }
.wrap { max-width: 880px; margin: 0 auto; padding: 32px 24px 64px; }
.topbar {
  display: flex; align-items: baseline; justify-content: space-between;
  border-bottom: 2px solid var(--ink); padding-bottom: 14px; margin-bottom: 28px;
}
.topbar .brand { font-family: 'Fraunces', serif; font-size: 22px; letter-spacing: .01em; }
.topbar .brand span { color: var(--verified); }
.topbar nav a { margin-left: 18px; font-size: 14px; text-decoration: none; color: var(--muted); }
.topbar nav a:hover { color: var(--ink); }
.card {
  background: var(--paper-raised);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 24px;
  margin-bottom: 20px;
}
label { display: block; font-size: 13px; color: var(--muted); margin: 14px 0 4px; }
input[type=text], input[type=number], input[type=password], input[type=file] {
  width: 100%; padding: 10px 12px; border: 1px solid var(--line);
  border-radius: 2px; background: #fff; font-size: 15px; font-family: inherit;
}
input:focus { outline: 2px solid var(--verified); outline-offset: 1px; }
.btn {
  display: inline-block; background: var(--ink); color: #fff; border: none;
  padding: 11px 20px; border-radius: 2px; font-size: 14px; cursor: pointer;
  text-decoration: none; margin-top: 16px;
}
.btn:hover { background: var(--accent-ink); }
.btn.secondary { background: transparent; color: var(--ink); border: 1px solid var(--ink); }
.check-row { display: flex; align-items: flex-start; gap: 10px; margin-top: 18px; }
.check-row input { width: auto; margin-top: 3px; }
.ledger-line {
  display: flex; justify-content: space-between; padding: 8px 0;
  border-bottom: 1px dotted var(--line); font-size: 15px;
}
.ledger-line.total { border-bottom: 2px solid var(--ink); font-weight: 600; }
.flash { background: #fff4e5; border: 1px solid var(--pending); padding: 10px 14px;
  border-radius: 2px; margin-bottom: 16px; font-size: 14px; }
.flash.error { background: #fbe9e7; border-color: var(--alert); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); font-size: 14px; }
th { color: var(--muted); font-weight: 500; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.stamp {
  display: inline-block; padding: 6px 14px; border-radius: 999px;
  font-family: 'IBM Plex Mono', monospace; font-size: 12px; letter-spacing: .03em;
  border: 2px solid; transform: rotate(-2deg);
}
.stamp.verified { color: var(--verified); border-color: var(--verified); }
.stamp.alert { color: var(--alert); border-color: var(--alert); }
.stamp.pending { color: var(--pending); border-color: var(--pending); }
.note { font-size: 12.5px; color: var(--muted); margin-top: 6px; }
.security-strip {
  margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--line);
  font-size: 12px; color: var(--muted);
}
"""

HEAD = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,600&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{css}</style>
""".replace("{css}", BASE_CSS)

TOPBAR = """
<div class="topbar">
  <div class="brand">Apex&nbsp;<span>Aura</span></div>
  <nav>
    {% if session.get('officer_id') %}
      <a href="{{ url_for('dashboard') }}">Appeals</a>
      <a href="{{ url_for('new_appeal') }}">New appeal</a>
      <a href="{{ url_for('logout') }}">Log out ({{ session.get('officer_name') }})</a>
    {% endif %}
  </nav>
</div>
"""

LOGIN_TEMPLATE = """
<!doctype html><html><head><meta charset="utf-8">
<title>Apex Aura — Officer sign-in</title>""" + HEAD + """
</head><body><div class="wrap" style="max-width:420px;">
""" + TOPBAR + """
  <h1>Officer sign-in</h1>
  <p class="note">DTI appeal recalculation is restricted to authenticated loan officers.</p>
  {% with messages = get_flashed_messages(category_filter=['error']) %}
    {% for m in messages %}<div class="flash error">{{ m }}</div>{% endfor %}
  {% endwith %}
  <form class="card" method="post">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" required autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required>
    <button class="btn" type="submit">Sign in</button>
  </form>
  <p class="note">Demo credentials: <span class="mono">officer / ChangeMe123!</span> — change this before any real use.</p>
</div></body></html>
"""

DASHBOARD_TEMPLATE = """
<!doctype html><html><head><meta charset="utf-8">
<title>Apex Aura — Appeals</title>""" + HEAD + """
</head><body><div class="wrap">
""" + TOPBAR + """
  <h1>Loan appeals</h1>
  <p class="note">Monthly Net Income and debt figures are decrypted only for this authenticated view. At rest, they are stored as Fernet ciphertext.</p>
  {% with messages = get_flashed_messages(category_filter=['success']) %}
    {% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}
  {% endwith %}
  <div class="card">
    {% if appeals %}
    <table>
      <tr><th>#</th><th>Applicant</th><th>Filed</th><th>Recalculated DTI</th><th>Verdict</th><th></th></tr>
      {% for a in appeals %}
      <tr>
        <td class="mono">{{ '%03d' % a.id }}</td>
        <td>{{ a.applicant_name }}</td>
        <td class="mono">{{ a.created_at[:10] }}</td>
        <td class="mono">{{ '%.1f' % (a.recalculated_dti * 100) if a.recalculated_dti is not none else '—' }}%</td>
        <td>
          {% if not a.officer_verified %}
            <span class="stamp pending">awaiting verification</span>
          {% elif a.clears %}
            <span class="stamp verified">clears threshold</span>
          {% else %}
            <span class="stamp alert">still exceeds</span>
          {% endif %}
        </td>
        <td><a href="{{ url_for('view_appeal', appeal_id=a.id) }}">Open →</a></td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
      <p>No appeals filed yet. <a href="{{ url_for('new_appeal') }}">Start one →</a></p>
    {% endif %}
  </div>
</div></body></html>
"""

NEW_APPEAL_TEMPLATE = """
<!doctype html><html><head><meta charset="utf-8">
<title>Apex Aura — New appeal</title>""" + HEAD + """
</head><body><div class="wrap">
""" + TOPBAR + """
  <h1>Recalculate a DTI appeal</h1>
  <p class="note">
    Scope, on purpose: one document (the new pay stub), one metric
    (Monthly Net Income). Nothing here is read automatically from the
    file — you confirm every figure against the document yourself.
  </p>
  {% with messages = get_flashed_messages(category_filter=['error']) %}
    {% for m in messages %}<div class="flash error">{{ m }}</div>{% endfor %}
  {% endwith %}
  <form class="card" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">

    <label for="applicant_name">Applicant name</label>
    <input type="text" id="applicant_name" name="applicant_name" required>

    <label for="pay_stub">New pay stub (PNG, JPG, or PDF — max 5&nbsp;MB)</label>
    <input type="file" id="pay_stub" name="pay_stub" accept=".png,.jpg,.jpeg,.pdf" required>

    <label for="prior_dti">DTI at original rejection (%)</label>
    <input type="number" step="0.01" id="prior_dti" name="prior_dti" required>

    <label for="monthly_net_income">Monthly net income shown on this pay stub ($)</label>
    <input type="number" step="0.01" id="monthly_net_income" name="monthly_net_income" required>

    <label for="existing_monthly_debt">Applicant's other existing monthly debt payments ($)</label>
    <input type="number" step="0.01" id="existing_monthly_debt" name="existing_monthly_debt" required>

    <label for="proposed_loan_payment">Proposed monthly payment for the requested loan ($)</label>
    <input type="number" step="0.01" id="proposed_loan_payment" name="proposed_loan_payment" required>

    <div class="check-row">
      <input type="checkbox" id="officer_verified" name="officer_verified" required>
      <label for="officer_verified" style="margin:0;">
        I have opened the uploaded pay stub and manually confirmed the
        Monthly Net Income figure above matches it. I am not relying on
        automated extraction.
      </label>
    </div>

    <button class="btn" type="submit">Recalculate DTI</button>
  </form>
</div></body></html>
"""

VIEW_APPEAL_TEMPLATE = """
<!doctype html><html><head><meta charset="utf-8">
<title>Apex Aura — Appeal #{{ '%03d' % appeal.id }}</title>""" + HEAD + """
</head><body><div class="wrap">
""" + TOPBAR + """
  <h1>Appeal #{{ '%03d' % appeal.id }} — {{ appeal.applicant_name }}</h1>
  <p class="note">Filed {{ appeal.created_at }} · Pay stub on file:
    <a href="{{ url_for('uploaded_file', filename=appeal.pay_stub_filename) }}" target="_blank" rel="noopener">view document</a>
  </p>

  <div class="card">
    <h3>Recalculation ledger</h3>
    <div class="ledger-line"><span>Prior DTI at rejection</span><span class="mono">{{ '%.1f' % appeal.prior_dti }}%</span></div>
    <div class="ledger-line"><span>Monthly net income (this pay stub)</span><span class="mono">${{ '{:,.2f}'.format(appeal.monthly_net_income) }}</span></div>
    <div class="ledger-line"><span>Existing monthly debt</span><span class="mono">${{ '{:,.2f}'.format(appeal.existing_monthly_debt) }}</span></div>
    <div class="ledger-line"><span>Proposed loan payment</span><span class="mono">${{ '{:,.2f}'.format(appeal.proposed_loan_payment) }}</span></div>
    <div class="ledger-line total"><span>Recalculated DTI</span><span class="mono">{{ '%.1f' % (appeal.recalculated_dti * 100) }}%</span></div>

    <p style="margin-top:18px;">
      {% if appeal.clears %}
        <span class="stamp verified">{{ appeal.recommendation }}</span>
      {% else %}
        <span class="stamp alert">{{ appeal.recommendation }}</span>
      {% endif %}
    </p>
    <p class="note">Recommendation only — the officer decision below is what actually governs this appeal.</p>
  </div>

  <div class="card">
    <h3>Officer decision</h3>
    {% if appeal.officer_decision == 'pending' %}
    <form method="post" action="{{ url_for('decide_appeal', appeal_id=appeal.id) }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <button class="btn" type="submit" name="decision" value="approved">Approve appeal</button>
      <button class="btn secondary" type="submit" name="decision" value="denied">Uphold denial</button>
    </form>
    {% else %}
      <p>Recorded decision:
        {% if appeal.officer_decision == 'approved' %}
          <span class="stamp verified">approved</span>
        {% else %}
          <span class="stamp alert">denial upheld</span>
        {% endif %}
      </p>
    {% endif %}
  </div>

  <div class="security-strip">
    Applicant name, income, and debt figures for this appeal are stored
    encrypted (Fernet/AES) and were decrypted only for this authenticated
    session.
  </div>
</div></body></html>
"""


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("dashboard") if session.get("officer_id") else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT * FROM officers WHERE username = ?", (username,)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["officer_id"] = row["id"]
            session["officer_name"] = row["username"]
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Incorrect username or password.", "error")
    return render_template_string(LOGIN_TEMPLATE, csrf_token=get_csrf_token())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM appeals ORDER BY created_at DESC"
    ).fetchall()
    appeals = []
    for r in rows:
        appeals.append({
            "id": r["id"],
            "applicant_name": decrypt_value(r["applicant_name_enc"]),
            "created_at": r["created_at"],
            "recalculated_dti": r["recalculated_dti"],
            "officer_verified": r["officer_verified"],
            "clears": (r["recalculated_dti"] is not None and r["recalculated_dti"] <= DTI_THRESHOLD),
        })
    return render_template_string(DASHBOARD_TEMPLATE, appeals=appeals)


@app.route("/appeals/new", methods=["GET", "POST"])
@login_required
def new_appeal():
    if request.method == "POST":
        check_csrf()
        try:
            applicant_name = request.form.get("applicant_name", "").strip()
            if not applicant_name:
                raise ValueError("Applicant name is required.")

            prior_dti = float(request.form.get("prior_dti", "nan"))
            monthly_net_income = float(request.form.get("monthly_net_income", "nan"))
            existing_monthly_debt = float(request.form.get("existing_monthly_debt", "nan"))
            proposed_loan_payment = float(request.form.get("proposed_loan_payment", "nan"))

            if not request.form.get("officer_verified"):
                raise ValueError(
                    "You must confirm the income figure against the uploaded document."
                )
            if any(v < 0 for v in (prior_dti, monthly_net_income, existing_monthly_debt, proposed_loan_payment)):
                raise ValueError("Figures cannot be negative.")

            stored_filename = save_pay_stub(request.files.get("pay_stub"))

            dti, recommendation, _clears = recalculate_dti(
                existing_monthly_debt, proposed_loan_payment, monthly_net_income
            )

            db = get_db()
            db.execute(
                """
                INSERT INTO appeals (
                    created_at, officer_id,
                    applicant_name_enc, monthly_net_income_enc,
                    existing_monthly_debt_enc, proposed_loan_payment_enc, prior_dti_enc,
                    pay_stub_filename, officer_verified, recalculated_dti, recommendation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat(timespec="seconds"),
                    session["officer_id"],
                    encrypt_value(applicant_name),
                    encrypt_value(monthly_net_income),
                    encrypt_value(existing_monthly_debt),
                    encrypt_value(proposed_loan_payment),
                    encrypt_value(prior_dti),
                    stored_filename,
                    1,
                    dti,
                    recommendation,
                ),
            )
            db.commit()
            flash("Appeal recalculated and saved.", "success")
            return redirect(url_for("dashboard"))

        except ValueError as e:
            flash(str(e), "error")

    return render_template_string(NEW_APPEAL_TEMPLATE, csrf_token=get_csrf_token())


@app.route("/appeals/<int:appeal_id>")
@login_required
def view_appeal(appeal_id):
    db = get_db()
    r = db.execute("SELECT * FROM appeals WHERE id = ?", (appeal_id,)).fetchone()
    if r is None:
        abort(404)
    appeal = {
        "id": r["id"],
        "created_at": r["created_at"],
        "applicant_name": decrypt_value(r["applicant_name_enc"]),
        "monthly_net_income": float(decrypt_value(r["monthly_net_income_enc"])),
        "existing_monthly_debt": float(decrypt_value(r["existing_monthly_debt_enc"])),
        "proposed_loan_payment": float(decrypt_value(r["proposed_loan_payment_enc"])),
        "prior_dti": float(decrypt_value(r["prior_dti_enc"])),
        "pay_stub_filename": r["pay_stub_filename"],
        "recalculated_dti": r["recalculated_dti"],
        "recommendation": r["recommendation"],
        "officer_decision": r["officer_decision"],
        "clears": r["recalculated_dti"] is not None and r["recalculated_dti"] <= DTI_THRESHOLD,
    }
    return render_template_string(VIEW_APPEAL_TEMPLATE, appeal=appeal, csrf_token=get_csrf_token())


@app.route("/appeals/<int:appeal_id>/decide", methods=["POST"])
@login_required
def decide_appeal(appeal_id):
    check_csrf()
    decision = request.form.get("decision")
    if decision not in {"approved", "denied"}:
        abort(400)
    db = get_db()
    db.execute(
        "UPDATE appeals SET officer_decision = ? WHERE id = ?",
        (decision, appeal_id),
    )
    db.commit()
    flash("Decision recorded.", "success")
    return redirect(url_for("view_appeal", appeal_id=appeal_id))


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    # login_required gate means only authenticated officers can ever
    # fetch a stored pay stub, even though filenames are unguessable.
    return send_from_directory(UPLOAD_DIR, filename)


@app.errorhandler(400)
def bad_request(e):
    return f"<h3>400 — {e.description}</h3><a href='/'>Back</a>", 400


# Initialize database when the application starts.
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
