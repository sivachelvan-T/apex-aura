"""SQLite connection, schema creation, and safe schema migration."""

import sqlite3
from contextlib import closing

from flask import g
from werkzeug.security import generate_password_hash

from config import Config


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(Config.DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _table_columns(db, table_name):
    rows = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _migrate_officers(db):
    """Add role/active to older databases without destroying existing users."""
    columns = _table_columns(db, "officers")

    if "role" not in columns:
        db.execute(
            "ALTER TABLE officers ADD COLUMN role TEXT NOT NULL DEFAULT 'officer'"
        )

    if "active" not in columns:
        db.execute(
            "ALTER TABLE officers ADD COLUMN active INTEGER NOT NULL DEFAULT 1"
        )


def _migrate_appeals(db):
    """Add columns used by current versions if an older DB is reused."""
    columns = _table_columns(db, "appeals")

    additions = {
        "officer_verified": "INTEGER NOT NULL DEFAULT 0",
        "recalculated_dti": "REAL",
        "recommendation": "TEXT",
        "officer_decision": "TEXT NOT NULL DEFAULT 'pending'",
    }

    for column, definition in additions.items():
        if column not in columns:
            db.execute(
                f"ALTER TABLE appeals ADD COLUMN {column} {definition}"
            )


def init_db():
    """Create/migrate the database and ensure one configured admin exists.

    Existing databases are preserved. Missing role/active columns are added.
    If no administrator exists, the configured admin is created. If the
    configured admin username already exists as an old officer and no admin
    exists yet, that account is promoted and its password is set to the
    configured admin password.
    """
    os_dir = Config.DB_PATH
    parent = __import__("os").path.dirname(os_dir)
    if parent:
        __import__("os").makedirs(parent, exist_ok=True)

    with closing(sqlite3.connect(Config.DB_PATH)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS officers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'officer',
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS appeals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                officer_id INTEGER NOT NULL,
                applicant_name_enc TEXT NOT NULL,
                monthly_net_income_enc TEXT NOT NULL,
                existing_monthly_debt_enc TEXT NOT NULL,
                proposed_loan_payment_enc TEXT NOT NULL,
                prior_dti_enc TEXT NOT NULL,
                pay_stub_filename TEXT NOT NULL,
                officer_verified INTEGER NOT NULL DEFAULT 0,
                recalculated_dti REAL,
                recommendation TEXT,
                officer_decision TEXT NOT NULL DEFAULT 'pending',
                FOREIGN KEY (officer_id) REFERENCES officers (id)
            )
            """
        )

        _migrate_officers(db)
        _migrate_appeals(db)

        # Normalize invalid/null role values from older/manual databases.
        db.execute(
            "UPDATE officers SET role = 'officer' "
            "WHERE role IS NULL OR role NOT IN ('admin', 'officer')"
        )
        db.execute(
            "UPDATE officers SET active = 1 "
            "WHERE active IS NULL OR active NOT IN (0, 1)"
        )

        admin = db.execute(
            "SELECT id FROM officers WHERE role = 'admin' LIMIT 1"
        ).fetchone()

        if admin is None:
            existing = db.execute(
                "SELECT id FROM officers WHERE lower(username) = lower(?) LIMIT 1",
                (Config.ADMIN_USERNAME,),
            ).fetchone()

            if existing:
                db.execute(
                    """
                    UPDATE officers
                    SET role = 'admin', active = 1, password_hash = ?
                    WHERE id = ?
                    """,
                    (
                        generate_password_hash(Config.ADMIN_PASSWORD),
                        existing["id"],
                    ),
                )
            else:
                db.execute(
                    """
                    INSERT INTO officers
                    (username, password_hash, role, active)
                    VALUES (?, ?, 'admin', 1)
                    """,
                    (
                        Config.ADMIN_USERNAME,
                        generate_password_hash(Config.ADMIN_PASSWORD),
                    ),
                )

        db.commit()
