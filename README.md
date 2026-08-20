# Apex Aura — Loan Appeal DTI Recalculator

A Flask web application for loan-appeal DTI recalculation.

## Roles and privileges

### Administrator
- Create Loan Officer accounts
- Create Administrator accounts
- View all users
- Change a user's privilege level
- Activate/deactivate users
- Cannot deactivate or demote the current account
- The system always protects at least one active administrator

### Loan Officer
- Sign in
- Create and review loan appeals
- Upload pay stubs
- Manually enter figures from the pay stub
- Recalculate DTI
- Record the officer decision
- Cannot access administrator routes

Public registration, when enabled, always creates a Loan Officer account. Administrator-created users can receive either privilege.

## Security controls

- Fernet encryption for sensitive applicant/financial values before SQLite storage
- Werkzeug password hashing
- Session authentication
- Server-side role authorization
- CSRF tokens on state-changing forms
- PDF/PNG/JPEG magic-byte validation
- 5 MB upload limit
- Randomized stored upload filenames
- Parameterized SQL
- Jinja2 autoescaping
- HTTP-only, SameSite session cookies

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

For local setup, the default admin is:

```text
Username: admin
Password: admin123!
```

Change this for any public deployment.

## Render deployment

Build command:

```text
pip install -r requirements.txt
```

Start command:

```text
gunicorn app:app
```

Set these environment variables in Render:

```text
SECRET_KEY=<strong random value or Render-generated value>
FERNET_KEY=<Fernet key>
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<strong admin password>
```

Generate a Fernet key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### Existing Render service

If the Render service already exists and uses Manual Deploy:

1. Replace the project files with the files in this repository.
2. Commit and push to GitHub.
3. Open the existing Render service.
4. Choose **Manual Deploy → Deploy latest commit**.
5. Keep `gunicorn app:app` as the start command.
6. Verify the environment variables.
7. Watch the deploy logs for a successful Gunicorn startup.

## Database migration

The current `db.py` safely adds the `role` and `active` columns if an older `officers` table is reused. It does not delete existing users.

It also adds missing appeal workflow columns used by the current application.

If an existing database has no administrator, the configured `ADMIN_USERNAME` account is created or an existing matching username is promoted to administrator.

## Free Render storage limitation

Render's Free filesystem is ephemeral. SQLite data and uploaded pay stubs may disappear after a restart, redeploy, or inactivity spin-down. This project is therefore suitable for a college/demo deployment using dummy data.

For real financial information, use persistent managed storage and a production deployment architecture.
