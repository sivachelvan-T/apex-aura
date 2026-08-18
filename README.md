# Apex Aura — Loan Appeal DTI Recalculator

**Track:** Zero Hunger & Economic Growth · Team 321
**Problem statement (as given to the team):** When a personal loan is
rejected for high Debt-to-Income (DTI), the applicant appeals with a new
pay stub — but the appeal process is manual, slow, and inconsistent
between officers.

## What this MVP does

One document. One metric. One recalculated ratio.

1. An officer opens a new appeal and uploads the applicant's new **pay
   stub** (PNG / JPG / PDF).
2. The officer **manually types** the figures shown on that document —
   Monthly Net Income, existing monthly debt, and the proposed loan
   payment — and must tick a box confirming they checked those numbers
   against the file themselves.
   *(This directly answers the mentor note: "the model must never
   invent a field value." There is no OCR auto-fill to trust or
   distrust — the human is always the one reading the document.)*
3. The app recalculates **DTI = (existing debt + proposed payment) /
   monthly net income** and shows a **recommendation**, clearly labelled
   "recommendation only — officer decision required."
4. The officer records the actual decision (approve / uphold denial),
   which is what the system treats as authoritative — not the
   recommendation.

## Security technique: encryption at rest

The headline control implemented here is **encryption at rest** for
every sensitive field (applicant name, income, existing debt, proposed
payment, prior DTI):

- Each value is encrypted with **Fernet** (AES-128-CBC + HMAC, from the
  `cryptography` library) *before* it is written to SQLite.
- The encryption key lives in a **separate file** (`secret.key`),
  generated on first run with owner-only permissions (`chmod 600`) —
  never inside the database itself.
- Values are decrypted only in memory, only for an **authenticated**
  officer's screen, and are never logged or cached to disk in plaintext.
- Practical effect: if `apex_aura.db` alone were copied or leaked (a
  common real-world breach pattern — stolen backups, misconfigured
  storage, etc.), the applicant's financial data is unreadable
  ciphertext without the separate key file.

Supporting controls (so the headline control isn't undone elsewhere):

| Control | Where |
|---|---|
| Session-based authentication, hashed passwords (`werkzeug.security`) | every route except `/login` |
| CSRF tokens on every POST form | login, new appeal, decision |
| Upload allowlist by **real file content** (magic-byte check), not just extension | `save_pay_stub()` |
| `secure_filename()` + random UUID prefix | blocks path traversal / overwrite |
| 5 MB upload cap | `MAX_CONTENT_LENGTH` |
| Parameterized SQL everywhere | no string-built queries, so no SQL injection surface |
| Jinja2 autoescaping (Flask default) | blocks stored/reflected XSS in rendered fields |

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000** and sign in with the demo account:

```
username: officer
password: ChangeMe123!
```

First run creates `apex_aura.db`, `secret.key`, and an `uploads/`
folder next to `app.py`.

## Deploying on Render

Render's free tier uses an **ephemeral filesystem** — the SQLite database,
the `secret.key` encryption key, and any uploaded pay stubs are wiped on
every restart, redeploy, or free-tier spin-down. For this app that's not
just an inconvenience: if the encryption key is regenerated, every
previously-encrypted row becomes permanently unreadable. So deployment
needs two things a plain "connect repo and go" free-tier deploy doesn't
give you: a fixed encryption key and a persistent disk.

The app already supports this via environment variables (`FERNET_KEY`,
`DB_PATH`, `UPLOAD_DIR`), and `render.yaml` in this folder wires it up
as a Render Blueprint.

**1. Push this folder to a GitHub repo.**

**2. Generate a Fernet key locally** (do this once, keep it somewhere safe):

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**3. In the Render dashboard: New → Blueprint**, point it at your repo.
Render reads `render.yaml` and creates:
- a **Starter** web service (the free plan can't attach a persistent disk)
- a **1 GB persistent disk** mounted at `/var/data`
- `DB_PATH` / `UPLOAD_DIR` already pointed at that disk
- a random `SECRET_KEY` (Flask session signing) generated for you

**4. Set the one value Render won't generate for you:** open the service's
**Environment** tab and paste your Fernet key into `FERNET_KEY`.

**5. Deploy.** Render runs `pip install -r requirements.txt` then
`gunicorn app:app`. Your first request will auto-create the database and
seed the demo `officer` account — go to `/login` on your Render URL.

**No Blueprint / prefer clicking through the UI instead?** Create a Web
Service manually, set the build command to `pip install -r
requirements.txt` and the start command to `gunicorn app:app`, add a
persistent disk mounted at `/var/data` (Starter plan or higher), and set
these four environment variables: `SECRET_KEY` (any random string),
`FERNET_KEY` (from step 2 above), `DB_PATH=/var/data/apex_aura.db`,
`UPLOAD_DIR=/var/data/uploads`.

**Just want a quick, disposable demo link and don't care about data
surviving a restart?** Skip the disk and the two path env vars entirely —
the app falls back to local files, which is fine right up until Render
recycles the container. Still set `FERNET_KEY` even for a demo, or the
key (and with it, every stored figure) resets on every redeploy.

## Before using this beyond a demo

- Set a real `SECRET_KEY` environment variable (Flask session signing
  key) instead of the auto-generated one, so sessions survive restarts.
- Move `secret.key` (the Fernet encryption key) into a proper secrets
  manager rather than a local file.
- Replace the single hardcoded demo account with real officer accounts
  and per-officer audit logging.
- Serve over HTTPS in any non-local deployment (Flask's dev server is
  HTTP-only and not meant for production).
