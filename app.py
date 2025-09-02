import os
import json
import base64
from flask import Flask, redirect, request, session, url_for, render_template, jsonify
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import openai
from apscheduler.schedulers.background import BackgroundScheduler
import sqlite3
from datetime import datetime, timedelta

# ---- CONFIG ----
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]

IMPORTANT_LABEL = "Important Emails"
MARKETING_LABEL = "Marketing Emails"

DB_FILE = "users.db"

# ---- DATABASE ----
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            token TEXT,
            refresh_token TEXT,
            token_uri TEXT,
            client_id TEXT,
            client_secret TEXT,
            scopes TEXT,
            expiry TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS status (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_user_credentials(email, creds: Credentials):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO users VALUES (?,?,?,?,?,?,?,?)''', (
        email,
        creds.token,
        creds.refresh_token,
        creds.token_uri,
        creds.client_id,
        creds.client_secret,
        json.dumps(creds.scopes),
        creds.expiry.isoformat() if getattr(creds, "expiry", None) else None
    ))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM users')
    rows = c.fetchall()
    conn.close()
    users = []
    for row in rows:
        users.append({
            "email": row[0],
            "token": row[1],
            "refresh_token": row[2],
            "token_uri": row[3],
            "client_id": row[4],
            "client_secret": row[5],
            "scopes": json.loads(row[6]),
            "expiry": row[7]
        })
    return users

def save_last_classified(timestamp):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO status VALUES (?,?)', ("last_classified", timestamp))
    conn.commit()
    conn.close()

def get_last_classified():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT value FROM status WHERE key=?', ("last_classified",))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

# ---- HELPERS ----
def load_client_config():
    credentials_content = os.getenv("GOOGLE_CLIENT_SECRETS_JSON")
    if not credentials_content:
        raise RuntimeError("GOOGLE_CLIENT_SECRETS_JSON environment variable not found.")
    return json.loads(credentials_content)

def build_gmail_service(creds: Credentials):
    return build("gmail", "v1", credentials=creds)

def extract_text_from_html_data(data_b64):
    try:
        html = base64.urlsafe_b64decode(data_b64).decode("utf-8", errors="ignore")
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        return ""

def extract_text_from_parts(parts):
    for part in parts or []:
        mime = part.get("mimeType", "")
        body = part.get("body", {}) or {}
        data = body.get("data")
        if mime == "text/plain" and data:
            try:
                return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
            except Exception:
                pass
        if mime == "text/html" and data:
            txt = extract_text_from_html_data(data)
            if txt:
                return txt
        if mime.startswith("multipart"):
            inner = part.get("parts", [])
            txt = extract_text_from_parts(inner)
            if txt:
                return txt
    return ""

def get_email_body_and_sender(service, msg_id):
    msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
    payload = msg.get("payload", {}) or {}
    headers = payload.get("headers", []) or []
    parts = payload.get("parts", []) or []

    sender = "Unknown"
    subject = ""
    for h in headers:
        name = h.get("name", "").lower()
        if name == "from":
            sender = h.get("value", "Unknown")
        if name == "subject":
            subject = h.get("value", "")

    body = ""
    if parts:
        body = extract_text_from_parts(parts)
    else:
        mime_type = payload.get("mimeType", "")
        data = (payload.get("body") or {}).get("data")
        if data:
            if mime_type == "text/html":
                body = extract_text_from_html_data(data)
            else:
                try:
                    body = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                except Exception:
                    body = ""
    return body.strip(), sender, subject

def fetch_today_unread_emails(service):
    today = datetime.utcnow().date()
    q = f"is:unread after:{today.isoformat()}"
    res = service.users().messages().list(userId="me", q=q, maxResults=500).execute()
    return res.get("messages", [])

def get_or_create_label(service, label_name):
    labels = service.users().labels().list(userId="me").execute().get("labels", [])
    for l in labels:
        if l["name"].lower() == label_name.lower():
            return l["id"]
    body = {
        "name": label_name,
        "labelListVisibility": "labelShow",
        "messageListVisibility": "show",
    }
    label = service.users().labels().create(userId="me", body=body).execute()
    return label["id"]

def apply_label_and_mark_read(service, msg_id, label_id):
    service.users().messages().modify(
        userId="me",
        id=msg_id,
        body={"addLabelIds": [label_id], "removeLabelIds": ["UNREAD"]},
    ).execute()

# ---- GPT CLASSIFIER ----
def classify_email(content, subject=""):
    text = (subject + " " + content).replace("\n", " ")
    if len(text) > 4000:
        text = text[:4000]

    prompt = f"""
Classify the email as either 'marketing' or 'important'.

Rules:
- 'Important' = urgent, personal, or directly relevant to you.
- 'Marketing' = newsletters, digests, blog posts, educational updates from companies, promotional emails, or content that is not directly actionable or time-sensitive.
- Do not misclassify company educational content as important.

Email Subject + Content:
\"\"\"{text}\"\"\"

Reply ONLY with one word: marketing or important.
"""

    messages = [
        {"role": "system", "content": "You are an expert email classifier."},
        {"role": "user", "content": prompt}
    ]

    try:
        resp = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            max_tokens=4,
            temperature=0,
        )
        label_raw = resp.choices[0].message.content.strip().lower()
        if "marketing" in label_raw:
            return "marketing"
        return "important"
    except Exception:
        return "marketing"  # fail-safe

# ---- FLASK APP ----
def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET", "change-this-secret")
    openai.api_key = os.environ.get("OPENAI_API_KEY")
    init_db()

    @app.route("/")
    def index():
        authed = bool(session.get("google_creds"))
        return render_template("index.html", authed=authed)

    @app.route("/authorize")
    def authorize():
        client_secrets = load_client_config()
        flow = Flow.from_client_config(
            client_secrets,
            scopes=SCOPES,
            redirect_uri=url_for("oauth2callback", _external=True)
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"
        )
        session["state"] = state
        return redirect(auth_url)

    @app.route("/oauth2callback")
    def oauth2callback():
        state = session.get("state")
        if not state:
            return "Session expired. Please try again.", 400

        client_secrets = load_client_config()
        flow = Flow.from_client_config(
            client_secrets,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for("oauth2callback", _external=True)
        )
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        user_email = None
        if isinstance(creds.id_token, dict):
            user_email = creds.id_token.get("email")
        if not user_email:
            user_email = f"user_{datetime.now().timestamp()}"

        save_user_credentials(user_email, creds)
        session["google_creds"] = {"email": user_email}
        return redirect(url_for("index"))

    @app.route("/logout")
    def logout():
        session.pop("google_creds", None)
        return redirect(url_for("index"))

    @app.route("/last-classified")
    def last_classified():
        ts = get_last_classified()
        return jsonify({"last_classified": ts})

    # ---- BACKGROUND JOB ----
    def classify_emails_for_all_users():
        users = get_all_users()
        for u in users:
            try:
                # Load credentials and refresh if needed
                creds = Credentials.from_authorized_user_info(u, SCOPES)
                if creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    save_user_credentials(u["email"], creds)

                service = build_gmail_service(creds)
                important_label_id = get_or_create_label(service, IMPORTANT_LABEL)
                marketing_label_id = get_or_create_label(service, MARKETING_LABEL)

                msgs = fetch_today_unread_emails(service)
                for m in msgs:
                    msg_id = m["id"]
                    body, sender, subject = get_email_body_and_sender(service, msg_id)
                    label = classify_email(body, subject)
                    if label == "marketing":
                        apply_label_and_mark_read(service, msg_id, marketing_label_id)
                    else:
                        apply_label_and_mark_read(service, msg_id, important_label_id)

            except Exception as e:
                print(f"Error processing {u['email']}: {e}")

        save_last_classified(datetime.utcnow().isoformat())

    scheduler = BackgroundScheduler()
    scheduler.add_job(classify_emails_for_all_users, 'interval', minutes=1)  # every 1 min
    scheduler.start()

    return app

# ---- RUN APP ----
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
