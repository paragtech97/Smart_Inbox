import os
import json
import base64
from flask import Flask, redirect, request, session, url_for, render_template, jsonify
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from bs4 import BeautifulSoup
import openai

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
DEFAULT_MAX_EMAILS = 5
IMPORTANT_LABEL = "Important Emails"
MARKETING_LABEL = "Marketing Emails"

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")
    openai.api_key = os.environ.get("OPENAI_API_KEY")

    # ---- Helpers ----
    def load_client_config():
        path = os.environ.get("GOOGLE_CLIENT_SECRETS_FILE", "credentials.json")
        if not os.path.exists(path):
            raise RuntimeError("credentials.json not found. Provide via local file or secret file.")
        return path

    def build_gmail_service():
        creds_dict = session.get("google_creds")
        if not creds_dict:
            return None
        creds = Credentials.from_authorized_user_info(creds_dict, SCOPES)
        return build("gmail", "v1", credentials=creds)

    # ---- Email extraction helpers ----
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
        for h in headers:
            if h.get("name", "").lower() == "from":
                sender = h.get("value", "Unknown")
                break

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
        return body.strip(), sender

    def fetch_latest_emails(service, n, recent_window="1d"):
        q = f"is:unread newer_than:{recent_window}"
        res = service.users().messages().list(userId="me", maxResults=n, q=q).execute()
        return res.get("messages", [])

    # ---- Label helpers ----
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

    # ---- Email classifier ----
    def classify_email(content):
        text = content.replace("\n", " ")
        if len(text) > 4000:
            text = text[:4000]

        prompt = f"""
Classify the email content as 'marketing' or 'non-marketing'.

Rules:
- Promotional content, event invites, upgrades, discounts, newsletters → marketing
- Receipts, order/delivery updates, invoices, meeting/calendar info, personal/team updates → non-marketing

Email:
\"\"\"{text}\"\"\"

Only reply with one word: marketing or non-marketing.
"""
        messages = [
            {"role": "system", "content": "You are a precise email classifier. Reply only 'marketing' or 'non-marketing'."},
            {"role": "user", "content": prompt},
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
            return "non-marketing"
        except Exception:
            return "non-marketing"

    # -------------------- Routes --------------------
    @app.route("/")
    def index():
        authed = bool(session.get("google_creds"))
        return render_template("index.html", authed=authed)

    @app.route("/authorize")
    def authorize():
        client_secrets_file = load_client_config()
        flow = Flow.from_client_secrets_file(
            client_secrets_file,
            scopes=SCOPES,
            redirect_uri="http://127.0.0.1:5000/oauth2callback",
        )
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )
        session["state"] = state
        return redirect(auth_url)

    @app.route("/oauth2callback")
    def oauth2callback():
        state = session.get("state")
        if not state:
            # Lost session or expired; redirect to /authorize
            return redirect(url_for("authorize"))

        client_secrets_file = load_client_config()
        flow = Flow.from_client_secrets_file(
            client_secrets_file,
            scopes=SCOPES,
            state=state,
            redirect_uri="http://127.0.0.1:5000/oauth2callback",
        )

        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        session["google_creds"] = {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": creds.scopes,
            "expiry": creds.expiry.isoformat() if getattr(creds, "expiry", None) else None,
        }
        return redirect(url_for("index"))

    @app.route("/logout")
    def logout():
        session.pop("google_creds", None)
        return redirect(url_for("index"))

    @app.route("/classify", methods=["POST"])
    def classify_endpoint():
        if not session.get("google_creds"):
            return jsonify({"error": "Not authorized"}), 401

        n = int(request.args.get("n", DEFAULT_MAX_EMAILS))
        window = request.args.get("window", "1d")

        service = build_gmail_service()
        if not service:
            return jsonify({"error": "No Gmail credentials"}), 401

        important_label_id = get_or_create_label(service, IMPORTANT_LABEL)
        marketing_label_id = get_or_create_label(service, MARKETING_LABEL)

        msgs = fetch_latest_emails(service, n, recent_window=window)
        results = []

        for m in msgs:
            msg_id = m["id"]
            body, sender = get_email_body_and_sender(service, msg_id)
            label = classify_email(body)

            if label == "marketing":
                apply_label_and_mark_read(service, msg_id, marketing_label_id)
                results.append({"from": sender, "label": "Marketing Emails"})
            else:
                apply_label_and_mark_read(service, msg_id, important_label_id)
                results.append({"from": sender, "label": "Important Emails"})

        return jsonify({"processed": len(results), "items": results})

    return app

# ---- Run app ----
app = create_app()

if __name__ == "__main__":
    # Make sure this is run in the same terminal with:
    # $env:OAUTHLIB_INSECURE_TRANSPORT=1
    app.run(debug=True)