import base64
import html
import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


BASE_DIR = Path(__file__).resolve().parent
TOKEN_FILE = BASE_DIR / "token.json"
MODEL_FILE = BASE_DIR / "models" / "phishing_model.joblib"
SCAN_HISTORY_FILE = BASE_DIR / "scan_history.db"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".msi", ".dll", ".lnk",
    ".iso", ".img", ".jar", ".xlsm", ".docm", ".pptm",
}

URGENCY_TERMS = {
    "urgent", "immediately", "final warning", "account suspended",
    "account suspension", "act now", "within 24 hours", "expires today",
    "payment overdue", "verify now", "unusual activity",
}

DATA_REQUEST_TERMS = {
    "password", "otp", "one-time password", "credit card", "bank account",
    "aadhaar", "pan card", "social security", "login credentials",
    "date of birth", "personal details", "verify your account",
}


app = FastAPI(title="PhishGuard Gmail Scanner", version="2.4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def allow_local_network_access(request, call_next):
    response = await call_next(request)
    if request.headers.get("access-control-request-private-network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


def get_gmail_service():
    if not TOKEN_FILE.exists():
        raise RuntimeError("token.json is missing. Run gmail_test.py first.")

    credentials = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())
        TOKEN_FILE.write_text(credentials.to_json(), encoding="utf-8")

    return build("gmail", "v1", credentials=credentials)


def load_phishing_model():
    if not MODEL_FILE.exists():
        print(f"Warning: phishing model not found at {MODEL_FILE}")
        return None

    try:
        model = joblib.load(MODEL_FILE)
        print(f"Phishing model loaded from {MODEL_FILE}")
        return model
    except Exception as error:
        print(f"Warning: unable to load phishing model: {error}")
        return None


PHISHING_MODEL = load_phishing_model()


def open_scan_history():
    connection = sqlite3.connect(SCAN_HISTORY_FILE, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS message_scans (
            message_id TEXT PRIMARY KEY,
            scanned_at TEXT NOT NULL,
            score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            severity TEXT NOT NULL,
            analysis_json TEXT NOT NULL
        )
        """
    )
    return connection


def load_saved_analysis(message_id: str) -> dict[str, Any] | None:
    with open_scan_history() as connection:
        row = connection.execute(
            "SELECT analysis_json, scanned_at FROM message_scans WHERE message_id = ?",
            (message_id,),
        ).fetchone()
    if row is None:
        return None
    result = json.loads(row["analysis_json"])
    result["scan_status"] = "complete"
    result["scanned_at"] = row["scanned_at"]
    result["cached"] = True
    return result


def load_scan_summaries(message_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not message_ids:
        return {}

    summaries: dict[str, dict[str, Any]] = {}
    with open_scan_history() as connection:
        # Keep each query below SQLite's bound-parameter limit for large inboxes.
        for start in range(0, len(message_ids), 500):
            batch = message_ids[start:start + 500]
            placeholders = ",".join("?" for _ in batch)
            rows = connection.execute(
                f"""
                SELECT message_id, scanned_at, score, verdict, severity
                FROM message_scans
                WHERE message_id IN ({placeholders})
                """,
                batch,
            ).fetchall()
            for row in rows:
                summaries[row["message_id"]] = {
                    "status": "complete",
                    "scanned_at": row["scanned_at"],
                    "score": row["score"],
                    "verdict": row["verdict"],
                    "severity": row["severity"],
                }
    return summaries


def save_analysis(result: dict[str, Any]) -> dict[str, Any]:
    scanned_at = datetime.now(timezone.utc).isoformat()
    stored_result = dict(result)
    stored_result["scan_status"] = "complete"
    stored_result["scanned_at"] = scanned_at
    stored_result["cached"] = False
    with open_scan_history() as connection:
        connection.execute(
            """
            INSERT INTO message_scans (
                message_id, scanned_at, score, verdict, severity, analysis_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(message_id) DO UPDATE SET
                scanned_at = excluded.scanned_at,
                score = excluded.score,
                verdict = excluded.verdict,
                severity = excluded.severity,
                analysis_json = excluded.analysis_json
            """,
            (
                result["message_id"],
                scanned_at,
                result["score"],
                result["verdict"],
                result["severity"],
                json.dumps(result, ensure_ascii=False),
            ),
        )
    return stored_result


def run_ml_analysis(subject: str, body: str) -> dict[str, Any]:
    if PHISHING_MODEL is None:
        return {
            "available": False,
            "classification": "Unavailable",
            "prediction": None,
            "phishing_probability": None,
            "confidence": None,
            "risk_band": "unknown",
        }

    model_text = f"Subject: {subject.strip()}\nBody: {body.strip()}"
    probabilities = PHISHING_MODEL.predict_proba([model_text])[0]
    classes = list(PHISHING_MODEL.classes_)
    phishing_index = classes.index(1)
    phishing_probability = float(probabilities[phishing_index])
    prediction = int(phishing_probability >= 0.50)

    if phishing_probability >= 0.85:
        risk_band = "high"
    elif phishing_probability >= 0.60:
        risk_band = "elevated"
    elif phishing_probability >= 0.40:
        risk_band = "uncertain"
    else:
        risk_band = "low"

    return {
        "available": True,
        "classification": "Phishing" if prediction == 1 else "Legitimate",
        "prediction": prediction,
        "phishing_probability": round(phishing_probability, 4),
        "confidence": round(
            phishing_probability if prediction == 1 else 1 - phishing_probability,
            4,
        ),
        "risk_band": risk_band,
    }


def header_values(headers: list[dict[str, str]], name: str) -> list[str]:
    return [
        item.get("value", "")
        for item in headers
        if item.get("name", "").lower() == name.lower()
    ]


def first_header(headers: list[dict[str, str]], name: str) -> str:
    values = header_values(headers, name)
    return values[0] if values else ""


def decode_body(data: str | None) -> str:
    if not data:
        return ""
    try:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return ""


def walk_parts(part: dict[str, Any]):
    yield part
    for child in part.get("parts", []) or []:
        yield from walk_parts(child)


def extract_message_content(payload: dict[str, Any]):
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, Any]] = []

    for part in walk_parts(payload):
        mime_type = part.get("mimeType", "")
        filename = part.get("filename", "") or ""
        body = part.get("body", {}) or {}

        if filename:
            attachments.append({
                "filename": filename,
                "mime_type": mime_type,
                "size": body.get("size", 0),
                "attachment_id": body.get("attachmentId"),
            })
            continue

        text = decode_body(body.get("data"))
        if mime_type == "text/plain":
            plain_parts.append(text)
        elif mime_type == "text/html":
            html_parts.append(text)

    plain_text = "\n".join(plain_parts)[:250_000]
    html_text = "\n".join(html_parts)[:250_000]

    if not plain_text and html_text:
        plain_text = re.sub(r"<[^>]+>", " ", html_text)
        plain_text = html.unescape(re.sub(r"\s+", " ", plain_text))

    return plain_text, html_text, attachments


def email_domain(value: str) -> str:
    address = parseaddr(value)[1].lower()
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def registrable_hint(domain: str) -> str:
    labels = [label for label in domain.lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain.lower()


def same_domain_family(first: str, second: str) -> bool:
    if not first or not second:
        return False
    return registrable_hint(first) == registrable_hint(second)


def auth_result(text: str, mechanism: str) -> str:
    match = re.search(rf"\b{re.escape(mechanism)}\s*=\s*([a-zA-Z0-9_-]+)", text, re.I)
    return match.group(1).lower() if match else "missing"


def public_ips(received_headers: list[str]) -> list[str]:
    found: list[str] = []
    for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", " ".join(received_headers)):
        try:
            ip = ipaddress.ip_address(candidate)
            if not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast):
                found.append(candidate)
        except ValueError:
            continue
    return list(dict.fromkeys(found))


def check_item(name: str, group: str, state: str, score: int, result: str, recommendation: str):
    return {
        "name": name,
        "group": group,
        "state": state,
        "score": score,
        "result": result,
        "recommendation": recommendation,
    }


def analyse_message(message: dict[str, Any]) -> dict[str, Any]:
    payload = message.get("payload", {})
    headers = payload.get("headers", []) or []
    plain_text, html_text, attachments = extract_message_content(payload)

    sender = first_header(headers, "From")
    reply_to = first_header(headers, "Reply-To")
    return_path = first_header(headers, "Return-Path")
    subject = first_header(headers, "Subject")
    message_id = first_header(headers, "Message-ID")
    received = header_values(headers, "Received")
    authentication = " ".join(
        header_values(headers, "Authentication-Results")
        + header_values(headers, "ARC-Authentication-Results")
    )

    sender_domain = email_domain(sender)
    reply_domain = email_domain(reply_to)
    return_domain = email_domain(return_path)
    checks: list[dict[str, Any]] = []

    for mechanism, label, points in (
        ("spf", "SPF Verification", 12),
        ("dkim", "DKIM Verification", 10),
        ("dmarc", "DMARC Alignment", 15),
    ):
        result = auth_result(authentication, mechanism)
        if result == "pass":
            checks.append(check_item(label, "Authentication", "pass", 0, f"{mechanism.upper()} passed according to the receiving mail system.", "No action required for this check."))
        elif result == "missing":
            checks.append(check_item(label, "Authentication", "warn", 4, f"No {mechanism.upper()} result was found in the available authentication headers.", "Confirm the result in Gmail's original-message view before trusting the sender."))
        else:
            checks.append(check_item(label, "Authentication", "fail", points, f"{mechanism.upper()} returned {result}.", "Treat the claimed sender identity as unverified."))

    reply_mismatch = reply_to and reply_domain and not same_domain_family(sender_domain, reply_domain)
    return_mismatch = return_domain and sender_domain and not same_domain_family(sender_domain, return_domain)
    if reply_mismatch:
        checks.append(check_item("Header Address Consistency", "Header forensics", "fail", 9, f"Replies are redirected from {sender_domain or 'the sender'} to {reply_domain}.", "Verify the reply address independently and do not respond from this message."))
    elif return_mismatch:
        checks.append(check_item("Header Address Consistency", "Header forensics", "warn", 4, f"The visible sender uses {sender_domain}, while the bounce path uses {return_domain}.", "Review whether the bounce domain belongs to an authorised mailing service."))
    else:
        checks.append(check_item("Header Address Consistency", "Header forensics", "pass", 0, "No unrelated Reply-To or Return-Path domain was detected.", "No action required for this check."))

    ips = public_ips(received)
    if received:
        checks.append(check_item("Sender Route & IP", "Network", "pass", 0, f"{len(received)} mail hops were found; {len(ips)} public IP address(es) were extracted for investigation.", "Use threat-intelligence enrichment before blocking an IP."))
    else:
        checks.append(check_item("Sender Route & IP", "Network", "warn", 5, "No Received routing chain was available.", "Inspect the original RFC 822 message before making a verdict."))

    domain_flags = []
    if sender_domain.startswith("xn--") or ".xn--" in sender_domain:
        domain_flags.append("punycode")
    if "\u202e" in sender or "\u202d" in sender:
        domain_flags.append("bidirectional Unicode")
    if domain_flags:
        checks.append(check_item("Sender Domain Safety", "Identity", "fail", 12, f"The sender identity contains {', '.join(domain_flags)} indicators.", "Verify the domain character-by-character and block confirmed impersonation."))
    else:
        checks.append(check_item("Sender Domain Safety", "Identity", "pass", 0, f"No punycode or bidirectional-text trick was detected in {sender_domain or 'the sender address'}.", "Continue with reputation and domain-age enrichment for production use."))

    combined = f"{subject}\n{plain_text}".lower()
    ml_analysis = run_ml_analysis(subject, plain_text)

    if not ml_analysis["available"]:
        checks.append(check_item(
            "Machine-Learning Classification",
            "AI model",
            "warn",
            0,
            "The trained phishing model was unavailable, so this message was assessed only by rule-based checks.",
            "Confirm that models/phishing_model.joblib exists and restart the API.",
        ))
    else:
        ml_probability = ml_analysis["phishing_probability"]
        probability_percent = round(ml_probability * 100, 2)

        if ml_probability >= 0.85:
            checks.append(check_item(
                "Machine-Learning Classification",
                "AI model",
                "fail",
                50,
                f"The trained model classified this email as phishing with a {probability_percent}% phishing probability.",
                "Treat the message as high risk and verify it through an independent channel.",
            ))
        elif ml_probability >= 0.60:
            checks.append(check_item(
                "Machine-Learning Classification",
                "AI model",
                "fail",
                25,
                f"The trained model found an elevated phishing probability of {probability_percent}%.",
                "Review the email headers, links, and request context before taking action.",
            ))
        elif ml_probability >= 0.40:
            checks.append(check_item(
                "Machine-Learning Classification",
                "AI model",
                "warn",
                10,
                f"The trained model produced an uncertain phishing probability of {probability_percent}%.",
                "Use the remaining forensic checks to resolve the uncertain model result.",
            ))
        else:
            checks.append(check_item(
                "Machine-Learning Classification",
                "AI model",
                "pass",
                0,
                f"The trained model produced a low phishing probability of {probability_percent}%.",
                "Continue reviewing the rule-based checks because a low model score is not a guarantee of safety.",
            ))

    urls = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>]+", html.unescape(f"{plain_text}\n{html_text}"), re.I)))
    suspicious_urls = []
    for url in urls:
        domain = (urlparse(url).hostname or "").lower()
        lowered = url.lower()
        if domain.startswith("xn--") or any(term in lowered for term in ("login", "verify", "password", "secure-account", "update-account")):
            suspicious_urls.append(url)
    if suspicious_urls:
        checks.append(check_item("URL & Redirect Indicators", "Content", "fail", 10, f"{len(suspicious_urls)} potentially credential-related or internationalised URL(s) were found.", "Do not open the links; enrich their final domains in an approved threat-intelligence service."))
    else:
        checks.append(check_item("URL & Redirect Indicators", "Content", "pass", 0, f"{len(urls)} URL(s) found; none matched the scanner's basic high-risk patterns.", "A production scanner should still follow redirects in isolation."))

    urgency_hits = sorted(term for term in URGENCY_TERMS if term in combined)
    if urgency_hits:
        checks.append(check_item("Urgency & Pressure Language", "Content", "warn", min(10, 3 + len(urgency_hits)), f"Pressure language detected: {', '.join(urgency_hits[:4])}.", "Verify the request using a trusted channel before acting."))
    else:
        checks.append(check_item("Urgency & Pressure Language", "Content", "pass", 0, "No common urgency or fear-based phrases were detected.", "No action required for this check."))

    data_hits = sorted(term for term in DATA_REQUEST_TERMS if term in combined)
    if data_hits:
        checks.append(check_item("Sensitive-Data Request", "Social engineering", "fail", min(12, 5 + len(data_hits)), f"The message references sensitive information: {', '.join(data_hits[:4])}.", "Do not provide credentials, OTPs, payment data, or identity documents by email."))
    else:
        checks.append(check_item("Sensitive-Data Request", "Social engineering", "pass", 0, "No common request for credentials or personal data was detected.", "Continue to review the request in context."))

    risky_attachments = []
    disguised_attachments = []
    for attachment in attachments:
        filename = attachment["filename"].lower()
        suffix = Path(filename).suffix
        if suffix in HIGH_RISK_EXTENSIONS:
            risky_attachments.append(attachment["filename"])
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|js|vbs|lnk)$", filename) or "\u202e" in filename:
            disguised_attachments.append(attachment["filename"])

    if disguised_attachments:
        checks.append(check_item("Attachment Type Safety", "Attachment", "fail", 18, f"Disguised executable-style filename detected: {disguised_attachments[0]}.", "Quarantine the attachment and submit it only to an isolated malware-analysis system."))
    elif risky_attachments:
        checks.append(check_item("Attachment Type Safety", "Attachment", "fail", 12, f"High-risk attachment type detected: {risky_attachments[0]}.", "Do not download or open it on a normal workstation."))
    else:
        checks.append(check_item("Attachment Type Safety", "Attachment", "pass", 0, f"{len(attachments)} attachment(s) identified; no high-risk extension was detected.", "File content must still be verified by magic bytes, hashes, YARA, and reputation checks."))

    obfuscation_terms = [term for term in ("display:none", "visibility:hidden", "<iframe", "<script", "font-size:0", "opacity:0") if term in html_text.lower()]
    if obfuscation_terms:
        checks.append(check_item("Hidden HTML Content", "Content", "warn", min(10, 3 + len(obfuscation_terms)), f"Potentially hidden or active HTML patterns detected: {', '.join(obfuscation_terms[:4])}.", "Render the message only in a sanitised analysis environment."))
    else:
        checks.append(check_item("Hidden HTML Content", "Content", "pass", 0, "No basic hidden iframe, script, or invisible-text pattern was detected.", "No action required for this check."))

    if message_id and "@" in message_id:
        checks.append(check_item("Message-ID Structure", "Header forensics", "pass", 0, "A syntactically plausible Message-ID is present.", "Retain it for mailbox hunting and evidence correlation."))
    else:
        checks.append(check_item("Message-ID Structure", "Header forensics", "warn", 4, "Message-ID is missing or has an unusual structure.", "Compare the message with other emails from the claimed sender."))

    total_score = min(100, sum(item["score"] for item in checks))
    if total_score >= 50:
        verdict = "Malicious"
        severity = "critical" if total_score >= 80 else "high"
    elif total_score >= 20:
        verdict = "Suspicious"
        severity = "medium"
    else:
        verdict = "Low risk"
        severity = "safe"

    return {
        "message_id": message["id"],
        "subject": subject or "(No subject)",
        "sender": sender,
        "score": total_score,
        "verdict": verdict,
        "severity": severity,
        "ml_analysis": ml_analysis,
        "checks": checks,
        "evidence": {
            "public_sender_ips": ips,
            "urls_found": len(urls),
            "attachments": attachments,
        },
        "limitations": [
            "This is a first-stage rule-based and machine-learning assessment, not a final SOC verdict.",
            "The text model was trained on public Nazario and Enron datasets and requires independent validation against newer email campaigns.",
            "IP/domain reputation, domain age, redirect following, YARA, and sandbox detonation are not yet enabled.",
            "Attachments are identified but are not downloaded or executed by this endpoint.",
        ],
    }


@app.get("/")
def home():
    return {
        "status": "online",
        "service": "PhishGuard Gmail Scanner",
        "version": "2.4",
        "ml_model_loaded": PHISHING_MODEL is not None,
        "scan_history": "persistent",
        "inbox_loading": "all_messages",
    }


@app.get("/api/messages")
def get_messages():
    gmail = get_gmail_service()
    references = []
    page_token = None
    while True:
        request = gmail.users().messages().list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=500,
            pageToken=page_token,
        )
        response = request.execute()
        references.extend(response.get("messages", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break

    scan_summaries = load_scan_summaries([reference["id"] for reference in references])
    emails = []
    for reference in references:
        message = gmail.users().messages().get(
            userId="me",
            id=reference["id"],
            format="metadata",
            metadataHeaders=["From", "To", "Subject", "Date"],
        ).execute()
        headers = message.get("payload", {}).get("headers", [])
        scan = scan_summaries.get(message["id"])
        emails.append({
            "id": message["id"],
            "threadId": message.get("threadId"),
            "from": first_header(headers, "From") or "Unknown sender",
            "to": first_header(headers, "To") or "Not available",
            "subject": first_header(headers, "Subject") or "(No subject)",
            "date": first_header(headers, "Date") or "Not available",
            "snippet": message.get("snippet", ""),
            "labels": message.get("labelIds", []),
            "scan": scan or {"status": "pending"},
        })

    return {"connected": True, "count": len(emails), "emails": emails}


@app.get("/api/messages/{message_id}/analysis")
def analyse_gmail_message(message_id: str, force: bool = False):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", message_id):
        raise HTTPException(status_code=400, detail="Invalid Gmail message ID")

    try:
        if not force:
            saved = load_saved_analysis(message_id)
            if saved is not None:
                return saved

        gmail = get_gmail_service()
        message = gmail.users().messages().get(
            userId="me", id=message_id, format="full"
        ).execute()
        return save_analysis(analyse_message(message))
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail="Unable to analyse the selected Gmail message") from error
