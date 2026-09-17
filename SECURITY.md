# Security, privacy and demonstration risks

## 1. Gmail access and privacy

The read-only OAuth token can read the connected mailbox. Although PhishGuard
does not request send, delete or modify permissions, message subjects, headers
and body text are still sensitive personal data.

Controls:

- Use a dedicated test Gmail account for the hackathon.
- Never commit or share `credentials.json`, `token.json`, `sender_token.json`,
  `scan_history.db`, raw MBOX files or exported results.
- Revoke the app under Google Account → Security → Third-party access after the
  demo if the connection is no longer needed.
- Do not connect an organisational mailbox without documented authorization,
  privacy review, retention rules and an incident-response process.

## 2. Local API exposure

The FastAPI service does not authenticate callers. If it is exposed on a LAN,
public IP, tunnel or permissive proxy, another party could retrieve mailbox
content through its endpoints.

Controls:

- Run Uvicorn on `127.0.0.1` only. Do not use `--host 0.0.0.0` for the demo.
- Keep the CORS allowlist restricted to the local frontend origins.
- Add authentication, TLS, authorization and audit logging before any shared or
  production deployment.

## 3. Phishing links and attachments

Historical corpora can contain live or compromised URLs and genuine malware.
Opening, forwarding, rendering or extracting them can cause compromise or
trigger security systems.

Controls:

- Use reserved `example.com` links for live demonstrations.
- Keep historical MBOX data offline and do not click its links.
- Never use real malware. Use safe files or the EICAR test string only where an
  authorized security team has approved it.
- Do not forward corpus messages through Gmail because that changes headers and
  may expose live indicators.

## 4. False positives and false negatives

Rules and ML probabilities can incorrectly block legitimate mail or miss
phishing, particularly business-email-compromise messages without links.

Controls:

- Present verdicts as analyst triage recommendations.
- Require human review before blocking senders, resetting accounts or reporting
  incidents.
- Display the triggered evidence and preserve an override/escalation path.
- Monitor precision and recall on newer, independent datasets.

## 5. Model and evaluation risk

Training/test overlap creates inflated results. Older corpora may not represent
current attacks, and email datasets can contain personal or copyrighted data.

Controls:

- Keep validation data separate from training data.
- Call the Nazario result `detection coverage`, not independent accuracy, if
  Nazario-derived messages were used for training.
- Record dataset origin, licence, date, class balance and preprocessing.
- Retrain and recalibrate against authorized, recent samples before production.

## 6. Persistence and retention

`scan_history.db` stores complete analysis JSON locally. Depending on the
analysis evidence, it may contain subjects, sender details, URLs or message
excerpts.

Controls:

- Encrypt the device and restrict filesystem access.
- Define retention and deletion rules.
- Avoid placing the project in a broadly synchronized folder when processing
  confidential mail.
- Remove the database and OAuth tokens after the hackathon if they are no longer
  required.

## 7. Demo-email reputation and provider controls

Sending many phishing-like messages can trigger Gmail anti-abuse controls,
temporarily restrict the sender, or damage its reputation.

Controls:

- Send small batches only between accounts you own and control.
- Clearly document the activity as an authorized simulation.
- Do not use credential-capture pages, active malicious links, impersonated real
  domains or real malware.
- Stop if Google warns, rate-limits or suspends either test account.

## 8. Production readiness

This package is a hackathon prototype. Production use requires threat-
intelligence services, attachment isolation, malware scanning, queueing,
authentication, role-based access control, encryption, secrets management,
monitoring, audit logs, data-protection assessment and legal approval.
