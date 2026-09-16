# forensic-frontiers-hackathon

# 🛡️ Unified Phishing Email & Malware Attachment Detection Framework

> **AI-Assisted DFIR Platform for Phishing Email Detection, Malware Attachment Analysis, Risk Assessment, and Security Reporting**

An integrated cybersecurity platform that combines **email forensics**, **malware attachment analysis**, **threat intelligence**, **risk correlation**, and **AI-assisted security reporting** into a single investigation workflow.

Instead of analyzing an email and its attachment as two independent problems, the system correlates evidence from both and produces a **single, explainable Composite Risk Score** with detailed findings, Indicators of Compromise (IOCs), and recommended remediation steps.

---

## 🎯 Problem Statement

Phishing emails and malicious attachments are commonly used to gain an initial foothold in organizations.

Traditional email security tools may focus primarily on sender authentication, URLs, or email content, while malware scanners focus on the attached file. This can result in fragmented analysis where an analyst has to manually correlate multiple findings.

This project addresses that problem through a unified DFIR pipeline:

```text
Email Ingestion
      │
      ├──────────────────────┐
      ▼                      ▼
Email Analysis        Attachment Analysis
      │                      │
      ▼                      ▼
Trust Score           Threat Score
      │                      │
      └──────────┬───────────┘
                 ▼
       Correlation Engine
                 │
                 ▼
       Composite Risk Score
                 │
                 ▼
       AI-Assisted Analysis
                 │
                 ▼
       DFIR Risk Assessment
                 │
                 ▼
       Report + IOCs + Actions
```

The architecture is designed around a single case and evidence trail so that email headers, metadata, attachment hashes, YARA findings, and other indicators can be correlated under one investigation.

---

# 🚀 Core Features

## 📥 1. Inbox

The Inbox provides a centralized interface for viewing emails retrieved from a connected mailbox or controlled demonstration mailbox.

### Features

* Email listing
* Sender and recipient information
* Subject and timestamp
* Attachment detection
* Email search/filtering
* Analysis status
* Risk/severity indicator
* Select an email to initiate forensic analysis

### Planned Integrations

* Gmail API
* Microsoft Graph API
* IMAP
* Mail gateway / ingestion hooks

The underlying architecture supports mailbox feeds, APIs, IMAP polling, and mail-server/gateway integration.

---

# 🔍 2. Email Analysis Engine

The Email Analysis Engine performs a structured forensic examination of the selected email.

Instead of simply returning:

> "This email is phishing."

the application executes a series of individual security checks and displays the result of each check.

Each test provides:

```text
✓ PASS
⚠ SUSPICIOUS
✗ FAIL
```

along with:

* Technical finding
* Risk contribution
* Explanation
* Evidence
* Recommended action

---

## 🧪 Email Security Checklist

The analysis engine can evaluate parameters including:

### Sender & Authentication

* SPF verification
* DKIM verification
* DMARC verification
* Sender authenticity
* Display-name spoofing
* From / Reply-To mismatch
* Return-Path analysis
* Message-ID analysis
* Received-chain analysis
* Sender IP analysis

### Domain & Identity

* Domain reputation
* Domain age
* WHOIS information
* Organization impersonation
* Lookalike-domain detection
* Typosquatting detection
* Homograph / Punycode detection
* Levenshtein/fuzzy domain similarity

### URL & Content

* URL extraction
* URL reputation
* Redirect-chain analysis
* SSL certificate inspection
* Suspicious destination detection
* Urgency detection
* Social-engineering language
* Credential/data-request detection
* Hidden or obfuscated HTML
* QR-code phishing detection

### Metadata & Forensics

* Embedded file/image metadata
* Timestamp inconsistencies
* GPS/author metadata
* Hash inconsistencies
* Sender behavior anomalies

The enhanced detection parameters include display-name spoofing, Reply-To mismatch, homograph domains, domain age, sender behavior baselines, redirect analysis, SSL inspection, QR-code phishing, hidden HTML, and RTLO filename tricks.

---

## 📊 Email Trust Score

The Email Analysis Engine produces a **Trust Score from 0–100** along with structured indicators explaining how the score was calculated.

Example:

```text
EMAIL TRUST SCORE

       24 / 100

       🔴 HIGH RISK
```

Example finding:

```text
✗ DMARC Verification

Status:
FAIL

Risk Contribution:
+15

Finding:
The message failed DMARC authentication.

Explanation:
The sender domain could not be authenticated
according to its configured DMARC policy.

Recommendation:
Treat the sender identity as untrusted.
```

The objective is to make every detection **explainable rather than a black-box classification**.

---

# 🦠 3. Malware Attachment Analysis Engine

When an email contains an attachment, the attachment can be passed to the Malware Analysis Engine.

The system performs static analysis first and can optionally integrate with an isolated sandbox for dynamic analysis.

```text
Attachment
     │
     ▼
File Identification
     │
     ▼
Hash Generation
     │
     ▼
Static Analysis
     │
     ├── YARA
     ├── Entropy
     ├── PE Analysis
     ├── Metadata
     ├── Macros
     ├── Embedded Objects
     └── Strings
     │
     ▼
Threat Intelligence
     │
     ▼
Threat Score
```

---

## 🔬 Malware Analysis Checklist

### File Identification

* File extension validation
* Magic-byte verification
* Extension spoofing detection
* File-type mismatch detection

### Hash Analysis

* MD5
* SHA-256
* Fuzzy hashing
* Internal case-history lookup
* Threat-intelligence reputation

### Static Malware Analysis

* YARA rule matching
* Entropy analysis
* PE header inspection
* Import analysis
* Section analysis
* Import hash / imphash
* Digital signature validation
* Suspicious strings
* Macro/VBA extraction
* Embedded object analysis
* OLE/DDE checks

### Delivery-Trick Detection

* Password-protected archives
* Nested archives
* Archive-bomb indicators
* ISO/IMG disk-image files
* LNK shortcut analysis
* Script obfuscation
* PowerShell/VBS/JavaScript analysis
* Base64 / encoded command detection
* RTLO filename tricks

The enhancement addendum specifically expands the attachment engine beyond YARA by adding entropy, PE inspection, digital signatures, Office macro analysis, embedded-object checks, archive analysis, ISO/IMG detection, LNK analysis, script deobfuscation, and fuzzy hashing.

---

# 🧬 Malware Classification

YARA-based classification can categorize suspicious samples into families/classes such as:

```text
Trojan
Worm
Ransomware
RAT
Botnet
Adware
Generic Malware
Fileless Malware
```

The system can produce:

```text
THREAT SCORE

       94 / 100

       🔴 MALICIOUS

Classification:
Trojan / Downloader

YARA Matches:
3

SHA-256:
xxxxxxxxxxxxxxxx...
```

The framework specifies a Threat Classification Score together with malware-family classification and an IOC list.

---

# 🧪 Sandbox Analysis

A sandbox is planned as an isolated analysis environment for controlled dynamic malware analysis.

```text
                  Attachment
                      │
                      ▼
              ┌───────────────┐
              │ Isolated      │
              │ Sandbox       │
              ├───────────────┤
              │ Process       │
              │ Network       │
              │ Files         │
              │ Registry      │
              │ Persistence   │
              └───────┬───────┘
                      │
                      ▼
              Behavioral IOCs
```

Potential future implementations include:

* Cuckoo Sandbox
* Container/VM-based isolated detonation environment

Sandboxing is intentionally treated as a later-stage capability rather than a dependency for the core MVP.

**Safety principle:** arbitrary attachments should never be executed directly on the host system.

---

# 🔗 4. Correlation & Unified Risk Engine

This is the central component that connects the email and malware scanners.

Instead of producing two unrelated results:

```text
Email:
Suspicious

Attachment:
Malicious
```

the system correlates the evidence into:

```text
                 EMAIL
                   │
            Trust Score
                   │
                   ▼
             ┌───────────┐
             │           │
             │ CORRELATE │
             │           │
             └───────────┘
                   ▲
                   │
          Threat Classification
                   │
              ATTACHMENT
                   │
                   ▼

        COMPOSITE RISK SCORE
```

---

## ⚖️ Suggested Risk Model

The initial framework proposes the following weighting:

| Component                    | Weight |
| ---------------------------- | -----: |
| Sender / Header Trust        |    25% |
| Content / Social Engineering |    15% |
| Metadata Inconsistency       |    10% |
| Attachment Presence & Type   |    15% |
| YARA Classification Severity |    25% |
| Reputation / Known-Bad Match |    10% |

Weights can be tuned for different organizational environments.

Known-malicious hashes or severe malware classifications can trigger an override rule so that a confirmed malicious attachment is not diluted by a relatively normal-looking email.

---

# 🧠 AI-Assisted Security Analyst

AI is used as an **analysis and explanation layer**, rather than replacing deterministic security controls.

The AI receives structured findings from the detection engines.

Example:

```json
{
  "spf": "FAIL",
  "dkim": "FAIL",
  "dmarc": "FAIL",
  "domain_similarity": 0.94,
  "yara_matches": 3,
  "known_bad_hash": true,
  "attachment_type": "PE"
}
```

The AI can then produce an analyst-friendly explanation:

```text
Verdict: MALICIOUS

Primary Findings:

1. Sender authentication failed.
2. The sender domain resembles a trusted domain.
3. The attachment is a Windows PE executable.
4. Multiple YARA rules were triggered.
5. The file hash has a malicious reputation.

Recommended Actions:

• Quarantine the message.
• Investigate other messages containing the same hash.
• Block associated malicious infrastructure.
• Review potentially affected endpoints.
```

This allows the underlying security detections to remain evidence-based while AI assists with interpretation, summarization, and reporting.

---

# 📋 5. Risk Assessment & DFIR Report Generation

Every investigation is associated with a unique **Case ID**.

Example:

```text
CASE ID: MS-2026-00421
```

The report generator combines evidence from:

* Email analysis
* Header analysis
* URL analysis
* Domain analysis
* Attachment analysis
* Hash analysis
* YARA results
* Threat intelligence
* Risk correlation
* AI-generated explanation

---

## 📄 Report Structure

Generated reports follow a professional security-assessment format:

```text
SECURITY INCIDENT REPORT

Case ID
Timestamp
Severity
Overall Verdict

1. Executive Summary

2. Incident Overview

3. Email Analysis

4. Sender & Header Analysis

5. Authentication Results

6. Domain & URL Analysis

7. Social Engineering Analysis

8. Attachment Analysis

9. Malware Analysis

10. Threat Intelligence

11. Indicators of Compromise

12. Risk Assessment

13. Findings & Evidence

14. Recommended Remediation

15. Incident Response Actions

16. Chain of Custody / Audit Trail
```

Example final assessment:

```text
╔══════════════════════════════════╗
║       COMPOSITE RISK SCORE      ║
║                                  ║
║             96 / 100             ║
║                                  ║
║            🔴 MALICIOUS          ║
╚══════════════════════════════════╝
```

The report includes the overall verdict, evidence summary, malware profile, remediation guidance, Case ID, and timestamped audit trail.

---

# 🧾 Indicators of Compromise

The platform extracts and presents IOCs such as:

### Domains

```text
example-malicious-domain.com
```

### IP Addresses

```text
185.xxx.xxx.xxx
```

### URLs

```text
hxxps://example.com/login
```

### File Hashes

```text
SHA-256:
xxxxxxxxxxxxxxxxxxxxxxxx
```

### Malware Indicators

```text
YARA rule matches
Suspicious imports
C2 indicators
Dropped files
Persistence mechanisms
```

Sandbox-derived behavioral IOCs can be incorporated once dynamic analysis is implemented.

---

# 🛠️ Recommended Technology Stack

## Frontend

```text
Next.js
React
TypeScript
Tailwind CSS
Recharts
```

## Backend

```text
Python
FastAPI
```

## Email Processing

```text
Python email
mailparser
IMAP
Gmail API
Microsoft Graph API
```

## Security Analysis

```text
YARA / yara-python
libmagic
ExifTool
hashlib
Levenshtein / fuzzy matching
```

## Malware Analysis

```text
YARA
PE analysis
Entropy analysis
Fuzzy hashing
Optional sandbox
```

## Machine Learning / NLP

```text
scikit-learn
Hugging Face Transformers
```

## Threat Intelligence

```text
VirusTotal
AbuseIPDB
WHOIS
MISP
OTX
```

## Database

```text
PostgreSQL
```

or for the prototype:

```text
SQLite
```

## Reporting

```text
HTML / PDF report generation
```

## The original framework recommends Python-based email processing, YARA, ExifTool, libmagic, threat-intelligence APIs, a lightweight ML/rules engine, and SQLite/Postgres.

# 🏗️ System Architecture

```text
                         ┌─────────────────────┐
                         │   Gmail / Outlook   │
                         │   IMAP / Mail Feed  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   INGESTION LAYER   │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
          ┌─────────────────────┐        ┌─────────────────────┐
          │ EMAIL ANALYSIS      │        │ ATTACHMENT ANALYSIS │
          │                     │        │                     │
          │ SPF / DKIM / DMARC  │        │ File Type           │
          │ Headers             │        │ Magic Bytes         │
          │ Sender IP           │        │ SHA-256             │
          │ Domain              │        │ YARA                │
          │ URLs                │        │ PE Analysis         │
          │ Social Engineering  │        │ Entropy             │
          │ Metadata            │        │ Macros              │
          │ Impersonation       │        │ Reputation           │
          └──────────┬──────────┘        └──────────┬──────────┘
                     │                              │
                     ▼                              ▼
              ┌────────────┐                ┌────────────┐
              │ Trust Score│                │Threat Score│
              └──────┬─────┘                └──────┬─────┘
                     │                              │
                     └──────────────┬───────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ CORRELATION ENGINE  │
                         │                     │
                         │ Unified Risk Score  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ AI SECURITY ANALYST │
                         │                     │
                         │ Explanation         │
                         │ Correlation         │
                         │ Recommendations     │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
             ┌────────────┐  ┌────────────┐  ┌────────────┐
             │   REPORT   │  │    IOCs    │  │  ACTIONS   │
             │  GENERATOR │  │   EXPORT   │  │            │
             └────────────┘  └────────────┘  └────────────┘
```

The unified architecture is intentionally designed so that the email and attachment engines operate in parallel before their results are fused by the correlation engine.

---

# 📁 Proposed Project Structure

```text
.
├── frontend/
│   ├── app/
│   ├── components/
│   ├── dashboard/
│   ├── inbox/
│   ├── email-analysis/
│   ├── malware-analyzer/
│   └── reports/
│
├── backend/
│   ├── app/
│   │   ├── ingestion/
│   │   ├── email_analysis/
│   │   ├── attachment_analysis/
│   │   ├── threat_intel/
│   │   ├── correlation/
│   │   ├── ai/
│   │   ├── reporting/
│   │   └── models/
│   │
│   └── tests/
│
├── yara_rules/
│   ├── ransomware.yar
│   ├── trojan.yar
│   ├── downloader.yar
│   └── suspicious_scripts.yar
│
├── datasets/
│
├── reports/
│
├── docs/
│
├── .env.example
├── docker-compose.yml
└── README.md
```

---

# 🔄 End-to-End Investigation Workflow

```text
1. Email arrives
        ↓
2. Email appears in Inbox
        ↓
3. Analyst selects email
        ↓
4. Email Analysis Engine starts
        ↓
5. Authentication / Header / URL /
   Domain / Content / Metadata checks
        ↓
6. Trust Score generated
        ↓
7. Attachment extracted
        ↓
8. Malware Analysis Engine starts
        ↓
9. Static analysis + YARA +
   Hash + File analysis
        ↓
10. Threat Score generated
        ↓
11. Evidence correlation
        ↓
12. Composite Risk Score
        ↓
13. AI-assisted explanation
        ↓
14. DFIR report generated
        ↓
15. IOCs extracted
        ↓
16. Recommended response actions
```

All artifacts can be associated with the same Case ID to maintain a consistent investigation and audit trail.

---

# 🎯 Hackathon MVP

The initial prototype should prioritize a working end-to-end flow rather than implementing every advanced feature.

### MVP

* [x] Email ingestion / `.eml` upload
* [x] Email parsing
* [x] Header analysis
* [x] SPF/DKIM/DMARC checks
* [x] Sender/IP analysis
* [x] URL/domain analysis
* [x] Phishing/social-engineering detection
* [x] Attachment extraction
* [x] File-type validation
* [x] SHA-256 hashing
* [x] YARA scanning
* [x] Basic threat-intelligence lookup
* [x] Email Trust Score
* [x] Attachment Threat Score
* [x] Unified Composite Risk Score
* [x] Explainable findings
* [x] IOC extraction
* [x] DFIR-style report generation
* [ ] Gmail / Outlook live integration
* [ ] Dynamic sandbox
* [ ] Advanced ML classifier
* [ ] Automated quarantine

The hackathon framework specifically recommends prioritizing header parsing, IP reputation, YARA classification, scoring, and report generation, while deferring sandboxing to future work.

---

# 🔮 Future Enhancements

## 🧪 Dynamic Malware Sandbox

Add isolated execution and behavioral analysis for suspicious attachments.

Potential outputs:

```text
Process Tree
Network Connections
DNS Requests
Dropped Files
Registry Changes
Persistence
C2 Infrastructure
```

---

## 🤖 ML-Based Phishing Detection

Train/fine-tune a phishing classifier to complement deterministic rules.

Possible approach:

```text
Email Body
     ↓
Transformer / NLP Model
     ↓
Phishing Probability
     ↓
Risk Engine
```

---

## 🌐 Real-Time Threat Intelligence

Integrate:

* MISP
* OTX
* VirusTotal
* AbuseIPDB
* Other organizational/commercial feeds

The enhancement framework recommends external threat-intelligence integration so detection is not limited to historical organizational data.

---

## 🔁 Analyst Feedback Loop

Allow analysts to select:

```text
✓ Correct Detection

✗ False Positive

✗ False Negative
```

Feedback can later be used to tune scoring weights and improve detection.

---

## 🏢 Organization-Specific Policies

Allow organizations to configure:

* Risk thresholds
* Trusted domains
* Allow-lists
* False-positive tolerance
* Scoring weights
* Automatic response policies

## Different organizations may require different detection sensitivities and thresholds.

# 🔐 Security Considerations

This project is intended for **authorized security analysis and controlled environments**.

Important design principles:

* Never execute untrusted attachments directly on the host.
* Use isolated environments for dynamic analysis.
* Do not expose malware samples through public web endpoints.
* Restrict sandbox networking.
* Store sensitive mailbox credentials securely.
* Use read-only mailbox access where possible.
* Sanitize uploaded files and metadata.
* Keep investigation artifacts associated with Case IDs.
* Maintain audit logs for security investigations.
* Never expose API keys in frontend code.

---

# 📊 Example Detection Scenario

### Incoming Email

```text
From:
security@paypa1-support.com

Subject:
URGENT: Your account will be suspended
```

### Email Analysis

```text
SPF                  ✗ FAIL
DKIM                 ✗ FAIL
DMARC                ✗ FAIL
Display Name         ⚠ SUSPICIOUS
Domain Similarity    ✗ DETECTED
URL Analysis         ✗ SUSPICIOUS
Social Engineering   ✗ DETECTED
```

```text
Email Trust Score:
18 / 100
```

### Attachment

```text
invoice.pdf.exe
```

Analysis:

```text
Extension Check      ✗ FAIL
Magic Bytes          ✗ PE
SHA-256              Generated
YARA                 ✗ 3 MATCHES
Entropy              ⚠ HIGH
Reputation           ✗ MALICIOUS
```

```text
Threat Score:
96 / 100
```

### Correlation

```text
Email Trust
     +
Attachment Threat
     +
Threat Intelligence
     ↓
Composite Risk
     ↓
97 / 100
     ↓
🔴 MALICIOUS
```

### Final Recommendation

```text
• Quarantine the email
• Block associated malicious infrastructure
• Search for matching SHA-256 across endpoints
• Investigate other recipients
• Reset credentials if credential harvesting occurred
• Preserve the email and attachment as investigation evidence
```

---

# 📈 Project Vision

The long-term goal is to evolve this prototype into an **analyst-centric email threat investigation platform** capable of moving from:

```text
Detection
   ↓
Analysis
   ↓
Correlation
   ↓
Risk Assessment
   ↓
Response
   ↓
DFIR Evidence
```

The platform can eventually provide SOC teams with organization-wide dashboards for campaign clustering, targeted users, malware families, recurring infrastructure, and historical investigations.

---

# 👥 Intended Users

* SOC Analysts
* DFIR Analysts
* Incident Responders
* Security Operations Teams
* Cybersecurity Researchers
* Enterprise Security Teams
* Security Students / Training Labs

---

# ⚠️ Project Status

> 🚧 **Prototype / Hackathon Project**

The current implementation focuses on demonstrating the integrated detection and DFIR workflow. Advanced capabilities such as full mailbox integration, dynamic sandboxing, large-scale ML classification, and automated response are planned enhancements.

---

# 📚 Project Documentation

The architecture and feature design of this project are based on the following internal project frameworks:

* **Phishing Email & Malware Attachment Forensic Scanner — Hackathon Framework**
* **Unified Phishing Email & Malware Attachment Detection Framework**
* **Module 1 & 2 Enhancement Parameters Addendum**

These documents define the core email-analysis, attachment-analysis, correlation, reporting, threat-intelligence, explainability, and future-enhancement requirements used to guide the project.

---

# ⚡ Quick Concept

```text
                    📧 EMAIL
                       │
          ┌────────────┴────────────┐
          │                         │
          ▼                         ▼
   🔍 EMAIL FORENSICS        🦠 MALWARE ANALYSIS
          │                         │
          ▼                         ▼
    TRUST SCORE              THREAT SCORE
          │                         │
          └────────────┬────────────┘
                       ▼
                🔗 CORRELATION
                       │
                       ▼
               🎯 RISK SCORE
                       │
                       ▼
                🤖 AI ANALYST
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
          📄 REPORT   IOCs    🚨 RESPONSE
```

> **Detect. Correlate. Explain. Respond.**
