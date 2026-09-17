# PhishGuard DFIR — VS Code project

PhishGuard is a hackathon prototype for explainable phishing-email analysis. It
combines a React/Vinext interface with a local FastAPI service that reads Gmail
through OAuth, evaluates message headers and content, applies an optional text
classifier, and stores completed results in SQLite so messages are not scanned
again unnecessarily.

## Project structure

```text
phishguard-vscode/
├── frontend/                     React/Vinext user interface
├── backend/
│   ├── api.py                    Gmail connector and analysis API (v2.4)
│   ├── authorize_gmail.py        creates the read-only Gmail token
│   ├── train_model.py            optional TF-IDF/logistic-regression trainer
│   ├── validate_model.py         validation metrics and error analysis
│   ├── analyze_mbox.py           safe offline MBOX batch analyser
│   ├── requirements.txt
│   ├── models/
│   │   └── phishing_model.joblib (add your existing model)
│   └── validation_data/
└── tools/
    └── gmail_phishing_test_pack.csv
```

## Prerequisites

- Visual Studio Code
- Python 3.11 or newer
- Node.js 22.13 or newer
- A Google Cloud project with Gmail API enabled
- An OAuth 2.0 **Desktop app** client downloaded as `credentials.json`
- The test Gmail address added under Google OAuth **Test users**

## 1. Open the project

Extract the ZIP, open VS Code, and select **File → Open Folder**. Choose the
extracted `phishguard-vscode` directory.

## 2. Set up the backend

Open a VS Code terminal and run:

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
```

Copy your Google OAuth Desktop client file to:

```text
backend\credentials.json
```

Copy your existing trained model to:

```text
backend\models\phishing_model.joblib
```

Create the read-only Gmail token:

```powershell
python authorize_gmail.py
```

Choose the Gmail inbox that PhishGuard should read. The generated `token.json`
stays on your computer and must never be committed or shared.

Start the API:

```powershell
uvicorn api:app --reload --port 8000
```

Verify it at <http://127.0.0.1:8000>. It should show version `2.4`, persistent
scan history, and `all_messages` inbox loading.

## 3. Set up the frontend

Open a second VS Code terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local address displayed by the command, normally
<http://127.0.0.1:5173>. Select **Connect Gmail** or **Refresh Inbox**. The API
loads every message carrying Gmail's `INBOX` label by following all result
pages. Spam, Trash, Sent and archived-only messages are excluded.

## 4. Demonstrate the code during the hackathon

Useful files to show:

- `frontend/app/page.tsx`: inbox, analysis workflow, risk presentation and reports.
- `frontend/app/globals.css`: the complete interface design.
- `backend/api.py`: Gmail pagination, MIME parsing, security checks, scoring,
  ML inference, SQLite persistence and API routes.
- `backend/train_model.py`: reproducible text-classifier training.
- `backend/analyze_mbox.py`: offline Nazario MBOX processing.
- `backend/validate_model.py`: accuracy, precision, recall, F1 and confusion matrix.

The strongest live demonstration is one legitimate message and one controlled
phishing simulation, followed by the stored scan result and Nazario batch
summary. Do not claim the Nazario result as independent model accuracy if that
corpus contributed to training.

## Optional model training

Prepare one or more CSV files with `email_text` and `label` columns. Labels may
be `0/1`, `legitimate/phishing`, or `ham/spam`. From the backend folder:

```powershell
python train_model.py training_data\emails.csv
```

Never train with the independent validation CSV. Keep training and validation
sets separate to avoid data leakage.

## Validation

With the trained model in place:

```powershell
python validate_model.py
```

This calculates accuracy, precision, recall, F1 score, a confusion matrix and
the list of incorrectly classified samples.

## Important prototype limitations

- A risk score is decision support, not proof that an email is malicious.
- Gmail-authenticated phishing can pass SPF, DKIM and DMARC.
- Reputation lookups, domain age, redirect traversal and real sandbox
  detonation are not implemented.
- Attachments are identified by metadata but are not downloaded or executed.
- The local API has no user authentication and must remain bound to localhost.
- Loading a very large Inbox can be slow and consume Gmail API quota because
  metadata is retrieved for every message.

See `SECURITY.md` before using real organisational mail.
