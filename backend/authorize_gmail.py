"""Create the read-only Gmail OAuth token used by PhishGuard."""

from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow


BASE_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = BASE_DIR / "credentials.json"
TOKEN_FILE = BASE_DIR / "token.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def main() -> None:
    if not CREDENTIALS_FILE.exists():
        raise FileNotFoundError(
            "credentials.json is missing. Download an OAuth Desktop client from "
            "Google Cloud and place it in the backend folder."
        )

    flow = InstalledAppFlow.from_client_secrets_file(
        str(CREDENTIALS_FILE), SCOPES
    )
    credentials = flow.run_local_server(port=0)
    TOKEN_FILE.write_text(credentials.to_json(), encoding="utf-8")
    print(f"Gmail read-only authorization saved to {TOKEN_FILE}")


if __name__ == "__main__":
    main()
