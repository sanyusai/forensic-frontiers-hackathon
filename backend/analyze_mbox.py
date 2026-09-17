"""Safely batch-analyse an MBOX file with the existing PhishGuard pipeline.

This script never opens URLs, renders HTML, or executes/extracts attachments.
It adapts MIME messages into the Gmail-like dictionary consumed by
api.analyse_message().
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import mailbox
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from api import analyse_message


def parse_message(file_object):
    """Parse one MBOX entry using Python's modern email policy."""
    return BytesParser(policy=policy.default).parse(file_object)


def encoded_text_body(part: Message) -> tuple[str | None, int]:
    """Return decoded text re-encoded as UTF-8 for the Gmail-style adapter."""
    if part.get_content_maintype() != "text":
        return None, 0

    try:
        content = part.get_content()
        if not isinstance(content, str):
            content = str(content)
    except Exception:
        raw = part.get_payload(decode=True) or b""
        charset = part.get_content_charset() or "utf-8"
        content = raw.decode(charset, errors="replace")

    raw_utf8 = content.encode("utf-8", errors="replace")
    encoded = base64.urlsafe_b64encode(raw_utf8).decode("ascii").rstrip("=")
    return encoded, len(raw_utf8)


def to_gmail_part(part: Message) -> dict[str, Any]:
    """Convert a MIME part into the subset of Gmail payload fields we use."""
    filename = part.get_filename() or ""
    child_parts = []
    if part.is_multipart():
        child_parts = [to_gmail_part(child) for child in part.iter_parts()]

    body_data, decoded_size = encoded_text_body(part)
    raw_payload = part.get_payload(decode=True) or b""
    body: dict[str, Any] = {
        "size": decoded_size if body_data is not None else len(raw_payload)
    }
    if body_data is not None and not filename:
        body["data"] = body_data

    converted: dict[str, Any] = {
        "mimeType": part.get_content_type(),
        "filename": filename,
        "headers": [
            {"name": str(name), "value": str(value)}
            for name, value in part.items()
        ],
        "body": body,
    }
    if child_parts:
        converted["parts"] = child_parts
    return converted


def to_gmail_message(message: Message, sequence: int) -> dict[str, Any]:
    return {
        "id": f"mbox-{sequence:06d}",
        "threadId": f"mbox-{sequence:06d}",
        "labelIds": ["OFFLINE_MBOX"],
        "snippet": "",
        "payload": to_gmail_part(message),
    }


def probability_from(result: dict[str, Any]) -> float | None:
    value = result.get("ml_analysis", {}).get("phishing_probability")
    return round(float(value) * 100, 2) if value is not None else None


def analyse_mbox(mbox_path: Path, output_dir: Path, limit: int) -> None:
    if not mbox_path.is_file():
        raise FileNotFoundError(f"MBOX file not found: {mbox_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "nazario_analysis_summary.csv"
    detail_path = output_dir / "nazario_analysis_details.jsonl"

    box = mailbox.mbox(
        str(mbox_path),
        factory=parse_message,
        create=False,
    )

    summary_rows: list[dict[str, Any]] = []
    verdict_counts: dict[str, int] = {}
    errors = 0

    with detail_path.open("w", encoding="utf-8") as detail_file:
        for index, message in enumerate(box, start=1):
            if limit and index > limit:
                break

            try:
                adapted = to_gmail_message(message, index)
                result = analyse_message(adapted)
                detail_file.write(json.dumps(result, ensure_ascii=False) + "\n")

                verdict = result.get("verdict", "Unknown")
                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                summary_rows.append(
                    {
                        "message_id": result.get("message_id"),
                        "subject": result.get("subject"),
                        "sender": result.get("sender"),
                        "score": result.get("score"),
                        "verdict": verdict,
                        "severity": result.get("severity"),
                        "ml_phishing_probability_percent": probability_from(result),
                        "urls_found": result.get("evidence", {}).get("urls_found", 0),
                        "attachment_count": len(
                            result.get("evidence", {}).get("attachments", [])
                        ),
                    }
                )
            except Exception as error:
                errors += 1
                print(f"Skipped message {index}: {error}")

            if index % 25 == 0:
                print(f"Processed {index} messages...")

    fieldnames = [
        "message_id",
        "subject",
        "sender",
        "score",
        "verdict",
        "severity",
        "ml_phishing_probability_percent",
        "urls_found",
        "attachment_count",
    ]
    with summary_path.open("w", newline="", encoding="utf-8-sig") as summary_file:
        writer = csv.DictWriter(summary_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(summary_rows)

    print("\nPHISHGUARD OFFLINE MBOX ANALYSIS")
    print("=" * 35)
    print(f"Successfully analysed: {len(summary_rows)}")
    print(f"Parsing/analysis errors: {errors}")
    for verdict, count in sorted(verdict_counts.items()):
        print(f"{verdict}: {count}")
    print(f"\nSummary: {summary_path}")
    print(f"Full details: {detail_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a safe offline PhishGuard analysis over an MBOX corpus."
    )
    parser.add_argument(
        "--mbox",
        type=Path,
        default=Path("offline_data/nazario/phishing3.mbox"),
        help="Path to the MBOX file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("offline_results/nazario"),
        help="Directory for CSV and JSONL results.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum messages to analyse; use 0 for the entire MBOX.",
    )
    arguments = parser.parse_args()
    analyse_mbox(arguments.mbox, arguments.output, arguments.limit)


if __name__ == "__main__":
    main()
