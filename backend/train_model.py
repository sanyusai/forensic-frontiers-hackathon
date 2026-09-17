"""Train the optional PhishGuard text classifier from labelled CSV files.

Expected columns default to `email_text` and `label`, where labels are either
0/1 or names such as legitimate/phishing. Use command-line options if a source
dataset uses different column names.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


LABEL_MAP = {
    "0": 0,
    "legitimate": 0,
    "safe": 0,
    "ham": 0,
    "benign": 0,
    "1": 1,
    "phishing": 1,
    "phish": 1,
    "malicious": 1,
    "spam": 1,
}


def normalize_label(value: object) -> int:
    key = str(value).strip().lower()
    if key not in LABEL_MAP:
        raise ValueError(f"Unsupported label: {value!r}")
    return LABEL_MAP[key]


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the PhishGuard classifier")
    parser.add_argument("csv", nargs="+", type=Path, help="labelled CSV file(s)")
    parser.add_argument("--text-column", default="email_text")
    parser.add_argument("--label-column", default="label")
    parser.add_argument(
        "--output", type=Path, default=Path("models/phishing_model.joblib")
    )
    args = parser.parse_args()

    frames = [pd.read_csv(path) for path in args.csv]
    data = pd.concat(frames, ignore_index=True)
    required = {args.text_column, args.label_column}
    missing = required.difference(data.columns)
    if missing:
        raise ValueError(f"Missing CSV columns: {sorted(missing)}")

    data = data.dropna(subset=list(required)).copy()
    text = data[args.text_column].astype(str)
    labels = data[args.label_column].map(normalize_label)
    if labels.nunique() != 2:
        raise ValueError("Training data must contain both legitimate and phishing samples")

    train_text, test_text, train_labels, test_labels = train_test_split(
        text,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )
    model = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=100_000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1_000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )
    model.fit(train_text, train_labels)
    predictions = model.predict(test_text)
    print(classification_report(test_labels, predictions, target_names=["Legitimate", "Phishing"]))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)
    print(f"Model saved to {args.output.resolve()}")


if __name__ == "__main__":
    main()
