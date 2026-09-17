from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"
DATA_PATH = BASE_DIR / "validation_data" / "phishguard_sample_emails.csv"
RESULTS_PATH = BASE_DIR / "validation_data" / "validation_results.csv"


def main():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Validation dataset not found: {DATA_PATH}")

    print(f"Loading model: {MODEL_PATH}")
    model = joblib.load(MODEL_PATH)

    print(f"Loading validation data: {DATA_PATH}")
    data = pd.read_csv(DATA_PATH)

    required_columns = {"id", "email_text", "label", "label_name"}
    missing = required_columns.difference(data.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    data = data.dropna(subset=["email_text", "label"]).copy()
    data["email_text"] = data["email_text"].astype(str)
    data["label"] = data["label"].astype(int)

    actual = data["label"]
    predicted = model.predict(data["email_text"])

    if hasattr(model, "predict_proba"):
        class_positions = {int(label): index for index, label in enumerate(model.classes_)}
        phishing_index = class_positions.get(1)
        if phishing_index is None:
            raise ValueError("The model does not contain phishing class 1.")
        phishing_probability = model.predict_proba(data["email_text"])[:, phishing_index]
    else:
        phishing_probability = [float(value) for value in predicted]

    data["predicted_label"] = predicted.astype(int)
    data["predicted_name"] = data["predicted_label"].map(
        {0: "Legitimate", 1: "Phishing"}
    )
    data["phishing_probability"] = phishing_probability
    data["phishing_probability_percent"] = (
        data["phishing_probability"] * 100
    ).round(2)
    data["correct"] = data["label"] == data["predicted_label"]

    accuracy = accuracy_score(actual, predicted)
    precision = precision_score(actual, predicted, zero_division=0)
    recall = recall_score(actual, predicted, zero_division=0)
    f1 = f1_score(actual, predicted, zero_division=0)
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])

    print("\nPHISHGUARD VALIDATION RESULTS")
    print("=" * 34)
    print(f"Samples:   {len(data)}")
    print(f"Correct:   {int(data['correct'].sum())}")
    print(f"Incorrect: {int((~data['correct']).sum())}")
    print(f"Accuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")
    print(f"F1 score:  {f1:.2%}")

    print("\nConfusion matrix [[TN, FP], [FN, TP]]:")
    print(matrix)

    print("\nClassification report:")
    print(
        classification_report(
            actual,
            predicted,
            labels=[0, 1],
            target_names=["Legitimate", "Phishing"],
            zero_division=0,
        )
    )

    mistakes = data.loc[
        ~data["correct"],
        [
            "id",
            "subject",
            "label_name",
            "predicted_name",
            "phishing_probability_percent",
        ],
    ]
    if mistakes.empty:
        print("No misclassified samples.")
    else:
        print("Misclassified samples:")
        print(mistakes.to_string(index=False))

    data.to_csv(RESULTS_PATH, index=False)
    print(f"\nDetailed results saved to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
