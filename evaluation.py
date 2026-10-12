import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import sqlite3
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_curve,
    roc_auc_score,
    precision_recall_curve
)

def run_evaluation():
    print("\n=== Evaluation Step ===")

    # Load data directly using specified query
    db_path = "malware_analytics.db"
    conn = sqlite3.connect(db_path)
    query = "SELECT file_size_bytes, file_entropy, block_size, num_sections, threat FROM malware_features_train_clean;"
    df = pd.read_sql_query(query, conn)
    conn.close()

    # Explicit feature list matching model's expected order
    feature_cols = ["file_size_bytes", "file_entropy", "block_size", "num_sections"]
    X = df[feature_cols]
    y = df["threat"]

    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Load trained model
    model = xgb.XGBClassifier()
    model.load_model("malware_modelV2.bin")

    # Predict probabilities
    y_proba = model.predict_proba(X_test)[:, 1]

    # Threshold optimization via Precision-Recall Curve
    precision, recall, thresholds = precision_recall_curve(y_test, y_proba)
    f1_scores = 2 * (precision * recall) / (precision + recall + 1e-9)
    best_idx = f1_scores.argmax()
    best_threshold = thresholds[best_idx]
    y_pred = (y_proba >= best_threshold).astype(int)

    print(f"[+] Best Threshold: {best_threshold:.3f}")

    # === Metrics ===
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)

    print(f"Accuracy: {acc:.3f}")
    print(f"Precision: {prec:.3f}")
    print(f"Recall: {rec:.3f}")
    print(f"F1 Score: {f1:.3f}")
    print(f"ROC-AUC: {auc:.3f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, digits=3))

    # === Confusion Matrix ===
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d",
                cmap="Blues", cbar=False,
                xticklabels=["Safe", "Malware"], yticklabels=["Safe", "Malware"])
    plt.title("Confusion Matrix")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")

    plt.text(0.5, -0.3, f"FP = {cm[0,1]} | FN = {cm[1,0]}",
             ha="center", va="center", fontsize=12, color="red", transform=plt.gca().transAxes)
    plt.tight_layout()
    plt.show()

    # === ROC Curve ===
    fpr, tpr, _ = roc_curve(y_test, y_proba)

    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color="darkorange", linewidth=2, label="ROC Curve")
    plt.fill_between(fpr, tpr, alpha=0.2, color="orange", label=f"AUC = {auc:.3f}")
    plt.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Random Guess")

    plt.text(0.6, 0.2, f"AUC = {auc:.3f}", fontsize=12, color="black",
             bbox=dict(facecolor="white", alpha=0.6, edgecolor="gray"))

    plt.title("ROC Curve (Receiver Operating Characteristic)")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()

    # === Precision-Recall Curve ===
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color="blue", linewidth=2, label="Precision-Recall Curve")
    plt.scatter(recall[best_idx], precision[best_idx], color="red", s=100,
                label=f"Best Threshold = {best_threshold:.3f}")
    plt.title("Precision-Recall Curve")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.show()