import sqlite3
import warnings
import matplotlib.cm as cm
import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import xgboost as xgb


def malware_eda():
    warnings.filterwarnings("ignore", category=FutureWarning)

    # === Load cleaned dataset from SQLite ===
    db_path = "malware_analytics.db"
    conn = sqlite3.connect(db_path)
    query = "SELECT file_size_bytes, file_entropy, block_size, num_sections, threat FROM malware_features_train_clean;"
    df = pd.read_sql_query(query, conn)
    conn.close()

    print(f"[*] Data loaded successfully. Shape: {df.shape}")

    feature_cols = [
        "file_size_bytes",
        "file_entropy",
        "block_size",
        "num_sections",
    ]
    X = df[feature_cols]
    y = df["threat"]

    # Set visualization theme
    sns.set_theme(style="whitegrid")

    # === 1. Class Balance ===
    plt.figure(figsize=(6, 4))
    sns.countplot(
        data=df,
        x="threat",
        palette=["#2ecc71", "#e74c3c"],
        hue="threat",
        legend=False,
    )
    plt.title("Class Distribution (0 = Benign, 1 = Malware)")
    plt.xlabel("Threat Label")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()

    # === 2. Feature Distributions (Histograms) ===
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    axes = axes.flatten()

    for i, col in enumerate(feature_cols):
        sns.histplot(
            data=df,
            x=col,
            hue="threat",
            kde=True,
            ax=axes[i],
            palette={0: "#2ecc71", 1: "#e74c3c"},
            bins=30,
        )
        axes[i].set_title(f"Distribution of {col}")
        axes[i].set_xlabel(col)
        axes[i].set_ylabel("Count")

    plt.tight_layout()
    plt.show()

    # === 3. Feature Boxplots ===
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    axes = axes.flatten()

    for i, col in enumerate(feature_cols):
        sns.boxplot(
            data=df,
            x="threat",
            y=col,
            hue="threat",
            ax=axes[i],
            palette={0: "#2ecc71", 1: "#e74c3c"},
            legend=False,
        )
        axes[i].set_title(f"{col} by Threat Label")
        axes[i].set_xlabel("Threat Label (0=Benign, 1=Malware)")

    plt.tight_layout()
    plt.show()

    # === 4. Correlation Heatmap ===
    plt.figure(figsize=(7, 6))
    sns.heatmap(
        df.corr(),
        annot=True,
        fmt=".2f",
        cmap="coolwarm",
        center=0,
        square=True,
        linewidths=0.5,
    )
    plt.title("Correlation Heatmap")
    plt.tight_layout()
    plt.show()

    # === 5. Top Feature Importance (%) with Scaled Meaningful Colors ===
    print("\n=== Feature Importance Breakdown (%) ===")
    eda_model = xgb.XGBClassifier(random_state=42, eval_metric="logloss")
    eda_model.fit(X, y)

    # Convert Gain importance to exact percentage
    importance_pct = eda_model.feature_importances_ * 100
    imp_df = (
        pd.DataFrame({"Feature": feature_cols, "Importance (%)": importance_pct})
        .sort_values(by="Importance (%)", ascending=False)
        .reset_index(drop=True)
    )

    for _, row in imp_df.iterrows():
        print(f" - {row['Feature']}: {row['Importance (%)']:.2f}%")

    # Map color gradient directly scaled to feature percentage magnitude (YlOrRd: Yellow -> Orange -> Red)
    norm = mcolors.Normalize(
        vmin=0, vmax=max(imp_df["Importance (%)"]) * 1.05
    )
    cmap = cm.get_cmap("YlOrRd")
    bar_colors = [cmap(norm(val)) for val in imp_df["Importance (%)"]]

    plt.figure(figsize=(9, 5))
    bars = plt.barh(
        imp_df["Feature"],
        imp_df["Importance (%)"],
        color=bar_colors,
        edgecolor="black",
        linewidth=0.8,
    )
    plt.gca().invert_yaxis()  # Top feature on top

    plt.title(
        "Top Features Affected by Percentage Impact",
        fontsize=13,
        fontweight="bold",
    )
    plt.xlabel("Percentage Contribution (%)", fontsize=11)
    plt.ylabel("Feature", fontsize=11)

    # Annotate exact percentage labels at the end of each bar
    for bar in bars:
        width = bar.get_width()
        plt.text(
            width + 0.8,
            bar.get_y() + bar.get_height() / 2.0,
            f"{width:.2f}%",
            va="center",
            ha="left",
            fontsize=10,
            fontweight="bold",
        )

    plt.xlim(0, max(imp_df["Importance (%)"]) * 1.18)
    plt.grid(axis="x", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    malware_eda()