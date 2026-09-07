from pathlib import Path
import sys

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# FEATURE IMPORT
# ============================================================

from app.features.url_features import (
    get_features,
    get_feature_vector,
    FEATURE_NAMES,
)


# ============================================================
# PATHS
# ============================================================

DATASET_PATH = PROJECT_ROOT / "data" / "dataset.csv"
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_PATH = MODEL_DIR / "url_risk_model.joblib"


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print("=" * 70)
    print("LOADING DATASET")
    print("=" * 70)

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset path : {DATASET_PATH}")
    print(f"Rows         : {len(df):,}")
    print(f"Columns      : {list(df.columns)}")

    if "url" not in df.columns:
        raise ValueError(
            "Dataset does not contain 'url' column."
        )

    if "label" not in df.columns:
        raise ValueError(
            "Dataset does not contain 'label' column."
        )

    df = df[["url", "label"]].copy()

    df = df.dropna(
        subset=["url", "label"]
    )

    df["url"] = df["url"].astype(str)

    df["label"] = pd.to_numeric(
        df["label"],
        errors="coerce"
    )

    df = df.dropna(
        subset=["label"]
    )

    df["label"] = df["label"].astype(int)

    print("\nClass distribution:")
    print(df["label"].value_counts())

    return df


# ============================================================
# EXTRACT FEATURES
# ============================================================

def extract_features(df):

    print("\n" + "=" * 70)
    print("EXTRACTING URL FEATURES")
    print("=" * 70)

    print(
        f"Expected feature count: {len(FEATURE_NAMES)}"
    )

    features = []

    total = len(df)

    error_count = 0

    for i, url in enumerate(df["url"]):

        try:

            # IMPORTANT:
            # get_features() expects a URL
            # and returns a dictionary.

            feature_dict = get_features(
                url
            )

            # get_feature_vector() expects
            # that dictionary.

            vector = get_feature_vector(
                feature_dict
            )

            if len(vector) != len(FEATURE_NAMES):

                raise ValueError(
                    f"Expected {len(FEATURE_NAMES)} "
                    f"features, got {len(vector)}"
                )

            features.append(vector)

        except Exception as e:

            error_count += 1

            # Do NOT print thousands of errors.
            # Print only the first few.

            if error_count <= 10:

                print(
                    f"Feature error at row {i}: {e}"
                )

            features.append(
                [0.0] * len(FEATURE_NAMES)
            )

        if (i + 1) % 10000 == 0:

            print(
                f"Processed {i + 1:,} / {total:,} URLs"
            )

    X = np.asarray(
        features,
        dtype=np.float32
    )

    print("\nFeature extraction completed.")

    print(
        f"Feature matrix shape: {X.shape}"
    )

    print(
        f"Feature errors: {error_count:,}"
    )

    if X.shape[1] != len(FEATURE_NAMES):

        raise ValueError(
            f"Feature count mismatch. "
            f"Expected {len(FEATURE_NAMES)}, "
            f"got {X.shape[1]}"
        )

    return X


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(X, y):

    print("\n" + "=" * 70)
    print("TRAINING RANDOM FOREST")
    print("=" * 70)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(
        f"Training samples: {len(X_train):,}"
    )

    print(
        f"Testing samples : {len(X_test):,}"
    )

    model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
        max_features="sqrt",
    )

    print("\nTraining started...")
    print("Please wait. This can take several minutes.")

    model.fit(
        X_train,
        y_train
    )

    print("Training completed.")

    # ========================================================
    # PREDICTION
    # ========================================================

    y_pred = model.predict(
        X_test
    )

    y_probability = model.predict_proba(
        X_test
    )[:, 1]

    # ========================================================
    # METRICS
    # ========================================================

    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        y_probability
    )

    print("\n" + "=" * 70)
    print("MODEL EVALUATION")
    print("=" * 70)

    print(
        f"Accuracy : {accuracy * 100:.2f}%"
    )

    print(
        f"Precision: {precision * 100:.2f}%"
    )

    print(
        f"Recall   : {recall * 100:.2f}%"
    )

    print(
        f"F1-score : {f1 * 100:.2f}%"
    )

    print(
        f"ROC-AUC  : {roc_auc * 100:.2f}%"
    )

    return model


# ============================================================
# SAVE MODEL
# ============================================================

def save_model(model):

    print("\n" + "=" * 70)
    print("SAVING MODEL")
    print("=" * 70)

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(
        model,
        MODEL_PATH
    )

    print(
        f"Model saved to:\n{MODEL_PATH}"
    )

    print("\nModel information:")

    print(
        f"Type     : {type(model)}"
    )

    print(
        f"Features : {model.n_features_in_}"
    )

    print(
        f"Classes  : {model.classes_}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("AI BROWSER SECURITY - MODEL TRAINING")
    print("=" * 70)

    print(
        f"\nFeature count: {len(FEATURE_NAMES)}"
    )

    df = load_dataset()

    X = extract_features(
        df
    )

    y = df["label"].to_numpy()

    model = train_model(
        X,
        y
    )

    save_model(
        model
    )

    print("\n" + "=" * 70)
    print("TRAINING FINISHED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    main()