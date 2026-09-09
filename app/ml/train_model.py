from pathlib import Path
import sys
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import (
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split

from xgboost import XGBClassifier
from lightgbm import LGBMClassifier


# ============================================================
# PROJECT ROOT
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
MODEL_PATH = MODEL_DIR / "url_risk_ensemble.joblib"


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset():

    print("=" * 80)
    print("LOADING DATASET")
    print("=" * 80)

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    print(f"Dataset : {DATASET_PATH}")
    print(f"Rows    : {len(df):,}")
    print(f"Columns : {list(df.columns)}")

    if "url" not in df.columns:
        raise ValueError(
            "Dataset must contain a 'url' column."
        )

    if "label" not in df.columns:
        raise ValueError(
            "Dataset must contain a 'label' column."
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

    # Keep only binary classes.
    df = df[
        df["label"].isin([0, 1])
    ].copy()

    print("\nClass distribution:")
    print(df["label"].value_counts())

    return df


# ============================================================
# EXTRACT FEATURES
# ============================================================

def extract_features(df):

    print("\n" + "=" * 80)
    print("EXTRACTING URL FEATURES")
    print("=" * 80)

    print(
        f"Feature count: {len(FEATURE_NAMES)}"
    )

    features = []

    total = len(df)
    errors = 0

    for i, url in enumerate(df["url"]):

        try:

            feature_dict = get_features(url)

            vector = get_feature_vector(
                feature_dict
            )

            if len(vector) != len(FEATURE_NAMES):

                raise ValueError(
                    f"Expected {len(FEATURE_NAMES)} "
                    f"features but received {len(vector)}."
                )

            features.append(vector)

        except Exception as exc:

            errors += 1

            if errors <= 10:
                print(
                    f"Feature error at row {i}: {exc}"
                )

            # Conservative fallback.
            features.append(
                [0.0] * len(FEATURE_NAMES)
            )

        if (i + 1) % 10000 == 0:

            print(
                f"Processed "
                f"{i + 1:,}/{total:,}"
            )

    X = np.asarray(
        features,
        dtype=np.float32
    )

    print("\nFeature extraction completed.")
    print(
        f"Feature matrix: {X.shape}"
    )
    print(
        f"Feature errors: {errors:,}"
    )

    return X


# ============================================================
# BUILD MODELS
# ============================================================

def build_models():

    # --------------------------------------------------------
    # Logistic Regression
    # --------------------------------------------------------

    logistic = Pipeline(
        steps=[
            (
                "scaler",
                StandardScaler()
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                )
            ),
        ]
    )

    # --------------------------------------------------------
    # Random Forest
    # --------------------------------------------------------

    random_forest = RandomForestClassifier(
        n_estimators=300,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    # --------------------------------------------------------
    # XGBoost
    # --------------------------------------------------------

    xgboost = XGBClassifier(
        n_estimators=400,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        random_state=42,
        n_jobs=-1,
    )

    # --------------------------------------------------------
    # LightGBM
    # --------------------------------------------------------

    lightgbm = LGBMClassifier(
        n_estimators=400,
        learning_rate=0.08,
        num_leaves=63,
        max_depth=-1,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="binary",
        random_state=42,
        n_jobs=-1,
        verbosity=-1,
    )

    # --------------------------------------------------------
    # Soft-voting ensemble
    # --------------------------------------------------------
    #
    # Tree models receive higher weight because the current
    # project uses structured/tabular security features.
    #
    # Logistic Regression remains useful as a diverse model.
    #

    ensemble = VotingClassifier(
        estimators=[
            ("lr", logistic),
            ("rf", random_forest),
            ("xgb", xgboost),
            ("lgbm", lightgbm),
        ],
        voting="soft",
        weights=[
            1,
            2,
            2,
            2,
        ],
        n_jobs=-1,
        flatten_transform=True,
    )

    return {
        "Logistic Regression": logistic,
        "Random Forest": random_forest,
        "XGBoost": xgboost,
        "LightGBM": lightgbm,
        "Ensemble": ensemble,
    }


# ============================================================
# EVALUATE MODEL
# ============================================================

def evaluate_model(
    name,
    model,
    X_train,
    X_test,
    y_train,
    y_test,
):

    print("\n" + "-" * 80)
    print(f"TRAINING: {name}")
    print("-" * 80)

    start = time.perf_counter()

    model.fit(
        X_train,
        y_train
    )

    training_time = (
        time.perf_counter()
        - start
    )

    y_pred = model.predict(
        X_test
    )

    y_probability = (
        model.predict_proba(
            X_test
        )[:, 1]
    )

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

    print(
        f"Training : {training_time:.2f} seconds"
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            y_pred
        )
    )

    return {
        "model": model,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "training_time": training_time,
    }


# ============================================================
# MAIN TRAINING
# ============================================================

def main():

    print("=" * 80)
    print("AI BROWSER SECURITY")
    print(
        "LOGISTIC + RANDOM FOREST + XGBOOST + LIGHTGBM"
    )
    print("=" * 80)

    print(
        f"\nFeatures: {len(FEATURE_NAMES)}"
    )

    df = load_dataset()

    X = extract_features(df)

    y = df[
        "label"
    ].to_numpy()

    # --------------------------------------------------------
    # Train/test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y,
        )
    )

    print(
        f"\nTraining samples: {len(X_train):,}"
    )

    print(
        f"Testing samples : {len(X_test):,}"
    )

    models = build_models()

    results = {}

    # --------------------------------------------------------
    # Train individual models
    # --------------------------------------------------------

    for name in [
        "Logistic Regression",
        "Random Forest",
        "XGBoost",
        "LightGBM",
    ]:

        results[name] = evaluate_model(
            name,
            models[name],
            X_train,
            X_test,
            y_train,
            y_test,
        )

    # --------------------------------------------------------
    # Train final ensemble
    # --------------------------------------------------------

    results["Ensemble"] = evaluate_model(
        "FINAL ENSEMBLE",
        models["Ensemble"],
        X_train,
        X_test,
        y_train,
        y_test,
    )

    # --------------------------------------------------------
    # Save final ensemble
    # --------------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    bundle = {
        "model": results["Ensemble"]["model"],
        "feature_names": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "model_type": (
            "Logistic Regression + "
            "Random Forest + "
            "XGBoost + "
            "LightGBM Soft Voting Ensemble"
        ),
        "weights": {
            "logistic_regression": 1,
            "random_forest": 2,
            "xgboost": 2,
            "lightgbm": 2,
        },
        "metrics": {
            name: {
                key: value
                for key, value in result.items()
                if key != "model"
            }
            for name, result in results.items()
        },
    }

    joblib.dump(
        bundle,
        MODEL_PATH,
        compress=3
    )

    print("\n" + "=" * 80)
    print("FINAL MODEL SAVED")
    print("=" * 80)

    print(
        f"Path: {MODEL_PATH}"
    )

    print(
        "\nFinal model:"
    )

    print(
        bundle["model_type"]
    )

    print(
        f"Features: {len(FEATURE_NAMES)}"
    )


if __name__ == "__main__":
    main()