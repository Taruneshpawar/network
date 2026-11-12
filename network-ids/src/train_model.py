"""Train and compare IDS models. Run: python -m src.train_model --help"""
from __future__ import annotations
import argparse
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import (
    train_test_split,
    StratifiedKFold,
    RandomizedSearchCV,
    cross_val_score,
)
from sklearn.pipeline import Pipeline
from scipy.stats import randint, uniform

import config
from src import data_loader, preprocessing, evaluation, anomaly_detection
from src.preprocessing import time_or_day_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)


def get_param_distributions():
    """Parameter distributions for RandomizedSearchCV."""
    return {
        "RandomForest": {
            "clf__n_estimators": randint(100, 500),
            "clf__max_depth": [None, 10, 20, 30, 50],
            "clf__min_samples_split": randint(2, 20),
            "clf__min_samples_leaf": randint(1, 10),
            "clf__max_features": ["sqrt", "log2", 0.5],
        },
        "LogisticRegression": {
            "clf__C": uniform(0.01, 10),
            "clf__penalty": ["l2"],
            "clf__solver": ["lbfgs", "saga"],
            "clf__max_iter": [1000, 2000],
        },
    }


def build_candidate_pipelines(numeric_cols, categorical_cols, seed):
    """Build unfitted candidate pipelines."""
    preprocessor = preprocessing.build_preprocessor(numeric_cols, categorical_cols)

    candidates = {
        "RandomForest": Pipeline([
            ("prep", preprocessor),
            ("clf", RandomForestClassifier(
                n_estimators=200,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=seed,
            )),
        ]),
        "LogisticRegression": Pipeline([
            ("prep", preprocessor),
            ("clf", LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=seed,
                n_jobs=-1,
            )),
        ]),
    }
    return candidates


def tune_model(pipe, param_dist, X_train, y_train, cv_folds=5, n_iter=20, seed=42, scoring="f1_macro"):
    """Run RandomizedSearchCV on training data only."""
    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=seed)
    search = RandomizedSearchCV(
        pipe, param_dist, n_iter=n_iter, scoring=scoring,
        cv=cv, n_jobs=-1, random_state=seed, verbose=1
    )
    search.fit(X_train, y_train)
    log.info(f"Best CV score: {search.best_score_:.4f} with params: {search.best_params_}")
    return search.best_estimator_


def train_binary_model(X_train, y_train, numeric_cols, categorical_cols, seed):
    """Train a dedicated binary (Benign vs Malicious) model."""
    y_binary = (y_train != "Benign").astype(int)
    preprocessor = preprocessing.build_preprocessor(numeric_cols, categorical_cols)
    pipe = Pipeline([
        ("prep", preprocessor),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced_subsample",
            n_jobs=-1,
            random_state=seed,
        )),
    ])
    pipe.fit(X_train, y_binary)
    return pipe


def main():
    ap = argparse.ArgumentParser(description="Train IDS models")
    ap.add_argument("--data-dir", default=str(config.RAW_DIR))
    ap.add_argument("--sample-frac", type=float, default=1.0, help="Fraction of data to use (for quick runs)")
    ap.add_argument("--tune", action="store_true", help="Enable hyperparameter tuning")
    ap.add_argument("--no-tune", dest="tune", action="store_false")
    ap.add_argument("--with-anomaly", action="store_true", help="Train Isolation Forest anomaly detector")
    ap.add_argument("--seed", type=int, default=config.RANDOM_SEED)
    ap.add_argument("--day-heldout", action="store_true", help="Run day-held-out Evaluation B (requires source_file column)")
    ap.add_argument("--compute-importance", action="store_true", help="Compute permutation importance (slow)")
    ap.set_defaults(tune=False)
    args = ap.parse_args()

    # Load and inspect
    files = data_loader.find_dataset_files(args.data_dir)
    df = data_loader.load_dataset(files)
    inspection = data_loader.inspect_dataset(df)
    df = data_loader.clean_dataset(df)

    # Sample if requested
    if args.sample_frac < 1.0:
        df = df.groupby("family", group_keys=False).apply(
            lambda g: g.sample(frac=args.sample_frac, random_state=args.seed)
        )
        log.info(f"Sampled {args.sample_frac:.0%}: {len(df):,} rows")

    # Feature columns
    numeric_cols, categorical_cols = preprocessing.get_feature_columns(df)
    log.info(f"Features: {len(numeric_cols)} numeric, {len(categorical_cols)} categorical")

    X = df[numeric_cols + categorical_cols]
    y = df["family"]

    # SPLIT FIRST - nothing fitted before this line
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.TEST_SIZE, stratify=y, random_state=args.seed
    )
    log.info(f"Train: {len(X_train):,}, Test: {len(X_test):,}")

    # Build candidates
    candidates = build_candidate_pipelines(numeric_cols, categorical_cols, args.seed)

    results = {}
    fitted_models = {}

    for name, pipe in candidates.items():
        log.info(f"Training {name}...")
        t0 = time.perf_counter()

        if args.tune and name in get_param_distributions():
            log.info(f"Tuning {name} with RandomizedSearchCV...")
            pipe = tune_model(pipe, get_param_distributions()[name], X_train, y_train,
                            cv_folds=config.CV_FOLDS, seed=args.seed)
        else:
            pipe.fit(X_train, y_train)

        fit_time = time.perf_counter() - t0
        log.info(f"{name} trained in {fit_time:.1f}s")

        # Evaluate on held-out test set
        metrics = evaluation.compute_metrics(pipe, X_test, y_test)
        metrics["train_seconds"] = fit_time
        results[name] = metrics
        fitted_models[name] = pipe

        # Print summary
        log.info(f"  Accuracy: {metrics['accuracy']:.4f}")
        log.info(f"  Balanced Acc: {metrics['balanced_accuracy']:.4f}")
        log.info(f"  Macro F1: {metrics['macro_f1']:.4f}")
        log.info(f"  Weighted F1: {metrics['weighted_f1']:.4f}")

    # -------------------------------------------------------------------
    # Select best model by CV score on training set (not test set) §8.1
    # -------------------------------------------------------------------
    cv_scores = {}
    for name, pipe in fitted_models.items():
        cv = StratifiedKFold(n_splits=config.CV_FOLDS, shuffle=True, random_state=args.seed)
        cv_f1 = cross_val_score(pipe, X_train, y_train, cv=cv, scoring="f1_macro", n_jobs=-1)
        cv_scores[name] = float(cv_f1.mean())
        results[name]["cv_macro_f1_mean"] = cv_scores[name]
        results[name]["cv_macro_f1_std"] = float(cv_f1.std())
        log.info(f"{name} CV macro-F1: {cv_scores[name]:.4f} ± {cv_f1.std():.4f}")

    best_name = max(cv_scores, key=lambda n: cv_scores[n])
    best_pipe = fitted_models[best_name]
    log.info(f"Best model (by CV macro-F1): {best_name} — CV: {cv_scores[best_name]:.4f}, Test: {results[best_name]['macro_f1']:.4f}")

    # Train binary model
    log.info("Training binary model...")
    binary_pipe = train_binary_model(X_train, y_train, numeric_cols, categorical_cols, args.seed)
    binary_metrics = evaluation.compute_metrics(binary_pipe, X_test, (y_test != "Benign").astype(int))
    results["Binary_RandomForest"] = binary_metrics

    # Train anomaly detector
    anomaly_detector = None
    if args.with_anomaly:
        log.info("Training anomaly detector...")
        anomaly_detector = anomaly_detection.train_anomaly_detector(
            pd.concat([X_train, y_train], axis=1),
            random_state=args.seed,
        )

    # -------------------------------------------------------------------
    # Evaluation B: Day-held-out generalization test (optional, §8.2)
    # -------------------------------------------------------------------
    day_heldout_results = {}
    if args.day_heldout and "source_file" in df.columns:
        log.info("Running day-held-out evaluation (Evaluation B)...")
        try:
            full_df = data_loader.clean_dataset(
                data_loader.load_dataset(data_loader.find_dataset_files(args.data_dir))
            )
            train_b, test_b = time_or_day_split(full_df)
            if len(test_b) == 0:
                log.warning("No Friday files found; skipping Evaluation B")
            else:
                num_cols_b, cat_cols_b = preprocessing.get_feature_columns(full_df)
                X_b_train = train_b[num_cols_b + cat_cols_b]
                y_b_train = train_b["family"]
                X_b_test  = test_b[num_cols_b + cat_cols_b]
                y_b_test  = test_b["family"]

                for name, pipe in candidates.items():
                    p = preprocessing.build_preprocessor(num_cols_b, cat_cols_b)
                    pipe_b = Pipeline([("prep", p), ("clf", pipe.named_steps["clf"].__class__(
                        **{k.replace("clf__", ""): v
                           for k, v in pipe.named_steps["clf"].get_params().items()
                           if not k.startswith("base_estimator")}
                    ))])
                    pipe_b.fit(X_b_train, y_b_train)
                    m_b = evaluation.compute_metrics(pipe_b, X_b_test, y_b_test)
                    # Report classes present in test but absent in train
                    train_classes = set(y_b_train.unique())
                    test_classes  = set(y_b_test.unique())
                    unseen = sorted(test_classes - train_classes)
                    m_b["unseen_classes"] = unseen
                    if unseen:
                        log.warning(f"[EvalB/{name}] Unseen classes in test: {unseen}")
                    day_heldout_results[name] = m_b
                    log.info(f"[EvalB] {name} Macro-F1: {m_b['macro_f1']:.4f}")
        except Exception as exc:
            log.warning(f"Evaluation B failed: {exc}")
    elif args.day_heldout:
        log.warning("--day-heldout requires 'source_file' column (GeneratedLabelledFlows variant)")

    # -------------------------------------------------------------------
    # Permutation importance (optional, §8.6)
    # -------------------------------------------------------------------
    if args.compute_importance:
        log.info("Computing permutation importance (this may take a few minutes)...")
        for name, pipe in fitted_models.items():
            imp = evaluation.permutation_importance_report(pipe, X_test, y_test)
            results[name]["permutation_importance"] = imp
            log.info(f"Importance computed for {name}")

    # -------------------------------------------------------------------
    # Save artifacts
    # -------------------------------------------------------------------
    config.MODEL_DIR.mkdir(exist_ok=True, parents=True)

    # Save best multi-class pipeline
    joblib.dump(best_pipe, config.MODEL_DIR / "ids_pipeline.joblib")

    # Save binary pipeline
    joblib.dump(binary_pipe, config.MODEL_DIR / "ids_binary_pipeline.joblib")

    # Save anomaly detector
    if anomaly_detector:
        anomaly_detector.save(config.MODEL_DIR / "anomaly_model.joblib")

    # Save metadata
    file_hashes = data_loader.compute_file_hashes(files)
    metadata = {
        "model": best_name,
        "features": numeric_cols + categorical_cols,
        "classes": sorted(y.unique().tolist()),
        "seed": args.seed,
        "sklearn_version": sklearn.__version__,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "sample_frac": args.sample_frac,
        "tuned": args.tune,
        "dataset_files": file_hashes,
        "numeric_features": numeric_cols,
        "categorical_features": categorical_cols,
    }
    (config.MODEL_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2))

    # Save metrics (include day-held-out results if computed)
    evaluation.save_metrics_json(results, inspection, day_heldout=day_heldout_results if day_heldout_results else None)

    # Print comparison table
    print("\n=== Model Comparison ===")
    print(f"{'Model':<25} {'Acc':>8} {'BalAcc':>8} {'MacroF1':>8} {'WeightedF1':>10} {'Train(s)':>8}")
    for name, m in results.items():
        print(f"{name:<25} {m['accuracy']:>8.4f} {m['balanced_accuracy']:>8.4f} "
              f"{m['macro_f1']:>8.4f} {m['weighted_f1']:>10.4f} {m['train_seconds']:>8.1f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())