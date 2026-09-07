"""Hyperparameter search and cross-validation for the EMBER classifier - NI.

Table 5.4, Weeks 9-12: *"Train XGBoost model, hyperparameter tuning,
cross-validation, model evaluation"*. Figure 4.7 names the same two steps inside
its XGBoost Training box. Neither existed: `train_ember_model.py` fits one model
with hand-picked constants (`n_estimators=300, max_depth=6, learning_rate=0.1`)
and evaluates it once on a single hold-out split, and no `GridSearchCV`,
`RandomizedSearchCV`, `cross_val_score` or `StratifiedKFold` appeared anywhere
in `src/`.

Design, and why
---------------
* **The search runs on the training split only.** The 15% test split is not
  touched here at all. Selecting on data that later reports the headline number
  is how a tuned model comes out looking better than it is.
* **Randomised, not exhaustive.** The stated grid below has 2,592 combinations.
  One fit on 35,000 x 2,381 takes ~35s measured on this machine, so exhaustive
  5-fold search is ~63 days. `--iterations` samples from that grid instead; the
  grid is stated in full so the sampling frame is visible.
* **The incumbent is scored on the identical folds.** A search that only reports
  its winner cannot show the winner is an improvement. The hand-picked
  configuration is evaluated as one more candidate, so the comparison is
  like-for-like.
* **Fold-level variance is reported, not just the mean.** A mean F1 that hides
  a 3-point spread across folds is a different claim from one that does not.

    python src/tune_ember_model.py --iterations 12 --folds 5

Writes reports/hyperparameter_search.json.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import (
    ParameterSampler,
    StratifiedKFold,
    cross_validate,
    train_test_split,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data" / "ember_subset"
REPORTS_DIR = REPO_ROOT / "reports"

# The stated grid. 4*4*3*3*3*3*2 = 2,592 combinations.
SEARCH_GRID = {
    "max_depth": [4, 6, 8, 10],
    "learning_rate": [0.03, 0.05, 0.1, 0.2],
    "n_estimators": [200, 300, 500],
    "subsample": [0.6, 0.8, 1.0],
    "colsample_bytree": [0.6, 0.8, 1.0],
    "min_child_weight": [1, 3, 5],
    "reg_lambda": [1.0, 3.0],
}

# What train_ember_model.py used before this script existed.
INCUMBENT = {
    "max_depth": 6,
    "learning_rate": 0.1,
    "n_estimators": 300,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 1,
    "reg_lambda": 1.0,
}

# F1 is the selection metric because it is the one the grading criteria name:
# TC-06 wants precision, recall and F1 above 85%, and 5.6.3 wants above 90%
# across all metrics. ROC-AUC is recorded alongside but does not decide.
SCORING = ("f1", "roc_auc", "accuracy", "precision", "recall")
SELECTION_METRIC = "f1"


def load_training_split(seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """The same 70% train split train_ember_model.py fits on, same seed.

    Reproducing the split rather than importing it keeps this script standalone,
    but the seed and proportions must not drift from the training script or the
    search would be tuning against a different partition than the one used.
    """
    candidates = [DATA_DIR / "ember_subset.parquet", DATA_DIR / "ember_50k.parquet"]
    path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        raise SystemExit(f"No EMBER parquet found in {DATA_DIR}")

    frame = pd.read_parquet(path)
    X = np.stack(frame["x"].values).astype(np.float32)
    y = frame["label"].values.astype(int)

    X_train, _, y_train, _ = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=seed
    )
    return X_train, y_train


def evaluate(params: dict, X: np.ndarray, y: np.ndarray, folds: int, seed: int) -> dict:
    scale_pos_weight = (y == 0).sum() / max((y == 1).sum(), 1)
    model = xgb.XGBClassifier(
        **params,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=seed,
    )

    started = perf_counter()
    scores = cross_validate(
        model,
        X,
        y,
        cv=StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed),
        scoring=list(SCORING),
        n_jobs=1,  # XGBoost already uses every core; nesting them thrashes.
        return_train_score=False,
    )
    elapsed = perf_counter() - started

    result = {"params": params, "cv_seconds": round(elapsed, 1)}
    for metric in SCORING:
        values = scores[f"test_{metric}"]
        result[metric] = {
            "mean": float(np.mean(values)),
            "std": float(np.std(values)),
            "min": float(np.min(values)),
            "max": float(np.max(values)),
            "folds": [float(v) for v in values],
        }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=12, help="configurations sampled")
    parser.add_argument("--folds", type=int, default=5, help="stratified k-fold splits")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    REPORTS_DIR.mkdir(exist_ok=True)

    print("Loading EMBER training split...")
    X, y = load_training_split(args.seed)
    print(f"  {X.shape[0]:,} rows x {X.shape[1]:,} features, "
          f"{(y == 0).sum():,} benign / {(y == 1).sum():,} malicious")

    sampled = list(
        ParameterSampler(SEARCH_GRID, n_iter=args.iterations, random_state=args.seed)
    )

    candidates: list[tuple[str, dict]] = [("incumbent", INCUMBENT)]
    candidates += [(f"sampled_{i:02d}", params) for i, params in enumerate(sampled)]

    print(
        f"\n{len(candidates)} configurations x {args.folds} folds "
        f"= {len(candidates) * args.folds} fits\n"
    )

    results = []
    for name, params in candidates:
        print(f"[{name}] {params}")
        result = evaluate(params, X, y, args.folds, args.seed)
        result["name"] = name
        results.append(result)
        selected = result[SELECTION_METRIC]
        print(
            f"    {SELECTION_METRIC} {selected['mean']:.4f} +/- {selected['std']:.4f}  "
            f"(min {selected['min']:.4f}, max {selected['max']:.4f})  "
            f"[{result['cv_seconds']}s]\n"
        )

    ranked = sorted(results, key=lambda r: r[SELECTION_METRIC]["mean"], reverse=True)
    best = ranked[0]
    incumbent = next(r for r in results if r["name"] == "incumbent")

    delta = best[SELECTION_METRIC]["mean"] - incumbent[SELECTION_METRIC]["mean"]
    # A winner inside the incumbent's own fold-to-fold spread has not been shown
    # to be better; it has been shown to be indistinguishable. Retraining on it
    # would be churn dressed as an improvement.
    meaningful = delta > incumbent[SELECTION_METRIC]["std"]

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "grid": SEARCH_GRID,
        "grid_size": int(np.prod([len(v) for v in SEARCH_GRID.values()])),
        "sampled_configurations": args.iterations,
        "folds": args.folds,
        "seed": args.seed,
        "selection_metric": SELECTION_METRIC,
        "training_rows": int(X.shape[0]),
        "features": int(X.shape[1]),
        "note": (
            "Search ran on the 70% training split only; the 15% test split was "
            "not read by this script."
        ),
        "incumbent": incumbent,
        "best": best,
        "improvement_over_incumbent": float(delta),
        "improvement_exceeds_incumbent_fold_std": bool(meaningful),
        "all_results": ranked,
    }
    (REPORTS_DIR / "hyperparameter_search.json").write_text(json.dumps(payload, indent=2))

    print("=" * 72)
    print(f"Best:      {best['name']}  {SELECTION_METRIC} "
          f"{best[SELECTION_METRIC]['mean']:.4f} +/- {best[SELECTION_METRIC]['std']:.4f}")
    print(f"Incumbent: {SELECTION_METRIC} "
          f"{incumbent[SELECTION_METRIC]['mean']:.4f} +/- {incumbent[SELECTION_METRIC]['std']:.4f}")
    print(f"Delta:     {delta:+.4f}  "
          f"({'exceeds' if meaningful else 'inside'} the incumbent's fold spread)")
    print(f"\nBest params: {best['params']}")
    print(f"\nWrote {REPORTS_DIR / 'hyperparameter_search.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
