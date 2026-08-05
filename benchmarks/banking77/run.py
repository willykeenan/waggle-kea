#!/usr/bin/env python3
"""Run the public, exploratory BANKING77 classifier benchmark."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import sys
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import scipy
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    log_loss,
    precision_recall_fscore_support,
    top_k_accuracy_score,
)
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import FeatureUnion, Pipeline


HERE = Path(__file__).resolve().parent
SOURCE_PATH = HERE / "SOURCE.json"
CONFIG_PATH = HERE / "config.v1.json"
DEFAULT_CACHE = HERE / ".cache" / "source"
DEFAULT_OUTPUT = HERE / "results" / "local-v1"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def acquire_source(cache: Path, source: dict[str, Any], offline: bool) -> dict[str, Path]:
    cache.mkdir(parents=True, exist_ok=True)
    base = (
        "https://raw.githubusercontent.com/PolyAI-LDN/task-specific-datasets/"
        f"{source['upstreamCommit']}/banking_data"
    )
    resolved: dict[str, Path] = {}
    for name, expected in source["files"].items():
        target = cache / name
        if target.exists():
            payload = target.read_bytes()
            if sha256_bytes(payload) != expected["sha256"] or len(payload) != expected["bytes"]:
                raise RuntimeError(f"Cached {name} does not match its pinned digest and size")
        else:
            if offline:
                raise RuntimeError(f"Offline mode requires verified cached source file {name}")
            request = urllib.request.Request(
                f"{base}/{name}",
                headers={"User-Agent": "waggle-kea-banking77-benchmark/1.0"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
            if sha256_bytes(payload) != expected["sha256"] or len(payload) != expected["bytes"]:
                raise RuntimeError(f"Downloaded {name} does not match its pinned digest and size")
            temporary = target.with_suffix(target.suffix + f".tmp-{os.getpid()}")
            temporary.write_bytes(payload)
            temporary.replace(target)
        resolved[name] = target
    return resolved


def normalize_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if any(set(row) != {"text", "category"} for row in rows):
        raise RuntimeError(f"Unexpected CSV schema in {path.name}")
    return rows


def group_rows(rows: list[dict[str, str]]) -> dict[str, list[tuple[int, dict[str, str]]]]:
    grouped: dict[str, list[tuple[int, dict[str, str]]]] = defaultdict(list)
    for index, row in enumerate(rows):
        grouped[normalize_text(row["text"])].append((index, row))
    return grouped


def prepare_data(
    train_rows: list[dict[str, str]],
    test_rows: list[dict[str, str]],
    categories: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, str]], dict[str, int]]:
    category_set = set(categories)
    if len(categories) != 77 or len(category_set) != 77:
        raise RuntimeError("Pinned BANKING77 category inventory must contain 77 unique labels")
    if {row["category"] for row in train_rows + test_rows} != category_set:
        raise RuntimeError("Observed labels do not match categories.json")

    train_groups = group_rows(train_rows)
    test_groups = group_rows(test_rows)
    raw_train_norms = set(train_groups)
    ambiguous_train = {
        key for key, values in train_groups.items() if len({row["category"] for _, row in values}) > 1
    }
    ambiguous_test = {
        key for key, values in test_groups.items() if len({row["category"] for _, row in values}) > 1
    }
    overlaps = raw_train_norms.intersection(test_groups)

    clean_train: list[dict[str, str]] = []
    for key, values in train_groups.items():
        if key in ambiguous_train:
            continue
        index, row = min(values, key=lambda item: item[0])
        clean_train.append({**row, "sourceIndex": str(index)})

    primary_test: list[dict[str, str]] = []
    for key, values in test_groups.items():
        if key in ambiguous_test or key in overlaps:
            continue
        index, row = min(values, key=lambda item: item[0])
        primary_test.append({**row, "sourceIndex": str(index)})

    post_filter_overlap = {
        normalize_text(row["text"]) for row in clean_train
    }.intersection(normalize_text(row["text"]) for row in primary_test)

    audit = {
        "rawTrainRows": len(train_rows),
        "rawTestRows": len(test_rows),
        "categories": len(categories),
        "normalizedTrainGroups": len(train_groups),
        "normalizedTestGroups": len(test_groups),
        "ambiguousTrainGroups": len(ambiguous_train),
        "ambiguousTestGroups": len(ambiguous_test),
        "normalizedTrainTestOverlapGroups": len(overlaps),
        "cleanUniqueTrainRows": len(clean_train),
        "primaryUniqueTrainDisjointTestRows": len(primary_test),
        "postFilterOverlapGroups": len(post_filter_overlap),
    }
    expected = {
        "rawTrainRows": 10003,
        "rawTestRows": 3080,
        "categories": 77,
        "normalizedTrainGroups": 9972,
        "normalizedTestGroups": 3076,
        "ambiguousTrainGroups": 1,
        "ambiguousTestGroups": 1,
        "normalizedTrainTestOverlapGroups": 25,
        "cleanUniqueTrainRows": 9971,
        "primaryUniqueTrainDisjointTestRows": 3050,
        "postFilterOverlapGroups": 0,
    }
    if audit != expected:
        raise RuntimeError(f"Frozen data-audit counts drifted: observed={audit}, expected={expected}")
    return clean_train, primary_test, audit


def word_features(config: dict[str, Any]) -> TfidfVectorizer:
    feature = config["wordFeatures"]
    return TfidfVectorizer(
        analyzer=feature["analyzer"],
        ngram_range=tuple(feature["ngramRange"]),
        min_df=feature["minDf"],
        max_features=feature["maxFeatures"],
        sublinear_tf=feature["sublinearTf"],
        dtype=np.float64,
    )


def word_character_features(config: dict[str, Any]) -> FeatureUnion:
    feature = config["characterFeatures"]
    return FeatureUnion(
        [
            ("word", word_features(config)),
            (
                "character",
                TfidfVectorizer(
                    analyzer=feature["analyzer"],
                    ngram_range=tuple(feature["ngramRange"]),
                    min_df=feature["minDf"],
                    max_features=feature["maxFeatures"],
                    sublinear_tf=feature["sublinearTf"],
                    dtype=np.float64,
                ),
            ),
        ]
    )


def classifier(config: dict[str, Any], seed: int) -> SGDClassifier:
    model = config["classifier"]
    return SGDClassifier(
        loss=model["loss"],
        alpha=model["alpha"],
        max_iter=model["maxIter"],
        tol=model["tolerance"],
        random_state=seed,
        n_jobs=model["jobs"],
        shuffle=True,
    )


def pipeline(config: dict[str, Any], seed: int, include_characters: bool) -> Pipeline:
    features = word_character_features(config) if include_characters else word_features(config)
    return Pipeline([("features", features), ("classifier", classifier(config, seed))])


def expected_calibration_error(y_true: np.ndarray, probabilities: np.ndarray, bins: int) -> float:
    confidence = probabilities.max(axis=1)
    predicted = probabilities.argmax(axis=1)
    correct = predicted == y_true
    edges = np.linspace(0.0, 1.0, bins + 1)
    total = len(y_true)
    ece = 0.0
    for index in range(bins):
        if index == bins - 1:
            selected = (confidence >= edges[index]) & (confidence <= edges[index + 1])
        else:
            selected = (confidence >= edges[index]) & (confidence < edges[index + 1])
        count = int(selected.sum())
        if count:
            ece += (count / total) * abs(float(correct[selected].mean()) - float(confidence[selected].mean()))
    return float(ece)


def multiclass_brier(y_true: np.ndarray, probabilities: np.ndarray) -> float:
    one_hot = np.zeros_like(probabilities)
    one_hot[np.arange(len(y_true)), y_true] = 1.0
    return float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))


def risk_coverage(
    y_true: np.ndarray,
    predictions: np.ndarray,
    probabilities: np.ndarray,
    thresholds: Iterable[float],
) -> list[dict[str, Any]]:
    confidence = probabilities.max(axis=1)
    output: list[dict[str, Any]] = []
    for threshold in thresholds:
        selected = confidence >= threshold
        accepted = int(selected.sum())
        accuracy = float((predictions[selected] == y_true[selected]).mean()) if accepted else None
        output.append(
            {
                "threshold": float(threshold),
                "accepted": accepted,
                "coverage": accepted / len(y_true),
                "selectiveAccuracy": accuracy,
                "selectiveRisk": None if accuracy is None else 1.0 - accuracy,
            }
        )
    return output


def model_metrics(
    y_true_labels: list[str],
    predictions: np.ndarray,
    probabilities: np.ndarray,
    classes: np.ndarray,
    config: dict[str, Any],
) -> dict[str, Any]:
    class_to_index = {label: index for index, label in enumerate(classes.tolist())}
    y_true = np.array([class_to_index[label] for label in y_true_labels], dtype=np.int64)
    y_pred = np.array([class_to_index[label] for label in predictions.tolist()], dtype=np.int64)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macroF1": float(f1_score(y_true, y_pred, average="macro", labels=np.arange(len(classes)))),
        "logLoss": float(log_loss(y_true, probabilities, labels=np.arange(len(classes)))),
        "multiclassBrier": multiclass_brier(y_true, probabilities),
        "expectedCalibrationError": expected_calibration_error(
            y_true, probabilities, config["eceBins"]
        ),
        "top3Accuracy": float(
            top_k_accuracy_score(y_true, probabilities, k=3, labels=np.arange(len(classes)))
        ),
        "riskCoverage": risk_coverage(
            y_true,
            y_pred,
            probabilities,
            config["riskCoverageThresholds"],
        ),
    }


def bootstrap_macro_f1(
    y_true: np.ndarray,
    baseline: np.ndarray,
    candidate: np.ndarray,
    classes: np.ndarray,
    draws: int,
    seed: int,
) -> dict[str, Any]:
    class_indexes = [np.flatnonzero(y_true == label) for label in classes]
    rng = np.random.default_rng(seed)
    baseline_values = np.empty(draws, dtype=np.float64)
    candidate_values = np.empty(draws, dtype=np.float64)
    delta_values = np.empty(draws, dtype=np.float64)
    for draw in range(draws):
        sampled = np.concatenate(
            [rng.choice(indexes, size=len(indexes), replace=True) for indexes in class_indexes]
        )
        baseline_score = f1_score(y_true[sampled], baseline[sampled], average="macro", labels=classes)
        candidate_score = f1_score(y_true[sampled], candidate[sampled], average="macro", labels=classes)
        baseline_values[draw] = baseline_score
        candidate_values[draw] = candidate_score
        delta_values[draw] = candidate_score - baseline_score

    def interval(values: np.ndarray) -> list[float]:
        return [float(value) for value in np.quantile(values, [0.025, 0.975])]

    return {
        "method": "label-stratified-paired-percentile-bootstrap",
        "draws": draws,
        "seed": seed,
        "baselineMacroF1Interval95": interval(baseline_values),
        "candidateMacroF1Interval95": interval(candidate_values),
        "pairedDeltaMacroF1Interval95": interval(delta_values),
    }


def seeded_typo(text: str, seed: int) -> tuple[str, bool]:
    spans = [match.span() for match in re.finditer(r"[A-Za-z]{5,}", text)]
    if not spans:
        return text, False
    digest = hashlib.sha256(f"{seed}|{text}".encode("utf-8")).digest()
    start, end = spans[int.from_bytes(digest[:4], "big") % len(spans)]
    position = start + 1 + (int.from_bytes(digest[4:8], "big") % (end - start - 2))
    return text[:position] + text[position + 1 :], True


def simple_metrics(y_true: list[str], predictions: np.ndarray, categories: list[str]) -> dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "macroF1": float(f1_score(y_true, predictions, average="macro", labels=categories)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="Require the verified local source cache")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    source = read_json(SOURCE_PATH)
    config = read_json(CONFIG_PATH)
    paths = acquire_source(args.cache, source, args.offline)
    categories = json.loads(paths["categories.json"].read_text(encoding="utf-8"))
    train_rows = read_rows(paths["train.csv"])
    test_rows = read_rows(paths["test.csv"])
    train, test, data_audit = prepare_data(train_rows, test_rows, categories)

    x_train = [row["text"] for row in train]
    y_train = [row["category"] for row in train]
    x_test = [row["text"] for row in test]
    y_test = [row["category"] for row in test]

    seed_results: list[dict[str, Any]] = []
    canonical_models: dict[str, Pipeline] = {}
    canonical_predictions: dict[str, np.ndarray] = {}
    canonical_probabilities: dict[str, np.ndarray] = {}

    for seed in config["sensitivitySeeds"]:
        per_seed: dict[str, Any] = {"seed": seed}
        for name, include_characters in (("wordOnly", False), ("wordPlusCharacter", True)):
            model = pipeline(config, seed, include_characters)
            model.fit(x_train, y_train)
            predictions = model.predict(x_test)
            probabilities = model.predict_proba(x_test)
            metrics = model_metrics(
                y_test,
                predictions,
                probabilities,
                model.named_steps["classifier"].classes_,
                config,
            )
            per_seed[name] = {
                key: metrics[key]
                for key in (
                    "accuracy",
                    "macroF1",
                    "logLoss",
                    "multiclassBrier",
                    "expectedCalibrationError",
                    "top3Accuracy",
                )
            }
            if seed == config["canonicalSeed"]:
                canonical_models[name] = model
                canonical_predictions[name] = predictions
                canonical_probabilities[name] = probabilities
                per_seed[name]["riskCoverage"] = metrics["riskCoverage"]
        per_seed["pairedMacroF1Delta"] = (
            per_seed["wordPlusCharacter"]["macroF1"] - per_seed["wordOnly"]["macroF1"]
        )
        seed_results.append(per_seed)

    canonical_seed_result = next(
        result for result in seed_results if result["seed"] == config["canonicalSeed"]
    )
    word_model = canonical_models["wordOnly"]
    candidate_model = canonical_models["wordPlusCharacter"]
    word_classes = word_model.named_steps["classifier"].classes_
    candidate_classes = candidate_model.named_steps["classifier"].classes_
    if not np.array_equal(word_classes, candidate_classes):
        raise RuntimeError("Matched classifiers produced different class inventories")
    class_to_index = {label: index for index, label in enumerate(candidate_classes.tolist())}
    y_test_index = np.array([class_to_index[label] for label in y_test], dtype=np.int64)
    word_index = np.array(
        [class_to_index[label] for label in canonical_predictions["wordOnly"].tolist()],
        dtype=np.int64,
    )
    candidate_index = np.array(
        [class_to_index[label] for label in canonical_predictions["wordPlusCharacter"].tolist()],
        dtype=np.int64,
    )
    bootstrap = bootstrap_macro_f1(
        y_test_index,
        word_index,
        candidate_index,
        np.arange(len(candidate_classes)),
        config["bootstrapDraws"],
        config["bootstrapSeed"],
    )

    majority_label = sorted(Counter(y_train).items(), key=lambda item: (-item[1], item[0]))[0][0]
    majority_predictions = np.array([majority_label] * len(y_test), dtype=object)
    majority = simple_metrics(y_test, majority_predictions, categories)

    naive_bayes = Pipeline(
        [
            ("features", word_features(config)),
            ("classifier", ComplementNB(alpha=config["naiveBayesAlpha"])),
        ]
    )
    naive_bayes.fit(x_train, y_train)
    naive_bayes_predictions = naive_bayes.predict(x_test)
    naive_bayes_probabilities = naive_bayes.predict_proba(x_test)
    naive_bayes_metrics = model_metrics(
        y_test,
        naive_bayes_predictions,
        naive_bayes_probabilities,
        naive_bayes.named_steps["classifier"].classes_,
        config,
    )

    shuffle_rng = np.random.default_rng(config["shuffleSeed"])
    shuffled_y = shuffle_rng.permutation(np.array(y_train, dtype=object))
    shuffled_model = pipeline(config, config["canonicalSeed"], True)
    shuffled_model.fit(x_train, shuffled_y)
    shuffled_predictions = shuffled_model.predict(x_test)
    shuffled = simple_metrics(y_test, shuffled_predictions, categories)
    shuffle_passed = (
        shuffled["accuracy"] <= config["shuffleControlMaximumAccuracy"]
        and shuffled["macroF1"] <= config["shuffleControlMaximumMacroF1"]
    )
    if not shuffle_passed:
        raise RuntimeError(f"Label-shuffled leakage control failed: {shuffled}")

    typo_pairs = [seeded_typo(text, config["typoSeed"]) for text in x_test]
    typo_text = [value for value, _ in typo_pairs]
    typo_changed = np.array([changed for _, changed in typo_pairs], dtype=bool)
    if not typo_changed.any():
        raise RuntimeError("Seeded typo stress generated zero eligible cases")
    typo_word_predictions = word_model.predict(typo_text)
    typo_candidate_predictions = candidate_model.predict(typo_text)
    clean_word_macro = canonical_seed_result["wordOnly"]["macroF1"]
    clean_candidate_macro = canonical_seed_result["wordPlusCharacter"]["macroF1"]
    typo_word_macro = float(
        f1_score(y_test, typo_word_predictions, average="macro", labels=categories)
    )
    typo_candidate_macro = float(
        f1_score(y_test, typo_candidate_predictions, average="macro", labels=categories)
    )

    precision_word, recall_word, f1_word, support = precision_recall_fscore_support(
        y_test,
        canonical_predictions["wordOnly"],
        labels=categories,
        zero_division=0,
    )
    precision_candidate, recall_candidate, f1_candidate, _ = precision_recall_fscore_support(
        y_test,
        canonical_predictions["wordPlusCharacter"],
        labels=categories,
        zero_division=0,
    )
    per_intent = {
        "schemaVersion": "waggle.banking77.per-intent.v1",
        "primaryTestCases": len(test),
        "intents": [
            {
                "intent": label,
                "support": int(support[index]),
                "wordOnly": {
                    "precision": float(precision_word[index]),
                    "recall": float(recall_word[index]),
                    "f1": float(f1_word[index]),
                },
                "wordPlusCharacter": {
                    "precision": float(precision_candidate[index]),
                    "recall": float(recall_candidate[index]),
                    "f1": float(f1_candidate[index]),
                },
                "f1Delta": float(f1_candidate[index] - f1_word[index]),
            }
            for index, label in enumerate(categories)
        ],
    }

    probability_scale = config["probabilityScale"]
    predictions_path = args.output / "predictions.jsonl"
    args.output.mkdir(parents=True, exist_ok=True)
    prediction_lines: list[str] = []
    candidate_probabilities = canonical_probabilities["wordPlusCharacter"]
    for index, (row, probabilities) in enumerate(zip(test, candidate_probabilities)):
        ranking = sorted(
            range(len(candidate_classes)),
            key=lambda class_index: (-probabilities[class_index], candidate_classes[class_index]),
        )[:3]
        top_three = [
            {
                "intent": str(candidate_classes[class_index]),
                "probabilityPpm": int(round(float(probabilities[class_index]) * probability_scale)),
            }
            for class_index in ranking
        ]
        normalized = normalize_text(row["text"])
        case_id = f"banking77_{sha256_text(normalized)[:20]}"
        prediction_record = {
            "caseId": case_id,
            "sourceSplit": "test",
            "sourceIndex": int(row["sourceIndex"]),
            "trueIntent": row["category"],
            "wordOnlyIntent": str(canonical_predictions["wordOnly"][index]),
            "predictedIntent": str(canonical_predictions["wordPlusCharacter"][index]),
            "confidencePpm": top_three[0]["probabilityPpm"],
            "top3": top_three,
            "typoEligible": bool(typo_changed[index]),
            "textIncluded": False,
        }
        prediction_lines.append(json.dumps(prediction_record, sort_keys=True, separators=(",", ":")))
    predictions_path.write_text("\n".join(prediction_lines) + "\n", encoding="utf-8")

    paired_delta = canonical_seed_result["pairedMacroF1Delta"]
    delta_interval = bootstrap["pairedDeltaMacroF1Interval95"]
    scientific_verdict = (
        "H1_SUPPORTED_EXPLORATORY" if paired_delta > 0 and delta_interval[0] > 0 else "H0_RETAINED"
    )
    non_claims = [
        "No HSBC or private customer data were used.",
        "No production routing, customer-benefit, or operational-readiness claim is made.",
        "No demographic fairness, accessibility, or regulatory-compliance claim is made.",
        "No LLM, latent-state, private Qwen, or native-state reproduction claim is made.",
        "The seeded typo stress does not establish natural-noise or out-of-distribution robustness.",
        "No adversarial-security or writer-authentication claim is made.",
        "No cross-dataset, cross-language, or cross-domain generalization claim is made.",
        "No token, cost, latency, memory, energy, or total-resource saving is claimed.",
        "No decoded prediction grants autonomous execution authority.",
    ]
    run = {
        "schemaVersion": "waggle.banking77.benchmark.v1",
        "runId": "banking77-reference-v1",
        "status": "exploratory-valid",
        "scientificVerdict": scientific_verdict,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "author": "William Keenan",
        "researchQuestion": (
            "On a train-disjoint BANKING77 test set, does a word-and-character classifier "
            "improve intent classification over a matched word-only model, and can Waggle/Kea "
            "transmit its frozen predictions without changing routing decisions while failing "
            "closed on specified detectable faults?"
        ),
        "evidenceClass": "exploratory-public-benchmark",
        "preRegistered": False,
        "testInformedDesign": True,
        "source": {
            "dataset": source["dataset"],
            "upstreamRepository": source["upstreamRepository"],
            "upstreamCommit": source["upstreamCommit"],
            "license": source["license"],
            "files": source["files"],
        },
        "dataAudit": data_audit,
        "configuration": config,
        "classification": {
            "primaryMetric": "paired macro-F1 difference",
            "canonicalSeed": config["canonicalSeed"],
            "canonical": canonical_seed_result,
            "seedSensitivity": seed_results,
            "pairedBootstrap": bootstrap,
            "majorityControl": {"label": majority_label, **majority},
            "complementNaiveBayes": {
                key: naive_bayes_metrics[key]
                for key in (
                    "accuracy",
                    "macroF1",
                    "logLoss",
                    "multiclassBrier",
                    "expectedCalibrationError",
                    "top3Accuracy",
                )
            },
            "shuffledLabelControl": {
                **shuffled,
                "maximumAccuracy": config["shuffleControlMaximumAccuracy"],
                "maximumMacroF1": config["shuffleControlMaximumMacroF1"],
                "passed": shuffle_passed,
            },
        },
        "seededTypoStress": {
            "method": "one SHA-256-selected internal character deletion in one word of at least five ASCII letters",
            "seed": config["typoSeed"],
            "primaryCases": len(test),
            "changedCases": int(typo_changed.sum()),
            "wordOnly": {
                "cleanMacroF1": clean_word_macro,
                "stressedMacroF1": typo_word_macro,
                "absoluteDrop": clean_word_macro - typo_word_macro,
            },
            "wordPlusCharacter": {
                "cleanMacroF1": clean_candidate_macro,
                "stressedMacroF1": typo_candidate_macro,
                "absoluteDrop": clean_candidate_macro - typo_candidate_macro,
            },
            "claimBoundary": "deterministic synthetic sensitivity only; not natural-noise validation",
        },
        "predictionArtifact": {
            "rows": len(prediction_lines),
            "textIncluded": False,
            "path": "predictions.jsonl",
            "sha256": sha256_bytes(predictions_path.read_bytes()),
        },
        "effects": {
            "providerApiCalls": 0,
            "modelApiCalls": 0,
            "trainingRuns": len(config["sensitivitySeeds"]) * 2 + 2,
            "authorityEffectsExecuted": 0,
        },
        "nonClaims": non_claims,
    }

    environment = {
        "schemaVersion": "waggle.banking77.environment.v1",
        "python": sys.version,
        "pythonExecutable": Path(sys.executable).name,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "dependencies": {
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "scikitLearn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "scoredPhaseNetworkCalls": 0,
        "providerApiCalls": 0,
    }
    write_json(args.output / "run.json", run)
    write_json(args.output / "per-intent.json", per_intent)
    write_json(args.output / "environment.json", environment)
    print(json.dumps({
        "ok": True,
        "output": str(args.output),
        "primaryTestCases": len(test),
        "wordOnlyMacroF1": canonical_seed_result["wordOnly"]["macroF1"],
        "wordPlusCharacterMacroF1": canonical_seed_result["wordPlusCharacter"]["macroF1"],
        "pairedMacroF1Delta": paired_delta,
        "pairedDeltaInterval95": delta_interval,
        "scientificVerdict": scientific_verdict,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
