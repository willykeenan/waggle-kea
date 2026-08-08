#!/usr/bin/env python3
"""Deterministic public ML state generator for decision-sufficiency v0.3.

Full mode loads the pinned BANKING77 source and classifier contracts, trains only
the canonical word-plus-character SGD pipeline, integerizes every 77-class
probability vector with stable largest-remainder quantization to exactly
1,000,000 units, and emits text-free content-addressed vector/run/environment
artifacts.

Synthetic --self-test validates quantization, tie allocation, vector identity,
and malformed-mass refusal without loading BANKING77 or making network calls.
"""

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
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence


HERE = Path(__file__).resolve().parent
BANKING77 = HERE.parent / "banking77"
SOURCE_PATH = BANKING77 / "SOURCE.json"
CLASSIFIER_CONFIG_PATH = BANKING77 / "config.v1.json"
CONFIG_PATH = HERE / "config.v1.json"
DEFAULT_CACHE = HERE / ".cache" / "source"
DEFAULT_OUTPUT = HERE / "results" / "local-v1"

PROBABILITY_SCALE = 1_000_000
VECTOR_SCHEMA = "waggle.decision-sufficiency.vector.v1"
RUN_SCHEMA = "waggle.decision-sufficiency.run.v1"
ENVIRONMENT_SCHEMA = "waggle.decision-sufficiency.environment.v1"
MODEL_ID = "model_banking77_word_char_sgd_v1"


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


def canonical_json(value: Any) -> str:
    """Match Kea/Waggle canonical JSON: sorted keys, compact separators."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_id(prefix: str, value: Any) -> str:
    return f"{prefix}_{sha256_text(canonical_json(value))[:20]}"


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_probability_vector(
    probabilities: Sequence[int],
    scale: int,
    label_count: int | None = None,
) -> None:
    require(isinstance(scale, int) and not isinstance(scale, bool), "probabilityScale must be an integer")
    require(1 <= scale <= 1_000_000_000, "probabilityScale is outside range")
    require(isinstance(probabilities, Sequence) and not isinstance(probabilities, (str, bytes)), "probabilities must be a sequence")
    require(2 <= len(probabilities) <= 1_024, "probability vector length is invalid")
    if label_count is not None:
        require(len(probabilities) == label_count, "probability vector length mismatch")
    total = 0
    for index, value in enumerate(probabilities):
        require(isinstance(value, int) and not isinstance(value, bool), f"probabilities[{index}] must be an integer")
        require(0 <= value <= scale, f"probabilities[{index}] is outside range")
        total += value
    require(total == scale, f"probability vector must sum exactly to {scale}")


def decision_vector_id(probabilities: Sequence[int], probability_scale: int) -> str:
    validate_probability_vector(probabilities, probability_scale)
    return content_id(
        "decisionvector",
        {
            "probabilityScale": probability_scale,
            "probabilities": list(probabilities),
        },
    )


def quantize_largest_remainder(
    probabilities: Sequence[float],
    scale: int = PROBABILITY_SCALE,
) -> list[int]:
    """Stable Hamilton largest-remainder quantization to exact integer mass.

    Fractional remainder ties allocate leftover units by ascending component
    index so the mapping is deterministic and independent of input order noise.
    """
    require(isinstance(scale, int) and not isinstance(scale, bool), "scale must be an integer")
    require(scale >= 1, "scale must be positive")
    require(isinstance(probabilities, Sequence) and not isinstance(probabilities, (str, bytes)), "probabilities must be a sequence")
    require(len(probabilities) >= 2, "probability vector length is invalid")

    values: list[float] = []
    for index, raw in enumerate(probabilities):
        require(isinstance(raw, (int, float)) and not isinstance(raw, bool), f"probabilities[{index}] must be numeric")
        value = float(raw)
        require(math.isfinite(value), f"probabilities[{index}] is non-finite")
        require(value >= 0.0, f"probabilities[{index}] is negative")
        values.append(value)

    total = sum(values)
    require(total > 0.0, "probability mass must be positive")

    scaled = [value * scale / total for value in values]
    floors = [math.floor(value) for value in scaled]
    remainders = [scaled[index] - floors[index] for index in range(len(scaled))]
    units = [int(floor) for floor in floors]
    leftover = scale - sum(units)
    require(leftover >= 0, "internal floor mass exceeded scale")

    # Largest remainder first; equal remainders break ties by lower index.
    order = sorted(range(len(units)), key=lambda index: (-remainders[index], index))
    for index in order[:leftover]:
        units[index] += 1

    require(sum(units) == scale, "quantization failed to conserve mass")
    require(all(unit >= 0 for unit in units), "quantization produced a negative unit")
    return units


def normalize_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


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
                headers={"User-Agent": "waggle-kea-decision-sufficiency/0.3"},
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


def word_character_pipeline(config: Mapping[str, Any], seed: int) -> Any:
    """Build the unchanged canonical word-plus-character SGD classifier."""
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import SGDClassifier
    from sklearn.pipeline import FeatureUnion, Pipeline

    word = config["wordFeatures"]
    character = config["characterFeatures"]
    model = config["classifier"]
    features = FeatureUnion(
        [
            (
                "word",
                TfidfVectorizer(
                    analyzer=word["analyzer"],
                    ngram_range=tuple(word["ngramRange"]),
                    min_df=word["minDf"],
                    max_features=word["maxFeatures"],
                    sublinear_tf=word["sublinearTf"],
                    dtype=np.float64,
                ),
            ),
            (
                "character",
                TfidfVectorizer(
                    analyzer=character["analyzer"],
                    ngram_range=tuple(character["ngramRange"]),
                    min_df=character["minDf"],
                    max_features=character["maxFeatures"],
                    sublinear_tf=character["sublinearTf"],
                    dtype=np.float64,
                ),
            ),
        ]
    )
    classifier = SGDClassifier(
        loss=model["loss"],
        alpha=model["alpha"],
        max_iter=model["maxIter"],
        tol=model["tolerance"],
        random_state=seed,
        n_jobs=model["jobs"],
        shuffle=True,
    )
    return Pipeline([("features", features), ("classifier", classifier)])


def run_full(offline: bool, cache: Path, output: Path) -> int:
    source = read_json(SOURCE_PATH)
    classifier_config = read_json(CLASSIFIER_CONFIG_PATH)
    decision_config = read_json(CONFIG_PATH)

    require(decision_config["schemaVersion"] == "waggle.decision-sufficiency.config.v1", "unexpected decision config schema")
    require(decision_config["probabilityScale"] == PROBABILITY_SCALE, "probabilityScale must be 1000000")
    require(decision_config["canonicalSeed"] == classifier_config["canonicalSeed"], "canonical seed drift")
    require(decision_config["sourceContract"] == "../banking77/SOURCE.json", "source contract path drift")
    require(decision_config["classifierContract"] == "../banking77/config.v1.json", "classifier contract path drift")
    require(decision_config["effects"]["providerApiCallsMaximum"] == 0, "provider effects must remain zero")
    require(decision_config["effects"]["modelApiCallsMaximum"] == 0, "model API effects must remain zero")
    require(decision_config["effects"]["authorityEffectsMaximum"] == 0, "authority effects must remain zero")

    paths = acquire_source(cache, source, offline)
    categories = json.loads(paths["categories.json"].read_text(encoding="utf-8"))
    train_rows = read_rows(paths["train.csv"])
    test_rows = read_rows(paths["test.csv"])
    train, test, data_audit = prepare_data(train_rows, test_rows, categories)

    x_train = [row["text"] for row in train]
    y_train = [row["category"] for row in train]
    x_test = [row["text"] for row in test]

    seed = int(classifier_config["canonicalSeed"])
    model = word_character_pipeline(classifier_config, seed)
    model.fit(x_train, y_train)
    probabilities = model.predict_proba(x_test)
    # Label order must match predict_proba column order (sklearn classes_), not categories.json order.
    label_ids = [str(label) for label in model.named_steps["classifier"].classes_.tolist()]
    if len(label_ids) != 77 or set(label_ids) != set(categories):
        raise RuntimeError("Classifier label inventory drifted from BANKING77 categories")
    if len(label_ids) != len(set(label_ids)):
        raise RuntimeError("Classifier label inventory contains duplicates")
    if len(test) != len(probabilities):
        raise RuntimeError(
            f"Primary test row count ({len(test)}) does not match predict_proba rows ({len(probabilities)})"
        )

    output.mkdir(parents=True, exist_ok=True)
    vectors_path = output / "vectors.jsonl"
    lines: list[str] = []
    case_ids: set[str] = set()
    for row, probability_row in zip(test, probabilities):
        units = quantize_largest_remainder(probability_row.tolist(), PROBABILITY_SCALE)
        validate_probability_vector(units, PROBABILITY_SCALE, label_count=77)
        vector_id = decision_vector_id(units, PROBABILITY_SCALE)
        normalized = normalize_text(row["text"])
        case_id = f"banking77_{sha256_text(normalized)[:20]}"
        require(case_id not in case_ids, f"duplicate caseId after normalization: {case_id}")
        case_ids.add(case_id)
        record = {
            "schemaVersion": VECTOR_SCHEMA,
            "caseId": case_id,
            "sourceSplit": "test",
            "sourceIndex": int(row["sourceIndex"]),
            "trueIntent": row["category"],
            "vectorId": vector_id,
            "probabilityScale": PROBABILITY_SCALE,
            # Same order as probabilities[] indices and run.labelIds.
            "labelIds": label_ids,
            "probabilities": units,
            "textIncluded": False,
            "modelId": MODEL_ID,
        }
        # Never emit source text.
        require("text" not in record, "source text leaked into vector artifact")
        require("sourceText" not in record, "source text leaked into vector artifact")
        require("utterance" not in record, "source text leaked into vector artifact")
        require(record["textIncluded"] is False, "vector artifact must mark text as excluded")
        lines.append(canonical_json(record))

    vectors_payload = ("\n".join(lines) + "\n").encode("utf-8")
    vectors_path.write_bytes(vectors_payload)

    run_identity = {
        "schemaVersion": "waggle.decision-sufficiency.run-identity.v1",
        "sourceContractSha256": sha256_bytes(SOURCE_PATH.read_bytes()),
        "classifierContractSha256": sha256_bytes(CLASSIFIER_CONFIG_PATH.read_bytes()),
        "decisionConfigSha256": sha256_bytes(CONFIG_PATH.read_bytes()),
        "vectorsSha256": sha256_bytes(vectors_payload),
    }
    run_body = {
        "schemaVersion": RUN_SCHEMA,
        "status": decision_config["status"],
        "author": "William Keenan",
        "evidenceClass": "preregistered-prospective-secondary-analysis",
        "runIdentity": run_identity,
        # Top-level inventory is required by the evaluator loader (run.labelIds / run.probabilityScale).
        # Order is classifier class order and must match every vector's probabilities[] indices.
        "labelIds": label_ids,
        "probabilityScale": PROBABILITY_SCALE,
        "source": {
            "dataset": source["dataset"],
            "upstreamRepository": source["upstreamRepository"],
            "upstreamCommit": source["upstreamCommit"],
            "license": source["license"],
            "citation": source["citation"],
            "files": source["files"],
            "contractPath": "benchmarks/banking77/SOURCE.json",
        },
        "dataAudit": data_audit,
        "configuration": decision_config,
        "classifierContract": classifier_config,
        "model": {
            "modelId": MODEL_ID,
            "representation": "wordPlusCharacter",
            "classifier": classifier_config["classifier"],
            "wordFeatures": classifier_config["wordFeatures"],
            "characterFeatures": classifier_config["characterFeatures"],
            "canonicalSeed": seed,
            "labelIds": label_ids,
            "labelCount": len(label_ids),
            "probabilityScale": PROBABILITY_SCALE,
            "quantization": "stable-largest-remainder",
        },
        "resources": {
            "trainingRuns": 1,
            "scoredCases": len(test),
            "vectorComponents": 77,
        },
        "vectorArtifact": {
            "rows": len(lines),
            "textIncluded": False,
            "path": "vectors.jsonl",
            "sha256": sha256_bytes(vectors_payload),
            "probabilityScale": PROBABILITY_SCALE,
            "contentAddressed": True,
            "vectorIdPrefix": "decisionvector_",
        },
        "effects": {
            "providerApiCalls": 0,
            "modelApiCalls": 0,
            "authorityEffectsExecuted": 0,
            "trainingRuns": 1,
        },
        "nonClaims": [
            "Source text is excluded from all committed prediction-state artifacts.",
            "No provider API, remote model API, or authority effect is executed.",
            "This artifact freezes public ML state only; it does not evaluate decision sufficiency.",
            "No autonomous execution authority is granted by any vector or run artifact.",
        ],
    }
    # The cross-runtime ID hashes an integer/string-only manifest. The richer
    # run body contains floating-point policy metadata whose JSON number lexemes
    # differ between Python and JavaScript (for example 1e-05 vs 0.00001).
    run = {**run_body, "runId": content_id("decisionrun", run_identity)}
    write_json(output / "run.json", run)

    import joblib
    import numpy as np
    import scipy
    import sklearn

    environment = {
        "schemaVersion": ENVIRONMENT_SCHEMA,
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
        "modelApiCalls": 0,
        "authorityEffectsExecuted": 0,
    }
    write_json(output / "environment.json", environment)

    print(
        json.dumps(
            {
                "ok": True,
                "output": str(output),
                "primaryTestCases": len(test),
                "vectorRows": len(lines),
                "probabilityScale": PROBABILITY_SCALE,
                "providerApiCalls": 0,
                "modelApiCalls": 0,
                "authorityEffectsExecuted": 0,
                "textIncluded": False,
            },
            sort_keys=True,
        )
    )
    return 0


def _assert_equal(actual: Any, expected: Any, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def run_self_test() -> int:
    """Synthetic checks only: no BANKING77 load, no network, no sklearn."""
    scale = PROBABILITY_SCALE

    # 1) Quantization conserves exact mass.
    equal = quantize_largest_remainder([1.0, 1.0, 1.0], scale)
    _assert_equal(sum(equal), scale, "equal-triple mass sum")
    _assert_equal(len(equal), 3, "equal-triple length")
    require(all(unit >= 0 for unit in equal), "equal-triple negativity")

    skewed = quantize_largest_remainder([0.7, 0.1, 0.1, 0.1], scale)
    _assert_equal(sum(skewed), scale, "skewed mass sum")
    _assert_equal(skewed[0], 700_000, "skewed top mass")

    already_normalized = quantize_largest_remainder([0.25, 0.25, 0.5], 8)
    _assert_equal(sum(already_normalized), 8, "small-scale mass sum")

    # Renormalization of non-unit mass still conserves the declared scale.
    unnormalized = quantize_largest_remainder([2.0, 1.0, 1.0], 100)
    _assert_equal(sum(unnormalized), 100, "unnormalized mass sum")
    _assert_equal(unnormalized, [50, 25, 25], "unnormalized allocation")

    # 2) Deterministic remainder-tie allocation (lower index wins).
    # Equal remainders of 0.5 with scale 3: floors [1,1], leftover 1 -> index 0.
    tied = quantize_largest_remainder([0.5, 0.5], 3)
    _assert_equal(tied, [2, 1], "two-way remainder tie")

    # Four equal quarters, scale 10: floors all 2, leftover 2 -> indices 0 then 1.
    quarter_ties = quantize_largest_remainder([0.25, 0.25, 0.25, 0.25], 10)
    _assert_equal(quarter_ties, [3, 3, 2, 2], "four-way remainder tie")

    # Three equal thirds at ppm scale: floors 333333 each, leftover 1 -> index 0.
    thirds = quantize_largest_remainder([1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0], scale)
    _assert_equal(thirds, [333_334, 333_333, 333_333], "three-way remainder tie at scale")

    # Re-running the same input must be bit-identical.
    _assert_equal(
        quantize_largest_remainder([0.4, 0.3, 0.2, 0.1], scale),
        quantize_largest_remainder([0.4, 0.3, 0.2, 0.1], scale),
        "quantization determinism",
    )

    # 3) Vector identity is content-addressed and stable.
    vector = [700_000, 100_000, 100_000, 100_000]
    vector_id = decision_vector_id(vector, scale)
    _assert_equal(vector_id, decision_vector_id(list(vector), scale), "vector identity stability")
    _assert_equal(vector_id, "decisionvector_fc17e20da1fc50a23c20", "vector identity golden value")
    require(vector_id.startswith("decisionvector_"), "vector identity prefix")
    require(len(vector_id) == len("decisionvector_") + 20, "vector identity length")
    require(all(character in "0123456789abcdef" for character in vector_id.split("_", 1)[1]), "vector identity hex")
    # Canonical object hashing must be independent of key insertion order.
    _assert_equal(
        content_id(
            "decisionvector",
            {"probabilities": list(vector), "probabilityScale": scale},
        ),
        vector_id,
        "vector identity key-order independence",
    )

    other = [600_000, 200_000, 100_000, 100_000]
    other_id = decision_vector_id(other, scale)
    require(other_id != vector_id, "distinct vectors must not share identity")
    _assert_equal(
        decision_vector_id([333_334, 333_333, 333_333], scale),
        "decisionvector_ce9898f53cd598e80d9b",
        "tied-vector identity golden value",
    )

    # 4) Malformed mass is refused (integer vectors and float quantization).
    refusals: list[tuple[str, Any]] = []

    def expect_refusal(label: str, action: Any) -> None:
        try:
            action()
        except (ValueError, TypeError, AssertionError):
            refusals.append((label, "ok"))
            return
        raise AssertionError(f"expected refusal for {label}")

    expect_refusal("short-sum", lambda: validate_probability_vector([700_000, 100_000, 100_000, 99_999], scale))
    expect_refusal("over-sum", lambda: validate_probability_vector([700_000, 100_000, 100_000, 100_001], scale))
    expect_refusal("negative-int", lambda: validate_probability_vector([700_001, 100_000, 100_000, -1], scale))
    expect_refusal("non-int", lambda: validate_probability_vector([700_000.5, 100_000, 100_000, 99_999.5], scale))  # type: ignore[list-item]
    expect_refusal("empty", lambda: validate_probability_vector([], scale))
    expect_refusal("singleton", lambda: validate_probability_vector([scale], scale))
    expect_refusal("bad-scale", lambda: validate_probability_vector(vector, 0))
    expect_refusal("negative-float", lambda: quantize_largest_remainder([0.5, -0.1, 0.6], scale))
    expect_refusal("nan-float", lambda: quantize_largest_remainder([0.5, float("nan"), 0.5], scale))
    expect_refusal("inf-float", lambda: quantize_largest_remainder([0.5, float("inf"), 0.5], scale))
    expect_refusal("zero-mass", lambda: quantize_largest_remainder([0.0, 0.0, 0.0], scale))
    expect_refusal("too-short-float", lambda: quantize_largest_remainder([1.0], scale))

    # Identity helper must refuse malformed mass before hashing.
    expect_refusal("identity-short-sum", lambda: decision_vector_id([700_000, 100_000, 100_000, 99_999], scale))

    require(len(refusals) == 13, f"expected 13 refusals, got {len(refusals)}")

    print("RUNNER_SELF_TEST_OK")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate frozen decision-sufficiency prediction state from BANKING77",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run synthetic quantization/identity tests without loading BANKING77",
    )
    parser.add_argument("--offline", action="store_true", help="Require the verified local source cache")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()
    return run_full(offline=args.offline, cache=args.cache, output=args.output)


if __name__ == "__main__":
    raise SystemExit(main())
