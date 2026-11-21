"""Descriptive within-dataset distribution checks. No tuning or significance claims."""

import hashlib
import statistics
from collections import Counter
from pathlib import Path

VERSION = "http-input-drift-v1-20261122"
CODE_HASH = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
PARAMETERS = {
    "minimum_windows": 12,
    "minimum_eligible_fraction": 0.9,
    "volume_ecdf_distance": 0.35,
    "minimum_median_delta": 10,
    "relative_median_delta": 0.5,
    "error_share_delta": 0.1,
    "minimum_requests_for_error_share": 100,
}


def ecdf_distance(reference, comparison):
    """Two-sided empirical CDF distance, not a hypothesis test/p-value."""
    if not reference or not comparison:
        raise ValueError("Both observed samples must be nonempty")
    a, b = Counter(reference), Counter(comparison)
    left = right = 0
    distance = 0.0
    for value in sorted(set(a) | set(b)):
        left += a[value]
        right += b[value]
        distance = max(distance, abs(left / len(reference) - right / len(comparison)))
    return round(distance, 8)


def valid_count(value):
    return type(value) is int and value >= 0


def quality(windows, truth):
    eligible = [w for w in windows if w.get("eligible") is True]
    return {
        "total_windows": len(windows),
        "eligible_windows": len(eligible),
        "eligible_fraction": len(eligible) / len(windows) if windows else 0,
        "excluded_windows": len(windows) - len(eligible),
        "label_context": dict(
            Counter(truth.get(w["index"], "unknown") for w in eligible)
        ),
        "invalid_volume_windows": sum(
            not valid_count(w.get("requests")) for w in eligible
        ),
        "missing_or_invalid_error_windows": sum(
            not valid_count(w.get("errors"))
            or not valid_count(w.get("requests"))
            or w.get("errors", 0) > w.get("requests", 0)
            for w in eligible
        ),
    }


def compare(training, comparison, truth):
    base_quality, observed_quality = (
        quality(training, truth),
        quality(comparison, truth),
    )
    result = {
        "baseline_quality": base_quality,
        "comparison_quality": observed_quality,
        "volume": None,
        "error_share": None,
        "scope": "All eligible comparison traffic, including unknown/lab windows; not a normal-only population or detection-quality estimate",
    }
    if (
        observed_quality["eligible_windows"] < PARAMETERS["minimum_windows"]
        or observed_quality["eligible_fraction"]
        < PARAMETERS["minimum_eligible_fraction"]
    ):
        return {
            **result,
            "state": "insufficient_coverage",
            "reason": "Need at least 12 eligible comparison windows and 90% eligible coverage; missing windows are not zero traffic",
        }
    if observed_quality["invalid_volume_windows"]:
        return {
            **result,
            "state": "invalid_volume_features",
            "reason": "Eligible windows contain invalid/missing request counts; no clean comparison",
        }
    a = [w["requests"] for w in training]
    b = [w["requests"] for w in comparison if w.get("eligible") is True]
    am, bm = statistics.median(a), statistics.median(b)
    delta = bm - am
    distance = ecdf_distance(a, b)
    volume_candidate = distance >= PARAMETERS["volume_ecdf_distance"] and abs(
        delta
    ) >= max(
        PARAMETERS["minimum_median_delta"], PARAMETERS["relative_median_delta"] * am
    )
    result["volume"] = {
        "state": "candidate_change"
        if volume_candidate
        else "no_candidate_under_fixed_rules",
        "ecdf_distance": distance,
        "baseline_median": am,
        "comparison_median": bm,
        "median_delta": delta,
        "median_ratio": bm / am if am else None,
        "baseline_mean": statistics.mean(a),
        "comparison_mean": statistics.mean(b),
        "baseline_zero_share": a.count(0) / len(a),
        "comparison_zero_share": b.count(0) / len(b),
        "p_value": None,
        "statistical_significance_claimed": False,
    }
    error_candidate = False
    if (
        base_quality["missing_or_invalid_error_windows"]
        or observed_quality["missing_or_invalid_error_windows"]
    ):
        result["error_share"] = {
            "state": "missing_or_invalid_features",
                "reason": "Error counts unavailable or outside 0..requests; no zero substitution",
        }
    else:
        ar, br = sum(a), sum(b)
        if min(ar, br) < PARAMETERS["minimum_requests_for_error_share"]:
            result["error_share"] = {
                "state": "insufficient_requests",
                "baseline_requests": ar,
                "comparison_requests": br,
                "reason": "Need at least 100 requests in each period for an error-share comparison",
            }
        else:
            ae = sum(w["errors"] for w in training) / ar
            be = sum(w["errors"] for w in comparison if w.get("eligible") is True) / br
            difference = be - ae
            error_candidate = abs(difference) >= PARAMETERS["error_share_delta"] - 1e-12
            result["error_share"] = {
                "state": "candidate_change"
                if error_candidate
                else "no_candidate_under_fixed_rules",
                "baseline_share": ae,
                "comparison_share": be,
                "share_delta": difference,
                "baseline_requests": ar,
                "comparison_requests": br,
                "definition": "Stored status>=400 counts / all stored requests; unknown statuses can bias this share",
            }
    result["state"] = (
        "candidate_input_change"
        if volume_candidate or error_candidate
        else "partial_feature_coverage"
        if result["error_share"]["state"]
        in ("missing_or_invalid_features", "insufficient_requests")
        else "no_candidate_under_fixed_rules"
    )
    result["reason"] = (
        "Descriptive fixed-rule signal only; lab activity, seasonality, attacks, logging or traffic mix can explain changes. No automatic retraining/threshold change."
    )
    return result


def summarize(windows, truth, train_end, test_start):
    training = windows[:train_end]
    result = {
        "version": VERSION,
        "implementation_sha256": CODE_HASH,
        "parameters": PARAMETERS.copy(),
        "scope": "Frozen training versus later splits within the same exact host/router dataset; no cross-asset pooling, p-values, causal drift or accuracy claims",
        "split_indices": {
            "training": [0, train_end],
            "calibration": [train_end, test_start],
            "test": [test_start, len(windows)],
            "end_exclusive": True,
        },
        "baseline_quality": quality(training, truth),
        "comparisons": {},
    }
    if len(training) < PARAMETERS["minimum_windows"] or any(
        w.get("eligible") is not True or truth.get(w["index"]) != "normal"
        for w in training
    ):
        return {
            **result,
            "state": "baseline_not_ready",
            "reason": "All training windows must be eligible, explicitly labeled normal and at least 12 in number",
        }
    if result["baseline_quality"]["invalid_volume_windows"]:
        return {
            **result,
            "state": "invalid_baseline_features",
            "reason": "Training request counts are missing/invalid",
        }
    result["state"] = "descriptive_only"
    result["comparisons"] = {
        "calibration": compare(training, windows[train_end:test_start], truth),
        "test": compare(training, windows[test_start:], truth),
    }
    return result
