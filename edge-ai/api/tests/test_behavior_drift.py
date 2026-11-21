"""Descriptive distribution checks: missing is never zero and future labels do not fit."""

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import behavior_drift as drift
from app import http_mix


def corpus():
    return [
        {"index": i, "eligible": True, "requests": 100, "errors": 0} for i in range(150)
    ], {i: "normal" for i in range(150)}


class DriftTests(unittest.TestCase):
    def test_http_mix_distinguishes_missing_sparse_and_shifted_distributions(self):
        training = [
            {
                "requests": 100,
                "http_mix": {
                    "method": {"GET": 100},
                    "status": {"2xx": 100},
                    "path_shape": {"unknown": 100},
                },
            }
        ]
        later = [
            {
                "requests": 100,
                "http_mix": {
                    "method": {"GET": 25, "POST": 75},
                    "status": {"2xx": 100},
                    "path_shape": {"unknown": 100},
                },
            }
        ]
        result = http_mix.compare(training, later)
        self.assertEqual(result["method"]["total_variation_distance"], 0.75)
        self.assertEqual(result["status"]["total_variation_distance"], 0)
        self.assertEqual(
            http_mix.compare(training, [{"requests": 100}])["method"][
                "comparison_state"
            ],
            "not_recorded",
        )
        self.assertEqual(
            http_mix.compare(
                training, [{"requests": 100, "http_mix": {"method": {"GET": 1}}}]
            )["method"]["comparison_state"],
            "invalid_histogram",
        )
        self.assertEqual(
            http_mix.compare(training, [{"requests": 0, "http_mix": {"method": {}}}])[
                "method"
            ]["state"],
            "insufficient_requests",
        )

    def test_empirical_distance_known_samples_and_ties(self):
        self.assertEqual(drift.ecdf_distance([0, 0, 1, 1], [0, 1]), 0)
        self.assertEqual(drift.ecdf_distance([0, 0], [1, 1]), 1)
        self.assertEqual(drift.ecdf_distance([0, 0, 1, 1], [0, 0, 0, 1]), 0.25)
        self.assertEqual(drift.ecdf_distance([1, 2, 3], [3, 2, 1]), 0)
        with self.assertRaises(ValueError):
            drift.ecdf_distance([], [])

    def test_stable_counts_and_sustained_shift_are_not_security_verdicts(self):
        windows, truth = corpus()
        stable = drift.summarize(windows, truth, 90, 120)
        self.assertEqual(
            stable["comparisons"]["test"]["state"], "no_candidate_under_fixed_rules"
        )
        for w in windows[120:]:
            w["requests"] = 200
        shifted = drift.summarize(windows, truth, 90, 120)
        self.assertEqual(
            shifted["comparisons"]["test"]["state"], "candidate_input_change"
        )
        self.assertEqual(shifted["comparisons"]["test"]["volume"]["median_ratio"], 2)
        self.assertFalse(
            shifted["comparisons"]["test"]["volume"]["statistical_significance_claimed"]
        )
        self.assertIsNone(shifted["comparisons"]["test"]["volume"]["p_value"])
        self.assertEqual(stable["baseline_quality"], shifted["baseline_quality"])

    def test_small_location_change_alone_is_not_flagged_by_distance(self):
        windows, truth = corpus()
        for w in windows[120:]:
            w["requests"] = 101
        result = drift.summarize(windows, truth, 90, 120)["comparisons"]["test"]
        self.assertEqual(result["volume"]["ecdf_distance"], 1)
        self.assertEqual(result["volume"]["state"], "no_candidate_under_fixed_rules")

    def test_error_share_can_shift_without_volume_shift(self):
        windows, truth = corpus()
        for w in windows[120:]:
            w["errors"] = 20
        report = drift.summarize(windows, truth, 90, 120)["comparisons"]["test"]
        self.assertEqual(report["volume"]["state"], "no_candidate_under_fixed_rules")
        self.assertEqual(report["error_share"]["share_delta"], 0.2)
        self.assertEqual(report["state"], "candidate_input_change")

    def test_gaps_and_short_period_never_pass_as_stable(self):
        windows, truth = corpus()
        for w in windows[120:125]:
            w["eligible"] = False
            w["requests"] = 999999
        result = drift.summarize(windows, truth, 90, 120)["comparisons"]["test"]
        self.assertEqual(result["state"], "insufficient_coverage")
        self.assertIsNone(result["volume"])
        self.assertEqual(result["comparison_quality"]["excluded_windows"], 5)
        result = drift.summarize(windows[:130], truth, 90, 120)["comparisons"]["test"]
        self.assertEqual(result["state"], "insufficient_coverage")
        windows, truth = corpus()
        truth[0] = "unknown"
        self.assertEqual(
            drift.summarize(windows, truth, 90, 120)["state"], "baseline_not_ready"
        )

    def test_missing_error_feature_and_zero_requests_are_not_zero_error_rate(self):
        windows, truth = corpus()
        for w in windows:
            w["requests"] = 0
        result = drift.summarize(windows, truth, 90, 120)["comparisons"]["test"]
        self.assertEqual(result["error_share"]["state"], "insufficient_requests")
        self.assertIsNone(result["volume"]["median_ratio"])
        windows, truth = corpus()
        windows[120].pop("errors")
        result = drift.summarize(windows, truth, 90, 120)["comparisons"]["test"]
        self.assertEqual(result["state"], "partial_feature_coverage")
        self.assertEqual(result["error_share"]["state"], "missing_or_invalid_features")

    def test_bad_counts_do_not_create_clean_result(self):
        windows, truth = corpus()
        windows[120]["requests"] = -1
        self.assertEqual(
            drift.summarize(windows, truth, 90, 120)["comparisons"]["test"]["state"],
            "invalid_volume_features",
        )
        windows, truth = corpus()
        windows[0]["requests"] = True
        self.assertEqual(
            drift.summarize(windows, truth, 90, 120)["state"],
            "invalid_baseline_features",
        )
        windows, truth = corpus()
        windows[120]["errors"] = 101
        self.assertEqual(
            drift.summarize(windows, truth, 90, 120)["comparisons"]["test"][
                "error_share"
            ]["state"],
            "missing_or_invalid_features",
        )

    def test_future_labels_change_context_only_and_future_counts_do_not_fit_baseline(
        self,
    ):
        windows, truth = corpus()
        first = drift.summarize(windows, truth, 90, 120)
        original = copy.deepcopy(windows)
        for i in range(120, 150):
            truth[i] = "lab_attack" if i % 2 else "unknown"
        second = drift.summarize(windows, truth, 90, 120)
        self.assertEqual(
            first["comparisons"]["test"]["volume"],
            second["comparisons"]["test"]["volume"],
        )
        self.assertEqual(
            first["comparisons"]["test"]["error_share"],
            second["comparisons"]["test"]["error_share"],
        )
        self.assertNotEqual(
            first["comparisons"]["test"]["comparison_quality"]["label_context"],
            second["comparisons"]["test"]["comparison_quality"]["label_context"],
        )
        self.assertEqual(windows, original)
        windows[-1]["requests"] = 100000
        third = drift.summarize(windows, truth, 90, 120)
        self.assertEqual(first["baseline_quality"], third["baseline_quality"])
        self.assertEqual(
            first["comparisons"]["calibration"], third["comparisons"]["calibration"]
        )
