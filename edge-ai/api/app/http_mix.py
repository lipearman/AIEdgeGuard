"""Coarse HTTP input categories for immutable evaluation snapshots."""

import hashlib
from pathlib import Path

CODE_HASH = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
BUCKETS = {
    "method": (
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "CONNECT",
        "TRACE",
        "other",
        "unknown",
    ),
    "status": ("1xx", "2xx", "3xx", "4xx", "5xx", "unknown"),
    "path_shape": ("root", "single_segment", "multiple_segments", "unknown"),
}
MIN_REQUESTS = 100

# Only fixed category names leave SQL. Literal paths, query values and arbitrary
# method strings never become snapshot keys.
QUERY = """
WITH selected AS (
 SELECT floor(extract(epoch FROM observed_at)/300)::bigint AS bucket,
        method, status, split_part(path,'?',1) AS target
 FROM gateway_requests WHERE host=%s AND router=%s AND observed_at>=%s AND observed_at<%s
)
SELECT bucket,feature,category,count(*) AS count FROM selected
CROSS JOIN LATERAL (VALUES
 ('method', CASE WHEN method IN ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','CONNECT','TRACE')
                 THEN method WHEN method='' THEN 'unknown' ELSE 'other' END),
 ('status', CASE WHEN status BETWEEN 100 AND 599 THEN (status/100)::text||'xx' ELSE 'unknown' END),
 ('path_shape', CASE WHEN target NOT LIKE '/%%' OR target LIKE '//%%' THEN 'unknown'
                     WHEN trim(both '/' from target)='' THEN 'root'
                     WHEN strpos(trim(both '/' from target),'/')=0 THEN 'single_segment'
                     ELSE 'multiple_segments' END)
) AS categories(feature,category)
GROUP BY bucket,feature,category
"""


def aggregate(windows, feature):
    counts = dict.fromkeys(BUCKETS[feature], 0)
    for window in windows:
        histogram = window.get("http_mix", {}).get(feature)
        if histogram is None:
            return "not_recorded", None
        if (
            not isinstance(histogram, dict)
            or histogram.keys() - counts.keys()
            or any(type(value) is not int or value < 0 for value in histogram.values())
            or sum(histogram.values()) != window["requests"]
        ):
            return "invalid_histogram", None
        for category, value in histogram.items():
            counts[category] += value
    return "available", counts


def compare(training, comparison):
    features = {}
    for feature in BUCKETS:
        baseline_state, baseline = aggregate(training, feature)
        comparison_state, later = aggregate(comparison, feature)
        if baseline is None or later is None:
            features[feature] = {
                "state": "unavailable",
                "baseline_state": baseline_state,
                "comparison_state": comparison_state,
            }
            continue
        a, b = sum(baseline.values()), sum(later.values())
        if min(a, b) < MIN_REQUESTS:
            features[feature] = {
                "state": "insufficient_requests",
                "baseline_requests": a,
                "comparison_requests": b,
            }
            continue
        features[feature] = {
            "state": "descriptive_only",
            "total_variation_distance": round(
                sum(abs(baseline[k] / a - later[k] / b) for k in baseline) / 2, 8
            ),
            "baseline_requests": a,
            "comparison_requests": b,
            "categories": [
                {
                    "category": k,
                    "baseline_count": baseline[k],
                    "comparison_count": later[k],
                }
                for k in baseline
            ],
        }
    return features
