"""Source-specific event time extraction; never consult AI analysis or infer timezone."""

from datetime import UTC, datetime, timedelta


def extract(source, wrapper, ingested_at):
    raw = wrapper.get("event", wrapper) if isinstance(wrapper, dict) else {}
    raw = raw if isinstance(raw, dict) else {}
    field = {"wazuh": "timestamp", "suricata": "timestamp", "crowdsec": "start_at"}.get(
        source
    )
    if not field:
        return None, "", "unsupported_source"
    value = raw.get(field)
    if value in (None, ""):
        return None, field, "missing"
    if not isinstance(value, str) or len(value) > 80:
        return None, field, "invalid"
    try:
        observed = datetime.fromisoformat(value)
    except ValueError:
        return None, field, "invalid"
    if observed.tzinfo is None:
        return None, field, "timezone_missing"
    try:
        observed = observed.astimezone(UTC)
    except (ValueError, OverflowError):
        return None, field, "invalid"
    if observed > ingested_at + timedelta(minutes=5):
        return None, field, "future_clock_untrusted"
    return observed, field, "source_reported"
