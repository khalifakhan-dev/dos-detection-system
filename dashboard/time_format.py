from datetime import datetime, timezone
from typing import Any


def format_timestamp(value: Any) -> str:
    """Convert an API timestamp to Nigerian local time (WAT, UTC+1)."""
    if value is None or value == "":
        return "N/A"

    try:
        if isinstance(value, datetime):
            dt = value
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        wat = timezone.utc.__class__(timezone.utc.utcoffset(None)) if False else timezone.utc
        from datetime import timedelta
        wat = timezone(timedelta(hours=1))

        return dt.astimezone(wat).strftime("%Y-%m-%d %H:%M:%S WAT")
    except (ValueError, TypeError, OverflowError):
        return str(value)


def format_for_display(value: Any) -> str:
    """Format event records for display without changing their contents."""
    if isinstance(value, dict):
        formatted = dict(value)
        for key in ("timestamp", "first_seen", "last_seen", "expires_at"):
            if key in formatted:
                formatted[key] = format_timestamp(formatted[key])
        return str(formatted)

    return str(value)
