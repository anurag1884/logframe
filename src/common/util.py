from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def safe_int_cast(val: str) -> str | int:
    try:
        return int(val)
    except ValueError:
        return val


def get_ulpf_severity_name(uid: int) -> str:
    if uid == 1:
        return "informational"
    elif uid == 2:
        return "low"
    elif uid == 3:
        return "medium"
    elif uid == 4:
        return "high"
    elif uid == 5:
        return "critical"
    else:
        return "unknown"


def get_as_utc_timestamp(raw: str, zone: str) -> int:
    try:
        tz = ZoneInfo(zone)
    except ZoneInfoNotFoundError:
        return -1
    year = datetime.now(tz).year
    try:
        return int(
            datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
            .replace(tzinfo=tz)
            .timestamp()
        )
    except ValueError:
        return -1


def get_utc_timestamp(raw: str) -> int:
    return int(
        datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )
