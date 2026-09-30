import re
from re import Match

from parser.util import safe_int_cast

FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "solaris-cron",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

SEVERITIES = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "informational",
    7: "debug",
}


def parse_priority(value: str) -> dict[str, str | int] | None:
    try:
        val_int = int(value)
    except ValueError:
        return None
    return {
        "priority": val_int,
        "facility": val_int // 8,
        "facility_name": FACILITIES.get(val_int // 8, "unknown"),
        "severity": val_int % 8,
        "severity_name": SEVERITIES.get(val_int % 8, "unknown"),
    }


def parse_network_fields(message: str) -> dict[str, str | int]:
    fields = {}

    patterns = {
        "src_ip": r"\b(?:src_ip|srcip|src|source_ip|source)\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})\b",
        "dst_ip": r"\b(?:dst_ip|dstip|dst|destination_ip|destination)\s*[=:]\s*(\d{1,3}(?:\.\d{1,3}){3})\b",
        "src_port": r"\b(?:src_port|srcport|sport|source_port|sourceport)\s*[=:]\s*(\d+)\b",
        "dst_port": r"\b(?:dst_port|dstport|dport|destination_port|destinationport)\s*[=:]\s*(\d+)\b",
        "protocol": r"\b(?:protocol|proto)\s*[=:]\s*([A-Za-z0-9_.-]+)\b",
    }

    for key, pattern in patterns.items():
        m = re.search(pattern, message, re.IGNORECASE)
        if m:
            fields[key] = safe_int_cast(m.group(1)) if "port" in key else m.group(1)

    # Common firewall form:
    # SRC=192.168.1.10 SPT=54321 DST=8.8.8.8 DPT=443 PROTO=TCP
    firewall_patterns = {
        "src_ip": r"\bSRC=(\d{1,3}(?:\.\d{1,3}){3})\b",
        "dst_ip": r"\bDST=(\d{1,3}(?:\.\d{1,3}){3})\b",
        "src_port": r"\bSPT=(\d+)\b",
        "dst_port": r"\bDPT=(\d+)\b",
        "protocol": r"\bPROTO=([A-Za-z0-9_.-]+)\b",
    }

    for key, pattern in firewall_patterns.items():
        if key not in fields:
            m = re.search(pattern, message, re.IGNORECASE)
            if m:
                fields[key] = safe_int_cast(m.group(1)) if "port" in key else m.group(1)

    # Example: 192.168.1.10:54321 -> 8.8.8.8:443
    m = re.search(
        r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*(?:->|=>|to)\s*"
        r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)",
        message,
        re.IGNORECASE,
    )
    if m:
        fields.setdefault("src_ip", m.group(1))
        fields.setdefault("src_port", safe_int_cast(m.group(2)))
        fields.setdefault("dst_ip", m.group(3))
        fields.setdefault("dst_port", safe_int_cast(m.group(4)))

    return fields


def parse_structured_data(value: str) -> dict[str, str | dict[str, str]]:
    if value == "-":
        return {}

    result = {}
    for block in re.findall(r"\[([^\]]*)\]", value):
        parts = block.split()
        if not parts:
            continue

        sd_id = parts[0]
        attrs = {}

        for item in parts[1:]:
            m = re.match(r'([^=]+)="(.*)"$', item)
            if m:
                attrs[m.group(1)] = (
                    m.group(2)
                    .replace(r"\\", "\\")
                    .replace(r"\"", '"')
                    .replace(r"\]", "]")
                )

        result[sd_id] = attrs

    return result


def parse_rfc5424(
    log: str, pri_match: Match[str]
) -> dict[str, str | int | None | dict[str, str | dict[str, str]]] | None:
    rest = log[pri_match.end() :]

    m = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", rest)
    if not m:
        return None

    version, time, hostname, app, procid, msgid, tail = m.groups()

    structured_data = "-"
    message = ""

    if tail.startswith("["):
        sd = re.match(r"^((?:\[[^\]]*\])+)(?:\s+(.*))?$", tail)
        if sd:
            structured_data = sd.group(1)
            message = sd.group(2) or ""
        else:
            message = tail
    else:
        message = tail

    result = {
        "format": "RFC5424",
        "version": safe_int_cast(version),
        "time": None if time == "-" else time,
        "hostname": None if hostname == "-" else hostname,
        "app_name": None if app == "-" else app,
        "process_id": None if procid == "-" else procid,
        "message_id": None if msgid == "-" else msgid,
        "structured_data": parse_structured_data(structured_data),
        "message": message,
    }

    result.update(parse_network_fields(message))
    return result


def parse_rfc3164(
    log: str, pri_match: Match[str]
) -> dict[str, str | int | None | dict[str, str]] | None:
    rest = log[pri_match.end() :]

    m = re.match(
        r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(\S+)\s+([^\s:]+)(?::\s*)?(.*)$",
        rest,
    )
    if not m:
        return None

    time, hostname, tag, message = m.groups()

    app_name = tag
    process_id = None

    pid = re.match(r"^(.+?)\[(\d+)\]$", tag)
    if pid:
        app_name = pid.group(1)
        process_id = pid.group(2)

    structured_data: dict[str, str] = {}

    result = {
        "format": "RFC3164",
        "version": None,
        "time": time,
        "hostname": hostname,
        "app_name": app_name,
        "process_id": process_id,
        "message_id": None,
        "structured_data": structured_data,
        "message": message,
    }

    result.update(parse_network_fields(message))
    return result


def parse_syslog(
    log: str,
) -> dict[str, str | int | None | dict[str, str | dict[str, str]] | dict[str, str]]:
    log = log.strip()

    if not log:
        return {"format": "syslog", "error_message": "Empty Syslog", "raw_data": log}

    pri: Match[str] | None = re.match(r"^<(\d+)>", log)

    if not pri:
        return {
            "format": "syslog",
            "error_message": "Invalid Syslog: PRI <number> not found",
            "raw_data": log,
        }

    result = {}

    priority = parse_priority(pri.group(1))
    if priority is None:
        result.update({"format": "syslog", "message": "Invalid priority value"})
    else:
        result.update(priority)

    parsed = parse_rfc5424(log, pri)
    if parsed is None:
        parsed = parse_rfc3164(log, pri)

    if parsed is None:
        result.update({"format": "unknown", "message": log[pri.end() :]})
    else:
        result.update(parsed)

    # ULPF requires the original source event to be preserved.
    result["raw_data"] = log

    return result
