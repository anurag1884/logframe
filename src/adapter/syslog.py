import json

from common.util import get_as_utc_timestamp, get_ulpf_severity_name


def syslog_severity_to_ulpf(sid: str) -> int:
    if sid == "0" or sid == "1":
        return 5
    elif sid == "2" or sid == "3":
        return 4
    elif sid == "4":
        return 3
    elif sid == "5":
        return 2
    elif sid == "6" or sid == "7":
        return 1
    else:
        return -1


def syslog_to_ulpf_adapter(
    input_syslog: dict[
        str, str | int | tuple[str] | dict[str, str | dict[str, str]] | dict[str, str]
    ],
) -> str:
    result = {}

    if "severity" in input_syslog:
        severity = syslog_severity_to_ulpf(str(input_syslog["severity"]))
    else:
        severity = -1

    if "time" in input_syslog:
        result["timestamp"] = get_as_utc_timestamp(
            str(input_syslog["time"]), "Asia/Kolkata"
        )
    else:
        result["timestamp"] = -1

    result["src_endpoint"] = {
        "ip": input_syslog.get("src_ip", "unknown"),
        "port": input_syslog.get("src_port", "unknown"),
        "hostname": "unknown",
    }
    result["dst_endpoint"] = {
        "ip": input_syslog.get("dst_ip", "unknown"),
        "port": input_syslog.get("dst_port", "unknown"),
        "hostname": "unknown",
    }
    result["connection_info"] = {
        "protocol_name": input_syslog.get("protocol", "unknown")
    }
    result["event"] = {
        "severity_id": severity,
        "severity_name": get_ulpf_severity_name(severity),
        "message": input_syslog.get("message", "unknown"),
    }
    result["app_protocol_name"] = input_syslog.get("app_name", "unknown")
    result["device"] = {
        "hostname": input_syslog.get("hostname", "unknown"),
        "version": "unknown",
        "vendor_name": "unknown",
        "product_name": "unknown",
    }

    result["metadata"] = {
        "format": "syslog",
        "version": input_syslog.get("version", "unknown"),
        "raw_data": input_syslog.get("raw_data", "unknown"),
        "syslog": {
            "format": input_syslog.get("format", "unknown"),
            "priority": input_syslog.get("priority", "unknown"),
            "severity_name": input_syslog.get("severity_name", "unknown"),
            "facility": input_syslog.get("facility", "unknown"),
            "facility_name": input_syslog.get("facility_name", "unknown"),
            "process_id": input_syslog.get("process_id", "unknown"),
            "message_id": input_syslog.get("message_id", "unknown"),
        },
    }

    return json.dumps(result)
