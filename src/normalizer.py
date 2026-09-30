import json
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from parser.cef import parse_cef
from parser.syslog import parse_syslog
from parser.util import safe_int_cast
from sample.cef import SAMPLE_CEF_LOGS
from sample.syslog import SAMPLE_SYSLOGS


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


def cef_severity_to_ulpf(cid: str) -> int:
    if cid == "0" or cid == "1" or cid == "2" or cid == "3":
        return 1
    elif cid == "4":
        return 2
    elif cid == "5":
        return 3
    elif cid == "6" or cid == "7":
        return 4
    elif cid == "8" or cid == "9" or cid == "10":
        return 5
    else:
        return -1


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


def syslog_to_ulpf_json(
    input_syslog: dict[
        str, str | int | None | dict[str, str | dict[str, str]] | dict[str, str]
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


def cef_to_ulpf_json(input_cef: dict[str, str | int]) -> str:
    result = {}

    if "_cef_severity" in input_cef:
        severity = syslog_severity_to_ulpf(str(input_cef["_cef_severity"]))
    else:
        severity = -1

    result["timestamp"] = -1

    result["src_endpoint"] = {
        "ip": input_cef.get("src", "unknown"),
        "port": input_cef.get("spt", "unknown"),
        "hostname": input_cef.get("shost", "unknown"),
    }
    result["dst_endpoint"] = {
        "ip": input_cef.get("dst", "unknown"),
        "port": input_cef.get("dpt", "unknown"),
        "hostname": input_cef.get("dhost", "unknown"),
    }
    result["connection_info"] = {"protocol_name": input_cef.get("proto", "unknown")}
    result["event"] = {
        "severity_id": severity,
        "severity_name": get_ulpf_severity_name(severity),
        "message": input_cef.get("_cef_name", "unknown"),
    }
    result["app_protocol_name"] = input_cef.get("app", "unknown")
    result["device"] = {
        "hostname": "unknown",
        "version": input_cef.get("_cef_device_version", "unknown"),
        "vendor_name": input_cef.get("_cef_vendor", "unknown"),
        "product_name": input_cef.get("_cef_product", "unknown"),
    }

    result["metadata"] = {
        "format": "cef",
        "version": input_cef.get("_cef_version", "unknown"),
        "raw_data": input_cef.get("raw_data", "unknown"),
        "cef": {
            "signature_id": input_cef.get("_cef_signature_id", "unknown"),
        },
    }

    return json.dumps(result)


def get_json_attr(input_json: dict[str, str], attrs: tuple[str, ...]) -> str:
    for attr in attrs:
        if attr in input_json:
            return input_json[attr]
    return "unknown"


def json_to_ulpf_json(input_json: dict[str, str], raw_data: str) -> str:
    result = {}

    try:
        severity = int(input_json["severity"])
    except (KeyError, ValueError):
        severity = -1

    if "time" in input_json:
        result["timestamp"] = get_utc_timestamp(input_json["time"])
    elif "timestamp" in input_json:
        result["timestamp"] = input_json["timestamp"]
    else:
        result["timestamp"] = -1

    result["src_endpoint"] = {
        "ip": get_json_attr(
            input_json, ("src_ip", "srcip", "src", "source_ip", "source")
        ),
        "port": safe_int_cast(
            get_json_attr(
                input_json,
                ("src_port", "srcport", "sport", "spt", "source_port", "sourceport"),
            )
        ),
        "hostname": get_json_attr(
            input_json, ("src_hostname", "shost", "source_hostname")
        ),
    }
    result["dst_endpoint"] = {
        "ip": get_json_attr(
            input_json, ("dst_ip", "dstip", "dst", "destination_ip", "destination")
        ),
        "port": safe_int_cast(
            get_json_attr(
                input_json,
                (
                    "dst_port",
                    "dstport",
                    "dport",
                    "dpt",
                    "destination_port",
                    "destinationport",
                ),
            )
        ),
        "hostname": get_json_attr(
            input_json, ("dst_hostname", "dhost", "destination_hostname")
        ),
    }
    result["connection_info"] = {
        "protocol_name": get_json_attr(input_json, ("protocol", "proto"))
    }
    result["event"] = {
        "severity_id": severity,
        "severity_name": get_ulpf_severity_name(severity),
        "message": get_json_attr(input_json, ("message", "msg")),
    }
    result["app_protocol_name"] = get_json_attr(input_json, ("app_name", "app"))
    result["device"] = {
        "hostname": get_json_attr(input_json, ("device_hostname", "hostname")),
        "version": safe_int_cast(
            get_json_attr(input_json, ("device_version", "version"))
        ),
        "vendor_name": get_json_attr(
            input_json, ("device_vendor_name", "vendor_name", "vendor")
        ),
        "product_name": get_json_attr(
            input_json, ("device_product_name", "product_name", "product")
        ),
    }

    result["metadata"] = {"format": "json", "raw_data": raw_data}

    return json.dumps(result)


def seq_parse(src: str) -> str:
    if src.startswith("CEF"):
        c = parse_cef(src)
        if "error_message" in c:
            return json.dumps({"metadata": c})
        return cef_to_ulpf_json(c)

    # if src.startsWith("LEEF"):
    #     l = parse_leef(src)
    #     if "error_message" in l:
    #         return {"metadata": {"format": "leef", **l}}
    #     return leef_to_ulpf_Json(l)

    if re.match(r"^<\d+>", src):
        s = parse_syslog(src)
        if s is not None:
            if "error_message" in s:
                return json.dumps({"metadata": s})
            return syslog_to_ulpf_json(s)

    try:
        j = json.loads(src)
        return json_to_ulpf_json(j, src)
    except json.JSONDecodeError as e:
        return json.dumps(
            {"metadata": {"format": "json", "error_message": e.msg, "raw_data": src}}
        )


for log in SAMPLE_SYSLOGS + SAMPLE_CEF_LOGS:
    print(seq_parse(log))
    print()
