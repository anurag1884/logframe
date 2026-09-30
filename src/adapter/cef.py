import json

from common.util import get_ulpf_severity_name


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


def cef_to_ulpf_adapter(input_cef: dict[str, str | int]) -> str:
    result = {}

    if "_cef_severity" in input_cef:
        severity = cef_severity_to_ulpf(str(input_cef["_cef_severity"]))
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
        "event_id": "unknown",
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
