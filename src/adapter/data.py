import json

from common.attrs import attrs, get_attr
from common.util import get_ulpf_severity_name, get_utc_timestamp, safe_int_cast


def data_format_to_ulpf_adapter(input_data: dict[str, str]) -> str:
    result = {}

    try:
        severity = int(input_data["severity"])
    except (KeyError, ValueError):
        severity = -1

    if "time" in input_data:
        result["timestamp"] = get_utc_timestamp(input_data["time"])
    elif "timestamp" in input_data:
        ts = get_utc_timestamp(input_data["timestamp"])
        if ts == -1:
            result["timestamp"] = input_data["timestamp"]
        else:
            result["timestamp"] = ts
    else:
        result["timestamp"] = -1

    result["src_endpoint"] = {
        "ip": get_attr(input_data, attrs.SRC_IP.value),
        "port": safe_int_cast(get_attr(input_data, attrs.SRC_PORT.value)),
        "hostname": get_attr(input_data, attrs.SRC_HOSTNAME.value),
    }
    result["dst_endpoint"] = {
        "ip": get_attr(input_data, attrs.DEST_IP.value),
        "port": safe_int_cast(get_attr(input_data, attrs.DEST_PORT.value)),
        "hostname": get_attr(input_data, attrs.DEST_HOSTNAME.value),
    }
    result["connection_info"] = {
        "protocol_name": get_attr(input_data, attrs.PROTO.value)
    }
    result["event"] = {
        "event_id": get_attr(input_data, attrs.EVENT_ID.value),
        "severity_id": severity,
        "severity_name": get_ulpf_severity_name(severity),
        "message": get_attr(input_data, attrs.MSG.value),
    }
    result["app_protocol_name"] = get_attr(input_data, attrs.APP.value)
    result["device"] = {
        "hostname": get_attr(input_data, attrs.DEVICE_HOSTNAME.value),
        "version": safe_int_cast(get_attr(input_data, attrs.DEVICE_VERSION.value)),
        "vendor_name": get_attr(input_data, attrs.DEVICE_VENDOR.value),
        "product_name": get_attr(input_data, attrs.DEVICE_PRODUCT.value),
    }

    result["metadata"] = {
        "format": "json",
        "raw_data": input_data.get("raw_data", "unknown"),
    }

    return json.dumps(result)
