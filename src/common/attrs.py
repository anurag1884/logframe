from enum import Enum


class attrs(Enum):
    SRC_IP = ("src_ip", "srcip", "sip", "src", "source_ip", "source")
    SRC_PORT = ("src_port", "srcport", "sport", "spt", "source_port", "sourceport")
    SRC_HOSTNAME = ("src_host", "src_hostname", "shost", "shostname", "source_host", "source_hostname")

    DEST_IP = ("dst_ip", "dstip", "dip", "dst", "destination_ip", "destination")
    DEST_PORT = (
        "dst_port",
        "dstport",
        "dport",
        "dpt",
        "destination_port",
        "destinationport",
    )
    DEST_HOSTNAME = ("dst_host", "dst_hostname", "dhost", "dhostname", "destination_host", "destination_hostname")

    PROTO = ("protocol", "proto")

    EVENT_ID = ("eid", "evt", "evt_id", "event", "event_id")
    MSG = ("message", "msg", "event_name")
    APP = ("application", "app", "app_name")

    DEVICE_HOSTNAME = ("device_hostname", "hostname", "device")
    DEVICE_VERSION = ("device_version", "version")
    DEVICE_VENDOR = ("device_vendor_name", "vendor_name", "vendor")
    DEVICE_PRODUCT = ("device_product_name", "product_name", "product")


def get_attr(input_obj: dict[str, str], attrs: tuple[str, ...]) -> str:
    for attr in attrs:
        if attr in input_obj:
            return input_obj[attr]
    return "unknown"
