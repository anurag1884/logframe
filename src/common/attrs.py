from enum import Enum


class attrs(Enum):
    SRC_IP = ("src_ip", "srcip", "sip", "src", "source_ip", "source")
    SRC_PORT = ("src_port", "srcport", "sport", "spt", "source_port", "sourceport")
    SRC_HOSTNAME = ("src_hostname", "shost", "source_hostname")

    DEST_IP = ("dst_ip", "dstip", "dip", "dst", "destination_ip", "destination")
    DEST_PORT = (
        "dst_port",
        "dstport",
        "dport",
        "dpt",
        "destination_port",
        "destinationport",
    )
    DEST_HOSTNAME = ("dst_hostname", "dhost", "destination_hostname")

    PROTO = ("protocol", "proto")
    MSG = ("message", "msg")
    APP = ("app_name", "app")

    DEVICE_HOSTNAME = ("device_hostname", "hostname")
    DEVICE_VERSION = ("device_version", "version")
    DEVICE_VENDOR = ("device_vendor_name", "vendor_name", "vendor")
    DEVICE_PRODUCT = ("device_product_name", "product_name", "product")


def get_attr(input_obj: dict[str, str], attrs: tuple[str, ...]) -> str:
    for attr in attrs:
        if attr in input_obj:
            return input_obj[attr]
    return "unknown"
