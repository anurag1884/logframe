import re

from parser.util import safe_int_cast


def parse_cef(log_line: str) -> dict[str, str | int]:
    header_parts: list[str] = re.split(r"(?<!\\)\|", log_line)

    if len(header_parts) < 8:
        return {
            "error_message": f"Invalid CEF format: expected at least 8 pipe-delimited header fields, got {len(header_parts)}",
            "raw_data": log_line,
        }

    version_field = header_parts[0]
    if not version_field.upper().startswith("CEF:"):
        return {
            "error_message": f"Invalid CEF format: log line must begin with 'CEF:', got '{version_field[:10]}'",
            "raw_data": log_line,
        }

    version = version_field[4:]
    vendor = header_parts[1].replace("\\|", "|")
    product = header_parts[2].replace("\\|", "|")
    device_version = header_parts[3].replace("\\|", "|")
    signature_id = header_parts[4].replace("\\|", "|")
    name = header_parts[5].replace("\\|", "|")
    severity = header_parts[6].strip()
    extension_str = "|".join(header_parts[7:])

    PORT_KEYS = {"spt", "dpt"}

    fields = {}

    if extension_str.strip():
        token_pattern = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)", re.DOTALL)
        for match in token_pattern.finditer(extension_str):
            key = match.group(1)
            value = match.group(2).replace("\\ ", " ").strip()
            if key in PORT_KEYS:
                value = safe_int_cast(value)
            fields[key] = value

    fields["_cef_version"] = version
    fields["_cef_vendor"] = vendor
    fields["_cef_product"] = product
    fields["_cef_device_version"] = device_version
    fields["_cef_signature_id"] = signature_id
    fields["_cef_name"] = name
    fields["_cef_severity"] = severity
    fields["raw_data"] = log_line

    return fields
