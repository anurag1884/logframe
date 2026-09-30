import xml.etree.ElementTree as ET


def parse_xml(log: str) -> dict[str, str]:
    result = {}

    try:
        root = ET.fromstring(log)
        result.update(
            {child.tag: child.text for child in root if child.text is not None}
        )
    except ET.ParseError as e:
        result.update({"format": "xml", "error_message": e.msg})

    result["raw_data"] = log

    return result
