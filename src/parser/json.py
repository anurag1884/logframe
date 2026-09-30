import json


def parse_json(log: str) -> dict[str, str]:
    result = {}

    try:
        result.update(json.loads(log))
    except json.JSONDecodeError as e:
        result.update({"format": "json", "error_message": e.msg})

    result["raw_data"] = log

    return result
