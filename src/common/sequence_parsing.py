import json
import re

from adapter.cef import cef_to_ulpf_adapter
from adapter.data import data_format_to_ulpf_adapter
from adapter.syslog import syslog_to_ulpf_adapter
from parser.cef import parse_cef
from parser.json import parse_json
from parser.syslog import parse_syslog
from parser.xml import parse_xml


def parse(src: str) -> str:
    if src.startswith("CEF"):
        c = parse_cef(src)
        if "error_message" in c:
            return json.dumps({"metadata": c})
        return cef_to_ulpf_adapter(c)

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
            return syslog_to_ulpf_adapter(s)

    if re.match(r"^\s*\{.+\}\s*$", src):
        j = parse_json(src)
        if "error_message" in j:
            return json.dumps({"metadata": j})
        return data_format_to_ulpf_adapter(j)

    if re.match(r"^\s*<.+>\s*$", src):
        x = parse_xml(src)
        if "error_message" in x:
            return json.dumps({"metadata": x})
        return data_format_to_ulpf_adapter(x)

    return json.dumps({"metadata": {"format": "unknown", "message": "Unknown format."}})
