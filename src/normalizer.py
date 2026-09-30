from common.sequence_parsing import parse
from sample.cef import SAMPLE_CEF_LOGS
from sample.json import SAMPLE_JSON_LOGS
from sample.syslog import SAMPLE_SYSLOGS
from sample.xml import SAMPLE_XML_LOGS

for log in SAMPLE_SYSLOGS + SAMPLE_CEF_LOGS + SAMPLE_JSON_LOGS + SAMPLE_XML_LOGS:
    print(parse(log))
    print()
