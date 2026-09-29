# ULPF Universal Event Schema v0.1

**Project:** Universal Log Pre-processing Framework (ULPF)\
**Schema basis:** OCSF 1.9.0\
**MVP event scope:** Network Activity events from perimeter/security
devices\
**Supported source formats:** Syslog, JSON, CEF

## 1. Purpose

This document defines the common structure that the ULPF normalization
engine must produce after parsing a source log.

The parsers (Syslog/JSON/CEF) may produce different source-specific
fields. The normalization engine converts those fields into this common
OCSF-based structure.

**Important:** This is an MVP subset of OCSF, not a replacement for the
complete OCSF schema.

------------------------------------------------------------------------

## 2. MVP Event Structure

``` text
Universal Event
│
├── Base Event
│   ├── time
│   ├── activity_id
│   ├── category_uid
│   ├── class_uid
│   ├── type_uid
│   ├── severity_id
│   ├── metadata
│   ├── message
│   ├── status_id
│   ├── status
│   ├── raw_data
│   └── unmapped
│
├── Network Activity
│   ├── src_endpoint
│   │   ├── ip
│   │   ├── port
│   │   └── hostname
│   │
│   ├── dst_endpoint
│   │   ├── ip
│   │   ├── port
│   │   └── hostname
│   │
│   ├── connection_info
│   │   ├── direction_id
│   │   ├── protocol_name
│   │   ├── protocol_num
│   │   └── protocol_ver_id
│   │
│   ├── app_name
│   └── app_protocol_name
│
└── Device
    ├── hostname
    ├── vendor_name
    └── type_id
```

------------------------------------------------------------------------

## 3. Selected OCSF Fields

  ------------------------------------------------------------------------------
  Field                 OCSF requirement  ULPF MVP          Purpose
  --------------------- ----------------- ----------------- --------------------
  `time`                Required          MUST              Time when the event
                                                            occurred

  `activity_id`         Required          MUST              Network activity
                                                            type such as Open,
                                                            Close, Reset, Fail,
                                                            Refuse, Traffic

  `category_uid`        Required          MUST              Identifies the
                                                            Network category

  `class_uid`           Required          MUST              Identifies Network
                                                            Activity

  `type_uid`            Required          MUST              Identifies the
                                                            specific OCSF event
                                                            type

  `severity_id`         Required          MUST              Normalized severity

  `metadata`            Required          MUST              Event/source
                                                            metadata

  `message`             Recommended       SHOULD            Human-readable event
                                                            summary

  `status_id`           Recommended       SHOULD            Normalized event
                                                            outcome

  `status`              Recommended       SHOULD            Human-readable
                                                            status

  `raw_data`            Optional          MUST              Preserve original
                                                            source event

  `unmapped`            Optional          SHOULD            Preserve source
                                                            fields that cannot
                                                            be mapped

  `src_endpoint`        Recommended       MUST\*            Source endpoint

  `dst_endpoint`        Recommended       MUST\*            Destination endpoint

  `connection_info`     Recommended       MUST              Network connection
                                                            information

  `app_name`            Optional          SHOULD            Network application
                                                            name

  `app_protocol_name`   Optional          SHOULD            Layer-7 application
                                                            protocol

  `initiator_id`        Recommended       SHOULD            Identifies which
                                                            endpoint initiated
                                                            communication

  `device`              OCSF object       SHOULD            Device that
                                                            generated/observed
                                                            the event
  ------------------------------------------------------------------------------

`*` OCSF 1.9.0 defines a constraint requiring at least one of
`src_endpoint` or `dst_endpoint`. For this ULPF perimeter-network MVP,
both will normally be populated when the source log provides both.

------------------------------------------------------------------------

## 4. Endpoint Fields

### `src_endpoint`

Use the OCSF `endpoint` object.

MVP fields:

  Field        Type      ULPF requirement      Example
  ------------ --------- --------------------- ------------------------
  `ip`         string    MUST when available   `192.168.1.10`
  `port`       integer   SHOULD                `44321`
  `hostname`   string    SHOULD                `client01.example.com`

### `dst_endpoint`

MVP fields:

  Field        Type      ULPF requirement      Example
  ------------ --------- --------------------- --------------
  `ip`         string    MUST when available   `8.8.8.8`
  `port`       integer   SHOULD                `443`
  `hostname`   string    SHOULD                `dns.google`

------------------------------------------------------------------------

## 5. Connection Information

Use the OCSF `network_connection_info` object.

  Field               OCSF requirement   ULPF MVP   Example
  ------------------- ------------------ ---------- ---------
  `direction_id`      Required           MUST       `1`
  `protocol_name`     Recommended        SHOULD     `tcp`
  `protocol_num`      Recommended        SHOULD     `6`
  `protocol_ver_id`   Recommended        SHOULD     `4`

Do not create a custom `protocol` field. Use OCSF's
`connection_info.protocol_name` and related fields.

------------------------------------------------------------------------

## 6. Network Activity

The MVP uses the OCSF Network Activity class.

Supported `activity_id` values:

     ID Meaning
  ----- ---------
    `1` Open
    `2` Close
    `3` Reset
    `4` Fail
    `5` Refuse
    `6` Traffic
    `7` Listen

Examples of source values:

``` text
ALLOW / ACCEPT
    → usually represents successful/open/traffic semantics
    → Person 2 must choose the appropriate OCSF activity/status based on source context

DENY / BLOCK / REJECT
    → commonly represents refused/failed semantics
    → Person 2 must map using the actual source event meaning
```

Do not add a custom OCSF `action` field.

------------------------------------------------------------------------

## 7. Device Information

Use the OCSF `device` object where the source identifies the device
generating or observing the event.

MVP fields:

  Field           Type      Example
  --------------- --------- --------------------
  `hostname`      string    `fw01.example.com`
  `vendor_name`   string    `Cisco`
  `type_id`       integer   `9`

Common device type IDs relevant to this MVP include:

``` text
9  = Firewall
12 = Router
13 = IDS
14 = IPS
```

------------------------------------------------------------------------

## 8. Source → Universal Mapping

Person 2 should use this table as the starting normalization contract.

  Source format   Source field/example   Universal OCSF field
  --------------- ---------------------- ---------------------------------
  Syslog          `src_ip`               `src_endpoint.ip`
  Syslog          `src_port`             `src_endpoint.port`
  Syslog          `dst_ip`               `dst_endpoint.ip`
  Syslog          `dst_port`             `dst_endpoint.port`
  Syslog          protocol               `connection_info.protocol_name`
  JSON            `source.ip`            `src_endpoint.ip`
  JSON            `source.port`          `src_endpoint.port`
  JSON            `destination.ip`       `dst_endpoint.ip`
  JSON            `destination.port`     `dst_endpoint.port`
  JSON            `protocol`             `connection_info.protocol_name`
  CEF             `src`                  `src_endpoint.ip`
  CEF             `spt`                  `src_endpoint.port`
  CEF             `dst`                  `dst_endpoint.ip`
  CEF             `dpt`                  `dst_endpoint.port`
  CEF             `proto`                `connection_info.protocol_name`
  CEF             `dhost`                `dst_endpoint.hostname`
  CEF             `shost`                `src_endpoint.hostname`
  CEF             `app`                  `app_name`

This table is a starting mapping. If a source uses a different field
name, the parser should expose the value and Person 2 should map it to
the corresponding universal field.

------------------------------------------------------------------------

## 9. Raw Data Preservation

ULPF must not discard the original event.

The normalized event should therefore retain:

``` json
{
  "raw_data": "<original source event>"
}
```

`raw_data` is an actual optional OCSF Base Event attribute in OCSF
1.9.0. ULPF makes it a required project-level preservation requirement
for the MVP.

If a source field cannot be mapped to an OCSF field, preserve it in:

``` json
{
  "unmapped": {
    "source_specific_field": "original value"
  }
}
```

`unmapped` is also an OCSF Base Event attribute.

------------------------------------------------------------------------

## 10. Example Normalized Event

Illustrative MVP example:

``` json
{
  "time": 1776881335332,
  "activity_id": 1,
  "category_uid": 4,
  "class_uid": 4001,
  "type_uid": 4001001,
  "severity_id": 2,

  "metadata": {
    "version": "1.9.0"
  },

  "src_endpoint": {
    "ip": "192.168.1.10",
    "port": 54321,
    "hostname": "client01"
  },

  "dst_endpoint": {
    "ip": "8.8.8.8",
    "port": 443,
    "hostname": "dns.google"
  },

  "connection_info": {
    "direction_id": 1,
    "protocol_name": "tcp",
    "protocol_num": 6,
    "protocol_ver_id": 4
  },

  "app_protocol_name": "https",

  "device": {
    "hostname": "fw01",
    "vendor_name": "Cisco",
    "type_id": 9
  },

  "raw_data": "original source log here"
}
```

The exact `type_uid` values should be generated according to the OCSF
event type definition rather than manually guessed by the parser.

------------------------------------------------------------------------

## 11. Team Contract

### Person 1 --- Schema

Defines and maintains this document.

### Person 2 --- Normalization

Input:

``` text
parser Python dict
```

Output:

``` text
OCSF-based Python dict following this schema
```

### Person 4 --- Syslog Parser

Extract source fields into a Python dictionary.

### Person 5 --- JSON Parser

Extract source fields into a Python dictionary.

### Person 6 --- CEF Parser

Extract source fields into a Python dictionary.

### Person 3 --- Integration/Storage

Connects:

``` text
Parser
  ↓
Normalizer
  ↓
Validator
  ↓
Storage
```

------------------------------------------------------------------------

## 12. Important Implementation Rule

The parser does **not** need to produce OCSF.

For example:

``` python
{
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP"
}
```

The normalizer converts that into:

``` python
{
    "src_endpoint": {
        "ip": "192.168.1.10",
        "port": 54321
    },
    "dst_endpoint": {
        "ip": "8.8.8.8",
        "port": 443
    },
    "connection_info": {
        "protocol_name": "tcp"
    }
}
```

The validator will later check the normalized output against this
contract.

------------------------------------------------------------------------

## 13. Versioning

Current version:

**ULPF Universal Event Schema v0.1**

After testing with real Syslog, JSON and CEF samples, update to:

**v0.2 / v1.0**

Do not change fields silently. Record schema changes in a changelog.

------------------------------------------------------------------------

## 14. Official References

-   OCSF Schema repository: https://github.com/ocsf/ocsf-schema
-   OCSF 1.9.0 release:
    https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0
-   Network Activity definition:
    https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/network/network_activity.json
-   Network category definition:
    https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/network/network.json
-   Base Event definition:
    https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/base_event.json
-   Endpoint object:
    https://github.com/ocsf/ocsf-schema/blob/1.9.0/objects/endpoint.json
-   Network Connection Information object:
    https://github.com/ocsf/ocsf-schema/blob/1.9.0/objects/network_connection_info.json
-   Device object:
    https://github.com/ocsf/ocsf-schema/blob/1.9.0/objects/device.json
