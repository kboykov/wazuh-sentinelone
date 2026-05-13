# Wazuh SentinelOne Ruleset

Custom Wazuh decoders and rules for SentinelOne CEF2 syslog events.

This project helps Wazuh parse SentinelOne Singularity syslog notifications into
searchable fields, then classify high-value SentinelOne activity such as EDR
alerts, malware detections, mitigation results, endpoint lifecycle changes,
Device Control, Firewall Control, Remote Shell, Ranger discovery,
administrative changes, and incident updates.

## What This Repository Contains

```text
.
├── decoders/
│   └── 0480-sentinelone_decoders.xml
├── rules/
│   └── 0480-sentinelone_rules.xml
└── README.md
```

### Decoder

`decoders/0480-sentinelone_decoders.xml` identifies SentinelOne CEF2 syslog
messages and extracts SentinelOne key/value attributes into Wazuh static fields
and dynamic fields.

The decoder is built around Wazuh sibling decoders. SentinelOne CEF2 events can
include many optional attributes and the key order can vary by event family,
platform version, and policy feature. Sibling decoders make the parser resilient:
each field is decoded independently when present.

### Rules

`rules/0480-sentinelone_rules.xml` provides a base SentinelOne rule and alerting
rules for common SentinelOne security and operations events.

Rules are grouped under `sentinelone` and use local rule IDs in the `119500`
range.

## Supported Log Format

The ruleset targets SentinelOne CEF2 syslog messages similar to:

```text
<date> <time> sentinel - CEF:2|SentinelOne|Mgmt|Windows|rt=2021-06-09 12:56:34.684145|eventID=19|eventDesc=New active threat|eventSeverity=10|sourceHostName=HOST01|sourceUserName=user1|threatConfidenceLevel=malicious|threatMitigationStatus=not_mitigated|fileName=bad.exe|activityType=19
```

SentinelOne documentation notes that newer platform versions use `activityType`
while older versions use `eventID`. This ruleset supports both.

Some SentinelOne deployments also send an EDR alert schema where the CEF header
contains a numeric alert type before the key/value extension fields:

```text
2026-05-13T13:29:32.413940+00:00 host.example CEF: 2|SentinelOne|Mgmt|16000|alertId=...|alertName=Freelens.exe - Preload Injection detected|severity=MEDIUM|confidenceLevel=SUSPICIOUS|mitigationStatus=UNMITIGATED|assetName=HOST01|fileSha256=...
```

For that schema, the decoder maps the numeric CEF header value, such as `16000`,
into Wazuh `id`.

## Decoded Fields

The decoder maps important values into Wazuh static fields where useful:

| Wazuh field | Source |
| --- | --- |
| `id` | `activityType`, `eventID`, or numeric SentinelOne CEF header ID |
| `srcip` | `ip` |
| `dstip` | `firewallNotificationTrafficRemoteHost` |
| `srcport` | `firewallNotificationTrafficLocalPort` |
| `dstport` | `firewallNotificationTrafficRemotePort` |
| `protocol` | `firewallNotificationTrafficProtocol` |
| `srcuser` | `suser` |
| `user` | `sourceUserName` |
| `system_name` | `sourceHostName` |

It also preserves SentinelOne values as dynamic fields under `sentinelone.*`.
Important field families include:

| Field family | Purpose |
| --- | --- |
| `sentinelone.event_*` | Legacy event ID, description, severity |
| `sentinelone.activity_*` | Newer activity ID and activity type |
| `sentinelone.alert.*` | EDR alert ID, name, description, severity, status, verdict, URL |
| `sentinelone.account.*` | SentinelOne account context |
| `sentinelone.site.*` | SentinelOne site context |
| `sentinelone.device.*` | SentinelOne management console host fields |
| `sentinelone.originator.*` | Event originator metadata |
| `sentinelone.source.*` | Endpoint identity, user, OS, network, group, agent metadata |
| `sentinelone.file.*` | File name, path, SHA1, SHA256, MD5 |
| `sentinelone.threat.*` | Threat ID, classification, confidence, mitigation, storyline |
| `sentinelone.process.*` | Originating process details from alert events |
| `sentinelone.change.*` | Old and new configuration values |
| `sentinelone.ranger.*` | Ranger discovery counters |
| `sentinelone.network.*` | Network discovery gateway and network names |
| `sentinelone.device_control.*` | Device Control events and rule attributes |
| `sentinelone.firewall.*` | Firewall Control notification and rule attributes |
| `sentinelone.remote_shell.*` | Remote Shell session details |
| `sentinelone.rule.*` | Generic rule ID and rule name attributes |

The decoder also handles documented SentinelOne aliases and variants such as
`siteID`, `sourceAgentUUID`, `sourceAddress`, `sourceAddressNN`,
`sourceMacAddress`, and `sourceMacAddressNN`. It also normalizes newer EDR alert
schema fields such as `alertName`, `confidenceLevel`, `mitigationStatus`,
`fileSha256`, `assetName`, and `assetLastLoggedInUser` into the same dynamic
field families used by the activity schema.

## Rule Behavior

The ruleset contains:

| Rule ID | Level | Purpose |
| --- | ---: | --- |
| `119500` | 0 | Base decoded SentinelOne event |
| `119501` | 3 | Generic SentinelOne event |
| `119510`-`119513` | 4-12 | Generic mapping from SentinelOne `eventSeverity` |
| `119514`-`119517` | 5-12 | Generic mapping from EDR alert text `severity` |
| `119520`-`119528` | 5-14 | Threat detection, threat status, and mitigation outcomes |
| `119529` | 8 | SentinelOne EDR alert schema, including CEF header ID `16000` |
| `119530`-`119533` | 5-8 | Device Control and Firewall Control |
| `119540`-`119541` | 6-10 | Remote Shell events |
| `119550`-`119551` | 4-6 | Endpoint lifecycle and agent operations |
| `119560`-`119562` | 7-8 | Administrative, allow/block list, and policy changes |
| `119570` | 5 | Ranger discovery |
| `119580`-`119581` | 6-9 | Incident activity and incident updates |
| `119590` | 7 | Scheduled report changes |

Event-code based rules match Wazuh `id`, which is decoded from either
SentinelOne `activityType` or `eventID`. This keeps the same rules working
across older and newer SentinelOne platform versions.

## Install On A Wazuh Manager

Copy the decoder and rule files to the Wazuh manager:

```sh
sudo cp decoders/0480-sentinelone_decoders.xml /var/ossec/etc/decoders/
sudo cp rules/0480-sentinelone_rules.xml /var/ossec/etc/rules/
```

Restart the manager:

```sh
sudo systemctl restart wazuh-manager
```

Check the manager status:

```sh
sudo systemctl status wazuh-manager
```

If the manager fails to start, inspect the Wazuh logs:

```sh
sudo tail -n 100 /var/ossec/logs/ossec.log
```

## Test With wazuh-logtest

Run:

```sh
sudo /var/ossec/bin/wazuh-logtest
```

Paste one complete SentinelOne syslog event as a single line.

Expected results:

1. The decoder should be `sentinelone`.
2. The event should include decoded fields such as `id`,
   `sentinelone.event_desc`, `sentinelone.event_severity`,
   `sentinelone.source.hostname`, and any event-specific fields present in the
   log.
3. One or more child rules should match depending on the event code, category,
   severity, or threat state.

Example test event:

```text
<date> <time> sentinel - CEF:2|SentinelOne|Mgmt|Windows|rt=2021-06-09 12:56:34.684145|fileHash=cc2f06865ba59951ccfadc30f003ee7f768dd562|filePath=C:\Temp\bad.exe|deviceAddress=192.0.2.10|deviceHostFqdn=console.sentinelone.net|deviceHostName=console.sentinelone.net|notificationScope=SITE|siteId=12345|siteName=Production|accountId=67890|accountName=Example|vendor=SentinelOne|eventID=19|eventDesc=New active threat - machine HOST01|eventSeverity=10|originatorName=HOST01|originatorVersion=23.1|sourceOsType=windows|sourceAgentUuid=agent-uuid|sourceHostName=HOST01|sourceUserName=user1|sourceAgentId=agent-id|sourceGroupName=Workstations|sourceIpAddresses=['192.0.2.25']|threatClassification=Malware|threatDetectingEngine=reputation.cloud|threatMitigationStatus=not_mitigated|threatConfidenceLevel=malicious|threatMitigationStatusLabel=active|threatMitigationStatusID=1|threatID=threat-id|threatStoryline=storyline-id|threatDetectionTime=2021-06-09 12:56:34.684145|cat=MALWARE|fileName=bad.exe|activityID=activity-id|activityType=19
```

## Wazuh Configuration Notes

This repository only provides decoders and rules. SentinelOne syslog ingestion
must already be configured in Wazuh.

Common ingestion patterns include:

- Sending SentinelOne syslog to a syslog collector that forwards to Wazuh.
- Sending SentinelOne syslog directly to the Wazuh manager.
- Writing SentinelOne events to a local file and monitoring that file with a
  Wazuh `localfile` configuration.

The exact Wazuh input configuration depends on your deployment model, network
controls, and syslog transport.

## Design Notes

### CEF2 key/value parsing

SentinelOne CEF2 messages use `key=value` attributes separated by `|`. Some
values can be empty, contain spaces, or include lists. The decoder captures each
value up to the next `|` separator.

### Optional fields

Not every SentinelOne event has every field. For example, threat events usually
include `threat.*` and `file.*` attributes, while Firewall Control events include
`firewallNotification*` attributes. The sibling-decoder design means missing
attributes do not prevent the event from decoding.

### Severity model

SentinelOne `eventSeverity` is an integer from 0 to 10. The ruleset maps it to
Wazuh alert levels as a generic fallback:

| SentinelOne `eventSeverity` | Wazuh level |
| --- | ---: |
| `1`-`3` | 4 |
| `4`-`6` | 7 |
| `7`-`8` | 10 |
| `9`-`10` | 12 |

Specific threat and activity rules may produce different levels when the event
type carries stronger meaning than generic severity alone.

### Threat handling

The ruleset has specific handling for:

- New malicious threat not mitigated
- New suspicious threat not mitigated
- Threat mitigated or preemptively blocked
- Mitigation success
- Mitigation failure
- Threat status changes
- Resolved threats
- Malicious or suspicious threats with `not_mitigated` status

### Device Control and Firewall Control

Device Control and Firewall Control rules use both event codes and decoded
attributes. This allows alerts for blocked device events, restricted device
events, approved/connected device events, and blocked firewall traffic.

### Remote Shell

Remote Shell rules highlight session creation/start events at a higher level
than termination/history events.

## Validation Performed

The XML files were checked locally for well-formed XML structure. The decoder
file contains multiple top-level `<decoder>` elements, as expected for Wazuh
decoder files, so validation was performed by wrapping the file in a temporary
root element.

The rules were also audited against the decoder outputs:

- Every `<field name="...">` condition maps to a decoder `<order>` field.
- Every `$(...)` description interpolation maps to a decoder `<order>` field.
- Event-code rules use Wazuh `id`, decoded from `eventID` or `activityType`.
- `decoded_as` matches the decoder name `sentinelone`.
- Every `if_sid` points to an existing rule in this ruleset.

Full runtime validation should still be performed with `wazuh-logtest` on a
Wazuh manager.

## Compatibility

This ruleset is intended for Wazuh custom ruleset deployments that support:

- Custom XML decoders in `/var/ossec/etc/decoders/`
- Custom XML rules in `/var/ossec/etc/rules/`
- Dynamic decoder fields
- PCRE2 regex syntax in decoders and rules

## Security And Privacy Notes

SentinelOne events can include hostnames, usernames, file paths, hashes, IP
addresses, MAC addresses, group names, site names, account names, and threat
identifiers. Treat raw logs and test samples as sensitive operational data.

This repository should contain only the Wazuh ruleset and project
documentation. Do not commit private production logs, proprietary vendor
documentation, API tokens, customer names, or internal environment details.

## Troubleshooting

### The event does not decode as `sentinelone`

Check that the raw log contains:

```text
CEF:2|SentinelOne|Mgmt|
```

Some syslog collectors forward SentinelOne messages with an extra timestamp and
program wrapper before the CEF payload, for example:

```text
2026-05-13T13:31:22.067963+00:00 2026-05-13 13: 31:22,047   sentinel -  CEF:2|SentinelOne|Mgmt|...
```

Other collectors may produce:

```text
2026-05-13T13:29:32.413940+00:00 host.example CEF: 2|SentinelOne|Mgmt|16000|...
```

In that format Wazuh may pre-decode `program_name` as `CEF`, leaving the decoder
to match a remainder that starts with `2|SentinelOne|Mgmt|...`. Because `CEF`
can appear in the remaining Phase 2 message, be removed into `program_name`, or
be hidden behind malformed timestamp fragments, the parent decoder intentionally
keys on the stable SentinelOne marker:

```text
SentinelOne|Mgmt|
```

Child decoders then extract the CEF header, numeric alert ID, `eventID`,
`activityType`, and extension fields.

If Phase 2 still shows `No decoder matched`, confirm that the updated decoder
file has actually been copied to `/var/ossec/etc/decoders/` and that there is no
older SentinelOne decoder file with the same decoder name still installed.

Useful checks on the Wazuh manager:

```sh
sudo grep -R "CEF:2.*SentinelOne" /var/ossec/etc/decoders /var/ossec/ruleset/decoders 2>/dev/null
sudo grep -R "decoder name=\"sentinelone\"" /var/ossec/etc/decoders /var/ossec/ruleset/decoders 2>/dev/null
```

### A field is missing

Confirm that the source log includes the key. SentinelOne omits many fields when
they do not apply to the event type. If the key exists but is not decoded, add a
new sibling decoder for that key.

### A rule does not fire

Check the decoded `id`, `sentinelone.category`,
`sentinelone.event_severity`, and other fields used by the rule. If the event
only has `eventID` or only has `activityType`, the decoder should still set
Wazuh `id`.

### Wazuh manager fails to restart

Inspect:

```sh
sudo tail -n 100 /var/ossec/logs/ossec.log
```

XML syntax errors and duplicate rule IDs are common causes.

### Duplicate rule ID warnings

Warnings like this mean the ruleset is installed more than once:

```text
WARNING: (7612): Rule ID '119500' is duplicated. Only the first occurrence will be considered.
```

Remove the duplicate copy and keep only one SentinelOne rule file. Common places
to check are:

```sh
sudo grep -R "id=\"119500\"" /var/ossec/etc/rules /var/ossec/ruleset/rules 2>/dev/null
sudo grep -R "SentinelOne CEF2 syslog rules" /var/ossec/etc/rules /var/ossec/ruleset/rules 2>/dev/null
```

If you are upgrading from an older version of this repository, also remove any
previous copy that used the old `100500` rule range:

```sh
sudo grep -R "id=\"100500\"" /var/ossec/etc/rules /var/ossec/ruleset/rules 2>/dev/null
```

Usually the correct cleanup is to keep:

```text
/var/ossec/etc/rules/0480-sentinelone_rules.xml
```

and remove any older copied version from `local_rules.xml` or another custom
rules file. Restart the manager after cleanup.

## Contributing

When adding new SentinelOne coverage:

1. Add or update sibling decoders for new CEF2 keys.
2. Prefer stable dynamic field names under `sentinelone.*`.
3. Use Wazuh static fields such as `id`, `srcip`, `dstip`, `user`, and
   `system_name` when they clearly map to SentinelOne data.
4. Add focused rules for high-value behavior.
5. Test with `wazuh-logtest` using single-line events.
6. Avoid committing real customer data, tokens, or proprietary documentation.
