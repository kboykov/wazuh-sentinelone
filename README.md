# Wazuh SentinelOne Ruleset

Custom Wazuh decoders and rules for SentinelOne CEF2 syslog events.

This project helps Wazuh parse SentinelOne Singularity syslog notifications into
searchable fields, then classify high-value SentinelOne activity such as malware
detections, mitigation results, endpoint lifecycle changes, Device Control,
Firewall Control, Remote Shell, Ranger discovery, administrative changes, and
incident updates.

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

Rules are grouped under `sentinelone` and use local rule IDs in the `100500`
range.

## Supported Log Format

The ruleset targets SentinelOne CEF2 syslog messages similar to:

```text
<date> <time> sentinel - CEF:2|SentinelOne|Mgmt|Windows|rt=2021-06-09 12:56:34.684145|eventID=19|eventDesc=New active threat|eventSeverity=10|sourceHostName=HOST01|sourceUserName=user1|threatConfidenceLevel=malicious|threatMitigationStatus=not_mitigated|fileName=bad.exe|activityType=19
```

SentinelOne documentation notes that newer platform versions use `activityType`
while older versions use `eventID`. This ruleset supports both.

## Decoded Fields

The decoder maps important values into Wazuh static fields where useful:

| Wazuh field | Source |
| --- | --- |
| `id` | `activityType` or `eventID` |
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
| `sentinelone.account.*` | SentinelOne account context |
| `sentinelone.site.*` | SentinelOne site context |
| `sentinelone.device.*` | SentinelOne management console host fields |
| `sentinelone.originator.*` | Event originator metadata |
| `sentinelone.source.*` | Endpoint identity, user, OS, network, group, agent metadata |
| `sentinelone.file.*` | File name, path, SHA1, SHA256, MD5 |
| `sentinelone.threat.*` | Threat ID, classification, confidence, mitigation, storyline |
| `sentinelone.change.*` | Old and new configuration values |
| `sentinelone.ranger.*` | Ranger discovery counters |
| `sentinelone.network.*` | Network discovery gateway and network names |
| `sentinelone.device_control.*` | Device Control events and rule attributes |
| `sentinelone.firewall.*` | Firewall Control notification and rule attributes |
| `sentinelone.remote_shell.*` | Remote Shell session details |
| `sentinelone.rule.*` | Generic rule ID and rule name attributes |

The decoder also handles documented SentinelOne aliases and variants such as
`siteID`, `sourceAgentUUID`, `sourceAddress`, `sourceAddressNN`,
`sourceMacAddress`, and `sourceMacAddressNN`.

## Rule Behavior

The ruleset contains:

| Rule ID | Level | Purpose |
| --- | ---: | --- |
| `100500` | 0 | Base decoded SentinelOne event |
| `100501` | 3 | Generic SentinelOne event |
| `100510`-`100513` | 4-12 | Generic mapping from SentinelOne `eventSeverity` |
| `100520`-`100528` | 5-14 | Threat detection, threat status, and mitigation outcomes |
| `100530`-`100533` | 5-8 | Device Control and Firewall Control |
| `100540`-`100541` | 6-10 | Remote Shell events |
| `100550`-`100551` | 4-6 | Endpoint lifecycle and agent operations |
| `100560`-`100562` | 7-8 | Administrative, allow/block list, and policy changes |
| `100570` | 5 | Ranger discovery |
| `100580`-`100581` | 6-9 | Incident activity and incident updates |
| `100590` | 7 | Scheduled report changes |

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

If your SentinelOne syslog header differs, adjust the decoder prematch in
`decoders/0480-sentinelone_decoders.xml`.

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

## Contributing

When adding new SentinelOne coverage:

1. Add or update sibling decoders for new CEF2 keys.
2. Prefer stable dynamic field names under `sentinelone.*`.
3. Use Wazuh static fields such as `id`, `srcip`, `dstip`, `user`, and
   `system_name` when they clearly map to SentinelOne data.
4. Add focused rules for high-value behavior.
5. Test with `wazuh-logtest` using single-line events.
6. Avoid committing real customer data, tokens, or proprietary documentation.

