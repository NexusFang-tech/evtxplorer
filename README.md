# EVTXplorer

> Windows Event Log analyzer with YAML-driven MITRE ATT&CK detection rules.

**[Try it in your browser](https://nexusfang-tech.github.io/labs/evtxplorer/)** with synthetic attack logs or your own exported XML.

[![CI](https://github.com/NexusFang-Tech/evtxplorer/actions/workflows/ci.yml/badge.svg)](https://github.com/NexusFang-Tech/evtxplorer/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

EVTXplorer parses Windows Event Logs (`.evtx` binary or exported `.xml`) and evaluates each event against a library of YAML detection rules. Each rule maps to a MITRE ATT&CK technique and can optionally aggregate events into threshold-based detections — firing only when N matching events occur within a sliding time window.

---

## Features

- **Dual format support** — parse `.evtx` binary logs or XML exports from Event Viewer
- **YAML rule engine** — write detection logic as human-readable rules, not code
- **Threshold detection** — alert on brute force, password spray, and bulk AD recon by aggregating events over configurable time windows, grouped by arbitrary field combinations
- **MITRE ATT&CK integration** — every rule maps to a technique ID; reports include tactic, technique name, and direct links to the ATT&CK knowledge base
- **Three output formats** — structured JSON, flat CSV, or a self-contained HTML report
- **Rich terminal output** — color-coded severity table with live progress, no setup required
- **Installable CLI** — `pip install -e .` and run `evtxplorer` from anywhere
- **CI-tested** — GitHub Actions pipeline across Python 3.10, 3.11, and 3.12

---

## Detection Coverage

| Rule ID   | Name                                        | MITRE Technique          | Severity |
|-----------|---------------------------------------------|--------------------------|----------|
| EVT-C001  | Failed Logon Attempt                        | T1110.001 Brute Force    | info     |
| EVT-C002  | Brute Force Login Attempts *(threshold)*    | T1110.001 Brute Force    | high     |
| EVT-C003  | Password Spray — Network Logon Failures     | T1110.003 Password Spray | high     |
| EVT-C004  | LSASS Process Memory Access                 | T1003.001 LSASS Memory   | critical |
| EVT-C005  | Kerberos TGS Request — Kerberoasting        | T1558.003 Kerberoasting  | high     |
| EVT-C006  | Logon with Explicit Credentials             | T1550.002 Pass-the-Hash  | medium   |
| EVT-L001  | Remote Desktop Protocol Logon               | T1021.001 RDP            | medium   |
| EVT-L002  | Network Logon — Admin Share Access          | T1021.002 SMB Shares     | low      |
| EVT-L003  | Potential Pass-the-Hash — NTLM Logon        | T1550.002 Pass-the-Hash  | high     |
| EVT-L004  | New Service Installed Remotely              | T1543.003 Windows Service| high     |
| EVT-L005  | Scheduled Task Created                      | T1053.005 Scheduled Task | medium   |
| EVT-P001  | New Local User Account Created              | T1078 Valid Accounts     | medium   |
| EVT-P002  | User Added to Privileged Group              | T1078.002 Domain Accounts| high     |
| EVT-P003  | Token Privilege Adjustment — UAC Bypass     | T1548.002 Bypass UAC     | medium   |
| EVT-P004  | Special Privileges Assigned at Logon        | T1134.001 Token Theft    | medium   |
| EVT-P005  | Windows Defender Real-Time Protection Off   | T1562.001 Disable Tools  | high     |
| EVT-P006  | Security Event Log Cleared                  | T1070.001 Clear Logs     | critical |
| EVT-P007  | PowerShell Script Block Logged              | T1059.001 PowerShell     | medium   |
| EVT-D001  | Domain Admin Group Enumerated               | T1069.002 Domain Groups  | medium   |
| EVT-D002  | Bulk Security Group Enumeration *(threshold)* | T1069.002 Domain Groups | high     |
| EVT-D003  | User Group Membership Queried               | T1087.002 Domain Account | low      |

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/NexusFang-Tech/evtxplorer.git
cd evtxplorer
pip install -e .
```

For `.evtx` binary parsing, `python-evtx` is included as a dependency. XML exports from Windows Event Viewer work without any additional requirements.

---

## Usage

### Basic — analyze a log file, print results to terminal

```bash
evtxplorer --input security.evtx
```

### Analyze an exported XML log

```bash
evtxplorer --input C:\Users\analyst\Desktop\security_export.xml
```

### Analyze a directory of logs and write an HTML report

```bash
evtxplorer --input logs/ --format html --output report.html
```

### Multiple input files with JSON output

```bash
evtxplorer --input security.evtx system.evtx --format json --output findings.json
```

### Filter to high and critical findings only

```bash
evtxplorer --input security.evtx --severity high critical
```

### Use a custom rules directory

```bash
evtxplorer --input security.evtx --rules /path/to/my/rules/
```

### Full options

```
usage: evtxplorer [-h] --input PATH [PATH ...] [--rules DIR]
                  [--format {json,csv,html,none}] [--output FILE]
                  [--severity LEVEL [LEVEL ...]] [--verbose] [--version]

options:
  --input, -i   Event log file(s) or directory (.evtx, .xml, .txt)
  --rules, -r   Directory containing YAML rule files (default: ./rules)
  --format, -f  Output format: json | csv | html | none (default: none)
  --output, -o  Output file path (required for json/csv/html)
  --severity    Filter to specific severity levels
  --verbose     Enable debug logging
  --version     Show version and exit
```

---

## Writing Detection Rules

Rules are YAML files in the `rules/` directory. EVTXplorer loads all `.yml` and `.yaml` files recursively, so you can organize rules into subdirectories.

### Minimal rule

```yaml
id: EVT-CUSTOM-001
name: "Account Lockout"
description: "A user account was locked out."
severity: medium
mitre: T1110.001
match:
  event_id: 4740
  channel: Security
```

### Rule with EventData field conditions

```yaml
id: EVT-CUSTOM-002
name: "Interactive Logon as SYSTEM"
description: "An interactive logon (Type 2) occurred using the SYSTEM account."
severity: high
mitre: T1078
match:
  event_id: 4624
  channel: Security
  data:
    LogonType: "2"
    TargetUserName: "SYSTEM"
```

### Threshold rule — fires after N events in a time window

```yaml
id: EVT-CUSTOM-003
name: "Account Lockout Storm"
description: "Multiple accounts locked out in a short window — possible spray attack."
severity: critical
mitre: T1110.003
match:
  event_id: 4740
  channel: Security
threshold:
  count: 5
  window_seconds: 30
  group_by: [computer]
```

### Rule schema reference

| Field                        | Type              | Required | Description |
|------------------------------|-------------------|----------|-------------|
| `id`                         | string            | ✅       | Unique rule identifier |
| `name`                       | string            | ✅       | Short descriptive name |
| `description`                | string            | —        | Analyst-facing explanation |
| `severity`                   | string            | ✅       | `critical` \| `high` \| `medium` \| `low` \| `info` |
| `mitre`                      | string            | —        | ATT&CK technique ID (e.g. `T1078.002`) |
| `tags`                       | list[string]      | —        | Arbitrary labels for filtering |
| `references`                 | list[string]      | —        | URLs to supporting documentation |
| `match.event_id`             | int or list[int]  | ✅       | Windows Event ID(s) to match |
| `match.channel`              | string            | —        | Substring match on log channel name |
| `match.provider`             | string            | —        | Substring match on provider name |
| `match.data`                 | dict              | —        | EventData field exact-match conditions |
| `threshold.count`            | int               | —        | Number of matches required to fire |
| `threshold.window_seconds`   | int               | —        | Sliding window duration |
| `threshold.group_by`         | list[string]      | —        | Fields to group by (e.g. `computer`, `data.TargetUserName`) |

---

## Output Formats

### Terminal (default)

Color-coded findings table with severity counts, rule names, MITRE IDs, computer names, Event IDs, and timestamps. Exit code `0` if no findings, `1` if any findings — suitable for scripting and pipeline integration.

### JSON (`--format json`)

Structured output with a `summary` block (severity counts, technique breakdown, tactic coverage) and a `findings` array containing full rule metadata, MITRE ATT&CK links, event data, and contributing event counts for threshold findings.

### CSV (`--format csv`)

Flat tabular output — one row per finding. Suitable for import into Excel, Splunk, or any SIEM ingestion pipeline.

### HTML (`--format html`)

Self-contained dark-theme report with severity summary cards, a sortable findings table with expandable EventData, a MITRE technique coverage breakdown, and direct links to ATT&CK entries. No external dependencies — share as a single file.

---

## Project Structure

```
evtxplorer/
├── evtxplorer/
│   ├── __init__.py       # Version
│   ├── cli.py            # Argparse entry point, Rich terminal output
│   ├── engine.py         # Rule loader and detection engine
│   ├── mitre.py          # ATT&CK technique registry
│   ├── parser.py         # EVTX binary and XML log parsing
│   └── reporter.py       # JSON, CSV, and HTML output
├── rules/
│   ├── credential_access.yml
│   ├── discovery.yml
│   ├── lateral_movement.yml
│   └── persistence_and_privilege_escalation.yml
├── tests/
│   ├── fixtures/         # Synthetic event log XML for testing
│   ├── conftest.py
│   ├── test_engine.py
│   ├── test_parser.py
│   └── test_reporter.py
├── .github/workflows/
│   └── ci.yml            # Python 3.10 / 3.11 / 3.12 matrix
└── pyproject.toml
```

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests with coverage
pytest

# Lint
ruff check evtxplorer/

# Regenerate test fixtures
python tests/fixtures/generate_fixtures.py
```

---

## Roadmap

- [ ] Sigma rule compatibility layer
- [ ] Sysmon event support (Event IDs 1, 3, 7, 10, 11)
- [ ] JSONL streaming output for large log sets
- [ ] Baseline mode — suppress detections matching a known-good profile
- [ ] Network share and UNC path input support

---

## License

MIT — see [LICENSE](LICENSE).

---

## References

- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [Ultimate Windows Security — Event ID Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft Security Auditing Documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [python-evtx](https://github.com/williballenthin/python-evtx) by Willi Ballenthin
