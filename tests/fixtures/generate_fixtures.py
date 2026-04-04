#!/usr/bin/env python3
"""
Generate synthetic Windows Event Log XML fixtures for EVTXplorer tests.
Run once: python tests/fixtures/generate_fixtures.py
"""

from pathlib import Path

FIXTURES_DIR = Path(__file__).parent


def make_event(event_id, channel, computer, timestamp, data_fields, provider="Microsoft-Windows-Security-Auditing", level=0, task=0):
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    data_xml = "\n".join(
        f'      <Data Name="{k}">{v}</Data>' for k, v in data_fields.items()
    )
    return (
        f'<Event xmlns="{ns}">\n'
        f'  <System>\n'
        f'    <Provider Name="{provider}" />\n'
        f'    <EventID>{event_id}</EventID>\n'
        f'    <Level>{level}</Level>\n'
        f'    <Task>{task}</Task>\n'
        f'    <TimeCreated SystemTime="{timestamp}" />\n'
        f'    <Channel>{channel}</Channel>\n'
        f'    <Computer>{computer}</Computer>\n'
        f'    <Security UserID="" />\n'
        f'  </System>\n'
        f'  <EventData>\n'
        f'{data_xml}\n'
        f'  </EventData>\n'
        f'</Event>'
    )


def wrap_events(events):
    inner = "\n".join(events)
    return f"<Events>\n{inner}\n</Events>"


# ── brute_force.xml ──────────────────────────────────────────────────────────
brute_events = []
for i in range(12):
    ts = f"2024-06-15T10:00:{i:02d}.000000Z"
    brute_events.append(make_event(
        event_id=4625,
        channel="Security",
        computer="DC01",
        timestamp=ts,
        data_fields={
            "TargetUserName": "administrator",
            "TargetDomainName": "CORP",
            "LogonType": "3",
            "IpAddress": "192.168.1.50",
            "FailureReason": "%%2313",
            "SubStatus": "0xC000006A",
        }
    ))

(FIXTURES_DIR / "brute_force.xml").write_text(wrap_events(brute_events), encoding="utf-8")
print("Written: brute_force.xml")

# ── log_cleared.xml ──────────────────────────────────────────────────────────
log_cleared_events = [
    make_event(
        event_id=1102,
        channel="Security",
        computer="WORKSTATION01",
        timestamp="2024-06-15T11:30:00.000000Z",
        provider="Microsoft-Windows-Eventlog",
        data_fields={
            "SubjectUserName": "jdoe",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
        }
    )
]
(FIXTURES_DIR / "log_cleared.xml").write_text(wrap_events(log_cleared_events), encoding="utf-8")
print("Written: log_cleared.xml")

# ── rdp_logon.xml ─────────────────────────────────────────────────────────────
rdp_events = [
    make_event(
        event_id=4624,
        channel="Security",
        computer="SERVER02",
        timestamp="2024-06-15T03:15:00.000000Z",
        data_fields={
            "TargetUserName": "Administrator",
            "TargetDomainName": "CORP",
            "LogonType": "10",
            "IpAddress": "203.0.113.45",
            "WorkstationName": "UNKNOWN",
            "AuthenticationPackageName": "Negotiate",
        }
    )
]
(FIXTURES_DIR / "rdp_logon.xml").write_text(wrap_events(rdp_events), encoding="utf-8")
print("Written: rdp_logon.xml")

# ── new_service.xml ────────────────────────────────────────────────────────────
service_events = [
    make_event(
        event_id=7045,
        channel="System",
        computer="SERVER02",
        timestamp="2024-06-15T03:16:00.000000Z",
        provider="Service Control Manager",
        data_fields={
            "ServiceName": "PSEXESVC",
            "ImagePath": "%SystemRoot%\\PSEXESVC.exe",
            "ServiceType": "user mode service",
            "StartType": "demand start",
            "AccountName": "LocalSystem",
        }
    )
]
(FIXTURES_DIR / "new_service.xml").write_text(wrap_events(service_events), encoding="utf-8")
print("Written: new_service.xml")

# ── mixed_scenario.xml — realistic multi-stage attack sequence ──────────────
mixed = []
# 1. Recon: group enumeration
for i in range(35):
    ts = f"2024-06-15T09:00:{i % 60:02d}.000000Z"
    mixed.append(make_event(
        event_id=4799,
        channel="Security",
        computer="DC01",
        timestamp=ts,
        data_fields={
            "TargetUserName": "Domain Admins",
            "SubjectUserName": "attacker",
            "SubjectDomainName": "CORP",
        }
    ))

# 2. Brute force
for i in range(15):
    ts = f"2024-06-15T09:02:{i:02d}.000000Z"
    mixed.append(make_event(
        event_id=4625,
        channel="Security",
        computer="DC01",
        timestamp=ts,
        data_fields={
            "TargetUserName": "svc_backup",
            "LogonType": "3",
            "IpAddress": "192.168.1.99",
            "FailureReason": "%%2313",
        }
    ))

# 3. Successful RDP (after brute)
mixed.append(make_event(
    event_id=4624,
    channel="Security",
    computer="DC01",
    timestamp="2024-06-15T09:05:00.000000Z",
    data_fields={
        "TargetUserName": "svc_backup",
        "LogonType": "10",
        "IpAddress": "192.168.1.99",
        "AuthenticationPackageName": "Negotiate",
    }
))

# 4. New admin user created
mixed.append(make_event(
    event_id=4720,
    channel="Security",
    computer="DC01",
    timestamp="2024-06-15T09:06:00.000000Z",
    data_fields={
        "TargetUserName": "maint_acct",
        "SubjectUserName": "svc_backup",
    }
))

# 5. Added to Administrators
mixed.append(make_event(
    event_id=4732,
    channel="Security",
    computer="DC01",
    timestamp="2024-06-15T09:06:05.000000Z",
    data_fields={
        "MemberName": "maint_acct",
        "GroupName": "Administrators",
        "SubjectUserName": "svc_backup",
    }
))

# 6. Log cleared to cover tracks
mixed.append(make_event(
    event_id=1102,
    channel="Security",
    computer="DC01",
    timestamp="2024-06-15T09:15:00.000000Z",
    provider="Microsoft-Windows-Eventlog",
    data_fields={
        "SubjectUserName": "maint_acct",
        "SubjectDomainName": "CORP",
    }
))

(FIXTURES_DIR / "mixed_scenario.xml").write_text(wrap_events(mixed), encoding="utf-8")
print("Written: mixed_scenario.xml")

print("\nAll fixtures generated successfully.")
