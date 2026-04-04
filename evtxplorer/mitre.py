"""
MITRE ATT&CK technique registry.

Each entry provides enough context for reports without requiring a live API call.
Covers the techniques most commonly detected via Windows Event Logs.

Reference: https://attack.mitre.org/
"""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Technique:
    id: str                         # e.g. "T1078"
    name: str
    tactic: list[str]               # ATT&CK tactic(s)
    description: str
    url: str = ""
    subtechnique_of: str = ""       # parent technique ID if this is a sub-technique

    def __post_init__(self):
        if not self.url:
            object.__setattr__(
                self, "url",
                f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"
            )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_TECHNIQUES: list[Technique] = [
    # ── Initial Access ──────────────────────────────────────────────────────
    Technique(
        id="T1078",
        name="Valid Accounts",
        tactic=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        description="Adversaries may obtain and abuse credentials of existing accounts to gain initial access.",
    ),
    Technique(
        id="T1078.002",
        name="Valid Accounts: Domain Accounts",
        tactic=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        description="Abuse of domain account credentials, often obtained via credential dumping or phishing.",
        subtechnique_of="T1078",
    ),

    # ── Execution ────────────────────────────────────────────────────────────
    Technique(
        id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        tactic=["Execution"],
        description="Adversaries may abuse PowerShell commands and scripts for execution.",
        subtechnique_of="T1059",
    ),
    Technique(
        id="T1059.003",
        name="Command and Scripting Interpreter: Windows Command Shell",
        tactic=["Execution"],
        description="Adversaries may abuse the Windows command shell (cmd.exe) for execution.",
        subtechnique_of="T1059",
    ),
    Technique(
        id="T1059.005",
        name="Command and Scripting Interpreter: Visual Basic",
        tactic=["Execution"],
        description="Adversaries may abuse VBScript for execution of malicious code.",
        subtechnique_of="T1059",
    ),
    Technique(
        id="T1204.002",
        name="User Execution: Malicious File",
        tactic=["Execution"],
        description="An adversary may rely upon a user opening a malicious file in order to gain execution.",
        subtechnique_of="T1204",
    ),

    # ── Persistence ──────────────────────────────────────────────────────────
    Technique(
        id="T1547.001",
        name="Boot or Logon Autostart Execution: Registry Run Keys",
        tactic=["Persistence", "Privilege Escalation"],
        description="Adversaries may achieve persistence by adding programs to registry run keys.",
        subtechnique_of="T1547",
    ),
    Technique(
        id="T1543.003",
        name="Create or Modify System Process: Windows Service",
        tactic=["Persistence", "Privilege Escalation"],
        description="Adversaries may create or modify Windows services to repeatedly execute malicious payloads.",
        subtechnique_of="T1543",
    ),
    Technique(
        id="T1053.005",
        name="Scheduled Task/Job: Scheduled Task",
        tactic=["Execution", "Persistence", "Privilege Escalation"],
        description="Adversaries may abuse the Windows Task Scheduler to perform task scheduling for persistence.",
        subtechnique_of="T1053",
    ),

    # ── Privilege Escalation ─────────────────────────────────────────────────
    Technique(
        id="T1548.002",
        name="Abuse Elevation Control Mechanism: Bypass UAC",
        tactic=["Privilege Escalation", "Defense Evasion"],
        description="Adversaries may bypass UAC mechanisms to elevate process privileges.",
        subtechnique_of="T1548",
    ),
    Technique(
        id="T1134.001",
        name="Access Token Manipulation: Token Impersonation/Theft",
        tactic=["Defense Evasion", "Privilege Escalation"],
        description="Adversaries may duplicate tokens to escalate privileges.",
        subtechnique_of="T1134",
    ),

    # ── Defense Evasion ──────────────────────────────────────────────────────
    Technique(
        id="T1070.001",
        name="Indicator Removal: Clear Windows Event Logs",
        tactic=["Defense Evasion"],
        description="Adversaries may clear Windows Event Logs to hide activity.",
        subtechnique_of="T1070",
    ),
    Technique(
        id="T1112",
        name="Modify Registry",
        tactic=["Defense Evasion"],
        description="Adversaries may interact with the Windows Registry to hide configuration information.",
    ),
    Technique(
        id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactic=["Defense Evasion"],
        description="Adversaries may disable security tools to avoid detection.",
        subtechnique_of="T1562",
    ),

    # ── Credential Access ────────────────────────────────────────────────────
    Technique(
        id="T1003.001",
        name="OS Credential Dumping: LSASS Memory",
        tactic=["Credential Access"],
        description="Adversaries may attempt to access credentials stored in LSASS memory.",
        subtechnique_of="T1003",
    ),
    Technique(
        id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic=["Credential Access"],
        description="Adversaries may use password guessing to attempt access to accounts.",
        subtechnique_of="T1110",
    ),
    Technique(
        id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic=["Credential Access"],
        description="Adversaries may use a single or small list of commonly used passwords against many accounts.",
        subtechnique_of="T1110",
    ),
    Technique(
        id="T1558.003",
        name="Steal or Forge Kerberos Tickets: Kerberoasting",
        tactic=["Credential Access"],
        description="Adversaries may abuse Kerberos to obtain service account password hashes.",
        subtechnique_of="T1558",
    ),

    # ── Discovery ────────────────────────────────────────────────────────────
    Technique(
        id="T1087.002",
        name="Account Discovery: Domain Account",
        tactic=["Discovery"],
        description="Adversaries may attempt to get a listing of domain accounts.",
        subtechnique_of="T1087",
    ),
    Technique(
        id="T1069.002",
        name="Permission Groups Discovery: Domain Groups",
        tactic=["Discovery"],
        description="Adversaries may attempt to find domain-level groups and permission settings.",
        subtechnique_of="T1069",
    ),

    # ── Lateral Movement ─────────────────────────────────────────────────────
    Technique(
        id="T1021.001",
        name="Remote Services: Remote Desktop Protocol",
        tactic=["Lateral Movement"],
        description="Adversaries may use RDP to laterally move through an environment.",
        subtechnique_of="T1021",
    ),
    Technique(
        id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic=["Lateral Movement"],
        description="Adversaries may use SMB to interact with file shares or perform pass-the-hash attacks.",
        subtechnique_of="T1021",
    ),
    Technique(
        id="T1550.002",
        name="Use Alternate Authentication Material: Pass the Hash",
        tactic=["Defense Evasion", "Lateral Movement"],
        description="Adversaries may pass the hash using stolen password hashes to move laterally.",
        subtechnique_of="T1550",
    ),

    # ── Collection ───────────────────────────────────────────────────────────
    Technique(
        id="T1560.001",
        name="Archive Collected Data: Archive via Utility",
        tactic=["Collection"],
        description="Adversaries may use utilities to compress and/or encrypt collected data before exfiltration.",
        subtechnique_of="T1560",
    ),

    # ── Command and Control ──────────────────────────────────────────────────
    Technique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic=["Command and Control"],
        description="Adversaries may use HTTP/HTTPS for command and control.",
        subtechnique_of="T1071",
    ),
]

# Build lookup dict
_BY_ID: dict[str, Technique] = {t.id: t for t in _TECHNIQUES}


def get(technique_id: str) -> Technique | None:
    """Look up a technique by ID (e.g. 'T1078' or 'T1078.002')."""
    return _BY_ID.get(technique_id)


def all_techniques() -> list[Technique]:
    return list(_TECHNIQUES)
