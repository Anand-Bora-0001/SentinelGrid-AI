"""
Document Loader for Threat Intelligence RAG Engine.
Loads threat data from various sources (MITRE, CVE, CERT-In, CISA, OWASP).
"""

from typing import List, Dict

def load_mitre_attack() -> List[Dict]:
    return [
        {
            "id": "T1003",
            "name": "OS Credential Dumping",
            "description": "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from the operating system and software.",
            "source": "MITRE ATT&CK"
        },
        {
            "id": "T1110",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown or when password hashes are obtained.",
            "source": "MITRE ATT&CK"
        },
        {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
            "source": "MITRE ATT&CK"
        }
    ]

def load_cves() -> List[Dict]:
    return [
        {
            "id": "CVE-2021-44228",
            "name": "Log4Shell",
            "description": "Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "source": "CVE Dataset"
        },
        {
            "id": "CVE-2023-23397",
            "name": "Microsoft Outlook Elevation of Privilege Vulnerability",
            "description": "A critical vulnerability in Microsoft Outlook that could allow an attacker to send a malicious email to a victim and cause their device to connect to an external server.",
            "source": "CVE Dataset"
        }
    ]

def load_advisories() -> List[Dict]:
    return [
        {
            "id": "CERT-In-2024",
            "name": "Ransomware Advisory",
            "description": "CERT-In has observed an increase in ransomware attacks targeting critical infrastructure. It is recommended to maintain offline backups and implement network segmentation.",
            "source": "CERT-In Advisory"
        },
        {
            "id": "CISA-AA23",
            "name": "Scattered Spider",
            "description": "CISA advisory on Scattered Spider threat actors engaging in data extortion and deploying BlackCat/ALPHV ransomware.",
            "source": "CISA Advisory"
        },
        {
            "id": "OWASP-TOP10",
            "name": "Injection",
            "description": "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.",
            "source": "OWASP Guidance"
        }
    ]

def load_all_documents() -> List[Dict]:
    """Load all documents from all sources."""
    docs = []
    docs.extend(load_mitre_attack())
    docs.extend(load_cves())
    docs.extend(load_advisories())
    return docs
