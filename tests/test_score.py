"""Tests for vuln_monitor.score() RCE/bypass classification.

Guards the 'unauthenticated-as-RCE' false-positive fix:
- a bare 'unauthenticated' / 'pre-auth' must NOT by itself make a record RCE
  (privilege escalation / SQLi / info-disclosure described as unauthenticated
   are not remote code execution)
- deserialization primitives (object injection / unserialize) ARE RCE
- the literal 'CVSS' in a summary must not trip the 'cvs' asset keyword
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as vm


def _score(title, summary=""):
    """score() runs on title + summary, matching how rescore composes text."""
    return vm.score(f"{title}\n{summary}")


# --- the bug: unauthenticated-non-RCE must not be tagged RCE ---

def test_unauthenticated_privilege_escalation_is_not_rce():
    # CVE-2026-56028 — the reported false positive
    _, reason, vt = _score(
        "CVE-2026-56028 Unauthenticated Privilege Escalation in Easy Elements for Elementor",
        "Unauthenticated Privilege Escalation in Easy Elements for Elementor <= 1.4.9 (CVSS 9.8)",
    )
    assert vt != "RCE", f"privesc mislabeled RCE via 'unauthenticated' (reason={reason})"


def test_unauthenticated_sqli_is_not_rce():
    _, reason, vt = _score(
        "CVE-2026-46670 YesWiki: Unauthenticated SQL Injection",
        "The YesWiki plugin for WordPress has unauthenticated SQL injection via the id parameter. (CVSS 9.8)",
    )
    assert vt != "RCE", f"plain SQLi mislabeled RCE (reason={reason})"


def test_pre_auth_info_disclosure_is_not_rce():
    _, reason, vt = _score(
        "CVE-2026-1 Pre-Auth Information Disclosure in FooPortal",
        "FooPortal exposes sensitive data via a pre-auth endpoint. (CVSS 8.2)",
    )
    assert vt != "RCE", f"info disclosure mislabeled RCE via 'pre-auth' (reason={reason})"


# --- the rescue: deserialization primitives stay/become RCE ---

def test_php_object_injection_is_rce_without_unauthenticated():
    # object injection is a deserialization/RCE primitive on its own
    _, reason, vt = _score(
        "CVE-2026-52706 PHP Object Injection in JetEngine",
        "JetEngine before 3.8.11 has a PHP object injection vulnerability. (CVSS 9.8)",
    )
    assert vt == "RCE", f"object injection should be RCE (reason={reason})"


def test_unauthenticated_php_object_injection_still_rce():
    # rescue target: unauth + object injection must NOT be downgraded
    _, reason, vt = _score(
        "CVE-2026-49769 Unauthenticated PHP Object Injection in wpForo Forum",
        "wpForo Forum <= 3.1.0 is prone to unauthenticated PHP object injection. (CVSS 9.8)",
    )
    assert vt == "RCE", f"unauth object injection should stay RCE (reason={reason})"


def test_unserialize_is_rce():
    _, reason, vt = _score(
        "CVE-2026-1 TYPO3 unserialize vulnerability",
        "TYPOCRUD deserializes untrusted input via unserialize() leading to code execution. (CVSS 9.8)",
    )
    assert vt == "RCE", f"unserialize() should be RCE (reason={reason})"


# --- no regression on real RCE ---

def test_unauthenticated_rce_still_rce():
    _, _, vt = _score(
        "CVE-2026-1 Unauthenticated Remote Code Execution in FooCMS",
        "FooCMS allows unauthenticated remote code execution via crafted requests. (CVSS 9.8)",
    )
    assert vt == "RCE"


def test_plain_rce_still_rce():
    _, reason, vt = _score(
        "CVE-2026-1 Remote Code Execution in nginx",
        "nginx RCE via malicious config. (CVSS 9.8)",
    )
    assert vt == "RCE"
    assert "asset" in reason  # 'nginx' is an asset keyword


# --- the cvs<-cvss asset substring bug ---

def test_cvss_does_not_trigger_cvs_asset():
    # '(CVSS 9.8)' must NOT match the 'cvs' asset keyword
    _, reason, vt = _score(
        "CVE-2026-1 Remote Code Execution in ContosoGreeter",
        "ContosoGreeter allows RCE via a crafted request. (CVSS 9.8)",
    )
    assert vt == "RCE"
    assert "asset" not in reason, f"'CVSS' falsely matched 'cvs' asset (reason={reason})"
