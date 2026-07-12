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


# --- gap fix: deserialization verb forms & 'execute arbitrary <X> commands' ---
# These phrasings are RCE but were missed once 'unauthenticated' stopped being a
# blanket RCE trigger. See audit of CVE-2026-40860 / -11860 / -48909 / -49188 / -35906.

def test_deserialized_verb_form_is_rce():
    # CVE-2026-40860 camel-jms — past tense 'deserialized' (not 'deserialization')
    _, reason, vt = _score(
        "CVE-2026-40860 camel-jms untrusted JMS payload handling",
        "JmsBinding.extractBodyFromJms() deserialized the payload of incoming JMS ObjectMessage values via javax.jms. (CVSS 9.8)",
    )
    assert vt == "RCE", f"'deserialized' (verb) should be RCE (reason={reason})"


def test_deserializes_cookie_is_rce():
    # CVE-2026-48909 SP LMS — 'deserializes' user-controlled cookie
    _, reason, vt = _score(
        "CVE-2026-48909 SP LMS (com_splms) cookie handling",
        "SP LMS deserializes user-controlled cookie data without validation. (CVSS 9.8)",
    )
    assert vt == "RCE", f"'deserializes' (verb) should be RCE (reason={reason})"


def test_execute_arbitrary_root_commands_is_rce():
    # CVE-2026-49188 ai_cmd — adjective 'root' between 'arbitrary' and 'commands'
    _, reason, vt = _score(
        "CVE-2026-49188 ai_cmd runs with root via popen",
        "The ai_cmd utility pipes socket input to popen() to execute arbitrary root commands. (CVSS 9.8)",
    )
    assert vt == "RCE", f"'execute arbitrary root commands' should be RCE (reason={reason})"


def test_execute_arbitrary_system_commands_is_rce():
    # CVE-2026-35906 T3 CPE debug CGI — 'system' between 'arbitrary' and 'commands'
    _, reason, vt = _score(
        "CVE-2026-35906 T3 CPE undocumented debug CGI endpoint",
        "A debug CGI endpoint lets attackers execute arbitrary system commands as root. (CVSS 9.6)",
    )
    assert vt == "RCE", f"'execute arbitrary system commands' should be RCE (reason={reason})"


def test_dos_deserialization_not_rce():
    # broadening deserialization must NOT turn DoS-deserialization into RCE (EXCLUDE wins)
    _, reason, vt = _score(
        "CVE-2026-42570 Svelte devalue memory exhaustion",
        "Svelte devalue: DoS via sparse array deserialization causing excessive memory allocation. (CVSS 7.5)",
    )
    assert vt != "RCE", f"DoS-deserialization must not be RCE (reason={reason})"


def test_execute_arbitrary_sql_queries_not_rce():
    # 'execute arbitrary SELECT SQL queries' is SQLi — broadened exec pattern must not catch it
    _, reason, vt = _score(
        "CVE-2026-8335 Aix-DB missing auth on llm endpoint",
        "A missing auth check lets clients execute arbitrary SELECT SQL queries and retrieve data. (CVSS 8.0)",
    )
    assert vt != "RCE", f"SQLi must not be RCE (reason={reason})"


# --- score() precision/recall overhaul (full audit 2026-06-27) ---

def test_sqli_execute_queries_not_rce():
    # CRITICAL-1: bare 'exec' in SQLi-chain pattern must not match 'execute'
    _, reason, vt = _score("CVE-2026-3325 MegaCMS SQL injection",
                           "SQL injection lets an unauthenticated attacker execute arbitrary SQL queries.")
    assert vt != "RCE", f"SQLi 'execute queries' must not be RCE (reason={reason})"


def test_sqli_xp_cmdshell_chain_still_rce():
    # CRITICAL-1 fix must still catch genuine SQLi->RCE chains
    _, reason, vt = _score("CVE-x sqli", "SQL injection via xp_cmdshell used to exec OS commands.")
    assert vt == "RCE", f"xp_cmdshell SQLi->RCE chain should be RCE (reason={reason})"


def test_acronym_glued_to_chinese_is_rce():
    # CRITICAL-2: \b fails at CJK boundaries; '认证绕过RCE漏洞' must be RCE
    _, reason, vt = _score("CVE-x 认证绕过RCE漏洞", "攻击者可远程执行任意代码。")
    assert vt == "RCE", f"acronym glued to Chinese must be RCE (reason={reason})"


def test_sql_command_injection_not_rce():
    # HIGH-2: 'SQL command injection' is SQLi, not RCE
    _, reason, vt = _score("CVE-x login", "SQL command injection in the login endpoint allows auth bypass.")
    assert vt != "RCE", f"'SQL command injection' must not be RCE (reason={reason})"


def test_os_command_injection_still_rce():
    _, reason, vt = _score("CVE-x ping", "OS command injection via the ping endpoint.")
    assert vt == "RCE"


def test_bare_command_execution_is_rce():
    # A (recall): bare 'command execution' without 'arbitrary' before it
    _, reason, vt = _score("CVE-2026-38615 DedeCMS", "DedeCMS is vulnerable to unauthenticated command execution.")
    assert vt == "RCE", f"bare 'command execution' should be RCE (reason={reason})"


def test_arbitrary_file_write_is_rce():
    # A (recall): arbitrary file write is an RCE primitive (cron/authorized_keys/webroot)
    _, reason, vt = _score("CVE-2026-20253 Splunk",
                           "An unauthenticated user could create or truncate arbitrary files via the sidecar endpoint.")
    assert vt == "RCE", f"arbitrary file write/create/truncate should be RCE (reason={reason})"


def test_xss_to_rce_chain_not_excluded():
    # HIGH-1: XSS chaining to RCE must not be excluded by the XSS filter
    _, reason, vt = _score("CVE-2026-44670 YesWiki", "Stored XSS via Attribute View Name to Electron Renderer RCE.")
    assert vt == "RCE", f"XSS->RCE chain must not be excluded (reason={reason})"


def test_plain_xss_still_not_rce():
    # the RCE-override must not break plain XSS exclusion
    _, reason, vt = _score("CVE-x comments", "A stored XSS in the comment field allows cookie theft.")
    assert vt != "RCE", f"plain XSS must not become RCE (reason={reason})"


def test_sqli_in_rce_substring_product_not_rce():
    # CVE-2026-54849: SQL Injection in Premmerce/WooCommerce — the 'rce' inside
    # 'Commerce' must NOT satisfy 'SQL injection.*RCE' (the bare RCE alt had no \b)
    _, reason, vt = _score("CVE-2026-54849 Unauthenticated SQL Injection in Premmerce Wishlist for WooCommerce")
    assert vt != "RCE", f"plain SQLi mislabeled RCE via 'rce' substring (reason={reason})"


def test_ssrf_with_rce_before_not_excluded():
    # MEDIUM: RCE appearing BEFORE 'SSRF' must still prevent SSRF exclusion
    _, reason, vt = _score("CVE-x webhook",
                           "Remote Code Execution and Server-Side Request Forgery in the webhook handler.")
    assert vt == "RCE", f"RCE before SSRF must not be excluded (reason={reason})"


def test_execute_arbitrary_sql_commands_not_rce():
    # CVE-2019-25728: 'execute arbitrary SQL commands' is SQLi — the modifier
    # slot must not let 'SQL' through to match 'commands'
    _, reason, vt = _score("CVE-2019-25728 Care2x",
                           "The flaw allows an attacker to execute arbitrary SQL commands on the backend.")
    assert vt != "RCE", f"'execute arbitrary SQL commands' must not be RCE (reason={reason})"


def test_execute_arbitrary_os_commands_still_rce():
    # the fix must keep genuine OS/root command execution as RCE
    _, reason, vt = _score("CVE-x", "Allows an unauthenticated attacker to execute arbitrary OS commands.")
    assert vt == "RCE", f"'execute arbitrary OS commands' should be RCE (reason={reason})"


# --- short asset keywords must use word boundaries (not raw substring) ---

def test_short_asset_ise_not_inside_enterprise():
    # 'ise' must not match inside 'enterprise' → no asset+CVE false positive
    hit, reason, vt = _score(
        "CVE-2026-1 enterprise noise",
        "Something in the enterprise product line. (CVSS 9.8)",
    )
    assert "asset" not in reason, f"'ise' leaked from enterprise (reason={reason})"


def test_short_asset_nsa_not_inside_transaction():
    hit, reason, _ = _score(
        "CVE-2026-1 transaction processing flaw",
        "A flaw in transaction handling. (CVSS 7.5)",
    )
    assert "asset" not in reason, f"'nsa' leaked from transaction (reason={reason})"


def test_short_asset_tar_not_inside_start():
    hit, reason, _ = _score(
        "CVE-2026-1 start of request parser",
        "Bug at the start of the request pipeline. (CVSS 7.5)",
    )
    assert "asset" not in reason, f"'tar' leaked from start (reason={reason})"


def test_short_asset_real_product_still_hits():
    # real short tokens as whole words still count
    assert vm.asset_hit("cisco ise vulnerability")
    assert vm.asset_hit("progress adc rce")
    assert vm.asset_hit("sonicwall nsa 2700")
    # long keywords unchanged
    assert vm.asset_hit("fortigate rce")
    assert vm.asset_hit("remote code execution in nginx")


def test_webshell_bypasses_xss_exclude():
    # webshell is an RCE primitive; a co-occurring XSS must not exclude it
    _, reason, vt = _score("CVE-2026-1 webshell upload via stored XSS in nginx", "")
    assert vt == "RCE", f"webshell should stay RCE despite XSS (reason={reason})"


def test_arbitrary_file_write_bypasses_xss_exclude():
    # arbitrary file write is an RCE primitive; a co-occurring XSS must not exclude it
    _, reason, vt = _score("CVE-2026-1 arbitrary file write chained from XSS in nginx", "")
    assert vt == "RCE", f"arbitrary file write should stay RCE despite XSS (reason={reason})"


def test_jndi_bypasses_ssrf_exclude():
    # JNDI/OGNL are unambiguous injection-to-RCE primitives (not DoS-confusable);
    # a co-occurring SSRF must not exclude them. deserialization/SSTI stay OUT of
    # _STRONG_RCE_RE because they can be DoS — see test_dos_deserialization_not_rce.
    _, reason, vt = _score("CVE-2026-1 JNDI injection via SSRF endpoint in log4j", "")
    assert vt == "RCE", f"JNDI should stay RCE despite SSRF (reason={reason})"
