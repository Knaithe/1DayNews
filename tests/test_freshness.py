"""Tests for _is_fresh: high-trust (FRESH_SOURCES) records must NOT trigger a
per-CVE NVD lookup.

A multi-thousand-CVE MSRC bundle otherwise stalls the fetch run for tens of
minutes on rate-limited NVD calls, exceeding systemd's RuntimeMaxSec and
turning the daemon into a kill-restart loop. For FRESH_SOURCES the final
verdict is already unconditional 'fresh' (unless every CVE is >1yr old), and
that year check needs only the CVE id — not NVD.
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as v


def test_fresh_source_skips_nvd(monkeypatch):
    def boom(cve):
        raise AssertionError(f"FRESH source must not query NVD, but queried {cve}")
    monkeypatch.setattr(v, "_nvd_published_date", boom)
    fresh, _pub, reason = v._is_fresh("MSRC", "CVE-2026-12345 RCE in Windows")
    assert fresh is True
    assert reason == "high_trust_source"


def test_fresh_source_old_cve_still_nday(monkeypatch):
    # even for a high-trust source, a CVE older than a year is an nday rehash
    monkeypatch.setattr(v, "_nvd_published_date",
                        lambda c: (_ for _ in ()).throw(AssertionError("no NVD")))
    fresh, _pub, reason = v._is_fresh("Fortinet", "CVE-2020-1111 old rehash")
    assert fresh is False
    assert reason == "old_cve"


def test_low_trust_source_still_uses_nvd(monkeypatch):
    called = []
    monkeypatch.setattr(v, "_nvd_published_date",
                        lambda c: (called.append(c), (None, None))[1])
    v._is_fresh("PoC-GitHub", "CVE-2026-12345 whatever")
    assert called, "low-trust source must still query NVD to confirm freshness"
