"""Tests for _is_fresh: all sources go through NVD verification.

High-trust sources (FRESH_SOURCES) fall back to CVE-year when NVD has no data
(new CVEs not yet indexed). Low-trust sources require NVD confirmation.
NVD-confirmed-stale records are nday even for high-trust sources.
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

from datetime import datetime, timezone

import src.vuln_monitor as v


def test_fresh_source_calls_nvd(monkeypatch):
    """High-trust sources must go through NVD — extra verification never hurts."""
    called = []
    monkeypatch.setattr(v, "_nvd_published_date",
                        lambda c: (called.append(c), (None, None))[1])
    fresh, _pub, reason = v._is_fresh("MSRC", "CVE-2026-12345 RCE in Windows")
    assert called, "high-trust source must query NVD for verification"
    assert fresh is True
    assert reason == "high_trust_source"


def test_fresh_source_nvd_confirms_recent(monkeypatch):
    """NVD confirms CVE is recent → 1day."""
    recent = datetime.now(timezone.utc)
    monkeypatch.setattr(v, "_nvd_published_date",
                        lambda c: (recent, recent.strftime("%Y-%m-%d")))
    fresh, pub, reason = v._is_fresh("Fortinet", "CVE-2026-99999 FG-IR vuln")
    assert fresh is True
    assert reason == "high_trust_source"
    assert pub is not None


def test_fresh_source_nvd_stale(monkeypatch):
    """NVD says CVE is >60 days old → nday even for high-trust source."""
    old_dt = datetime(2025, 1, 15, tzinfo=timezone.utc)
    monkeypatch.setattr(v, "_nvd_published_date",
                        lambda c: (old_dt, "2025-01-15"))
    fresh, pub, reason = v._is_fresh("MSRC", "CVE-2025-12345 old advisory update")
    assert fresh is False
    assert reason == "nvd_stale"


def test_fresh_source_old_cve_still_nday(monkeypatch):
    """Even for a high-trust source, a CVE older than a year is nday."""
    monkeypatch.setattr(v, "_nvd_published_date", lambda c: (None, None))
    fresh, _pub, reason = v._is_fresh("Fortinet", "CVE-2020-1111 old rehash")
    assert fresh is False
    assert reason == "old_cve"


def test_low_trust_source_still_uses_nvd(monkeypatch):
    called = []
    monkeypatch.setattr(v, "_nvd_published_date",
                        lambda c: (called.append(c), (None, None))[1])
    v._is_fresh("PoC-GitHub", "CVE-2026-12345 whatever")
    assert called, "low-trust source must still query NVD to confirm freshness"
