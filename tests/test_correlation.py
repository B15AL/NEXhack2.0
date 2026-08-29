from malware_analyzer.signature_analysis.models import Evidence, EvidenceSource, Severity, make_evidence
from malware_analyzer.signature_analysis import correlation


def _ev(source, category, correlation_id=None, confidence=0.3, severity=Severity.LOW):
    return make_evidence(
        source=source,
        finding=f"finding for {category}",
        severity=severity,
        confidence=confidence,
        reason="test",
        category=category,
        correlation_id=correlation_id,
    )


def test_deduplicate_merges_same_correlation_id():
    e1 = _ev(EvidenceSource.YARA, "cat_a", correlation_id="artifact:1", confidence=0.4)
    e2 = _ev(EvidenceSource.STRING_IOC, "cat_a", correlation_id="artifact:1", confidence=0.7)
    merged = correlation.deduplicate([e1, e2])
    assert len(merged) == 1
    assert merged[0].confidence == 0.7
    assert "Corroborated by" in merged[0].reason


def test_deduplicate_keeps_distinct_correlation_ids():
    e1 = _ev(EvidenceSource.YARA, "cat_a", correlation_id="artifact:1")
    e2 = _ev(EvidenceSource.YARA, "cat_b", correlation_id="artifact:2")
    merged = correlation.deduplicate([e1, e2])
    assert len(merged) == 2


def test_deduplicate_keeps_unkeyed_evidence():
    e1 = _ev(EvidenceSource.PE_STATIC, "cat_a", correlation_id=None)
    e2 = _ev(EvidenceSource.PE_STATIC, "cat_b", correlation_id=None)
    merged = correlation.deduplicate([e1, e2])
    assert len(merged) == 2


def test_correlate_adds_bonus_for_reinforcing_group():
    e1 = _ev(EvidenceSource.STRING_IOC, "powershell", severity=Severity.MEDIUM, confidence=0.35)
    e2 = _ev(EvidenceSource.STRING_IOC, "network_ioc", severity=Severity.LOW, confidence=0.2)
    combined, bundles = correlation.correlate([e1, e2])
    assert len(bundles) == 1
    assert bundles[0]["bundle"] == "downloader_chain"
    synthetic = [e for e in combined if e.source == EvidenceSource.CORRELATION]
    assert len(synthetic) == 1
    assert synthetic[0].severity == Severity.HIGH


def test_correlate_no_bonus_for_single_category():
    e1 = _ev(EvidenceSource.STRING_IOC, "powershell", severity=Severity.MEDIUM, confidence=0.35)
    combined, bundles = correlation.correlate([e1])
    assert bundles == []
    assert not any(e.source == EvidenceSource.CORRELATION for e in combined)


def test_correlate_no_bonus_for_unrelated_categories():
    e1 = _ev(EvidenceSource.STRING_IOC, "registry_path", severity=Severity.LOW, confidence=0.2)
    e2 = _ev(EvidenceSource.PE_STATIC, "packer", severity=Severity.LOW, confidence=0.5)
    combined, bundles = correlation.correlate([e1, e2])
    # "packer" alone (min_hits=2 required from packed_and_suspicious_static group) shouldn't fire
    assert bundles == []
