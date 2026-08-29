from malware_analyzer.signature_analysis.models import EvidenceSource, Severity, make_evidence
from malware_analyzer.signature_analysis import scoring


def _ev(severity, confidence, weight=None, **kw):
    kwargs = dict(
        source=EvidenceSource.YARA,
        finding="test finding",
        severity=severity,
        confidence=confidence,
        reason="test reason",
        **kw,
    )
    if weight is not None:
        kwargs["weight"] = weight
    return make_evidence(**kwargs)


def test_score_no_evidence_is_likely_safe():
    result = scoring.score_evidence([])
    assert result["score"] == 0
    assert result["verdict"] == "LIKELY_SAFE"
    assert result["confidence"] == 0.0
    # Regression: engine.py unconditionally reads these keys from every
    # score_evidence() result, including the empty-evidence early return.
    assert result["strong_evidence"] == []
    assert result["supporting_evidence"] == []


def test_score_single_weak_evidence_stays_low():
    e = _ev(Severity.LOW, 0.2)
    result = scoring.score_evidence([e])
    assert result["score"] < 20
    assert result["verdict"] == "LIKELY_SAFE"


def test_score_strong_critical_high_confidence_reaches_malicious():
    e = _ev(Severity.CRITICAL, 0.95, weight=90)
    result = scoring.score_evidence([e])
    assert result["verdict"] == "MALICIOUS"
    assert result["score"] >= 70


def test_score_high_severity_but_low_confidence_does_not_alone_reach_malicious():
    # Many HIGH severity but low-confidence findings shouldn't alone hit MALICIOUS,
    # because aggregate confidence gates the verdict.
    evidence = [_ev(Severity.HIGH, 0.2, weight=35) for _ in range(5)]
    result = scoring.score_evidence(evidence)
    assert result["confidence"] < 0.55
    assert result["verdict"] != "MALICIOUS"


def test_score_evidence_sorted_by_contribution():
    e_low = _ev(Severity.LOW, 0.2, weight=5)
    e_high = _ev(Severity.CRITICAL, 0.9, weight=90)
    result = scoring.score_evidence([e_low, e_high])
    assert result["evidence"][0]["finding"] == e_high.finding
    assert result["evidence"][0]["score_contribution"] > result["evidence"][1]["score_contribution"]


def test_score_strong_vs_supporting_split():
    e_strong = _ev(Severity.HIGH, 0.8, weight=35)
    e_weak = _ev(Severity.LOW, 0.2, weight=5)
    result = scoring.score_evidence([e_strong, e_weak])
    assert len(result["strong_evidence"]) == 1
    assert len(result["supporting_evidence"]) == 1


def test_scoring_notes_disclaim_calibration():
    e = _ev(Severity.MEDIUM, 0.5, weight=15)
    result = scoring.score_evidence([e])
    assert "NOT a statistically calibrated probability" in result["scoring_notes"]


def test_score_capped_at_100():
    evidence = [_ev(Severity.CRITICAL, 1.0, weight=90) for _ in range(6)]
    result = scoring.score_evidence(evidence)
    assert result["score"] <= 100
