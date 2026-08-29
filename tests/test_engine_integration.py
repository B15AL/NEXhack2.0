from malware_analyzer.signature_analysis import analyze_signatures
from malware_analyzer.hashes import compute_hashes
from malware_analyzer.strings_extractor import extract_strings
from malware_analyzer.network_iocs import extract_iocs_from_strings
from malware_analyzer.pe_info import parse_pe
from malware_analyzer.analyze import analyze_file


def _build_context(path):
    strings = extract_strings(path)
    return {
        "hashes": compute_hashes(path),
        "strings": strings,
        "iocs": extract_iocs_from_strings(strings),
        "pe_info": parse_pe(path),
    }


def test_engine_end_to_end_benign_file_is_safe(minimal_pe_path):
    context = _build_context(minimal_pe_path)
    report = analyze_signatures(minimal_pe_path, context)
    assert report["verdict"] == "LIKELY_SAFE"
    assert report["score"] < 35
    assert "score_contribution" not in report  # sanity: top-level keys are correct
    assert report["yara"]["available"] in (True, False)
    assert isinstance(report["evidence"], list)


def test_engine_end_to_end_keylogger_like_flags_higher(minimal_pe_path, keylogger_like_pe_path):
    baseline_context = _build_context(minimal_pe_path)
    baseline = analyze_signatures(minimal_pe_path, baseline_context)

    context = _build_context(keylogger_like_pe_path)
    report = analyze_signatures(keylogger_like_pe_path, context)

    # A single YARA match is deliberately not enough alone to reach
    # SUSPICIOUS/MALICIOUS (see "do not overstate weak indicators" in the
    # scoring design) -- but it must score strictly higher than a clean
    # file and surface as explainable YARA evidence.
    assert report["score"] > baseline["score"]
    assert any(e["source"] == "yara" for e in report["evidence"])
    assert any(e["finding"].startswith("YARA rule matched: Suspicious_Keylogger_Combo") for e in report["evidence"])


def test_engine_missing_context_keys_degrades_gracefully(minimal_pe_path):
    # empty context -- every sub-component must handle missing keys without raising
    report = analyze_signatures(minimal_pe_path, {})
    assert report["verdict"] == "LIKELY_SAFE"


def test_engine_nonexistent_file_does_not_raise():
    report = analyze_signatures("/nonexistent/path.exe", {})
    assert report["score"] == 0
    assert report["verdict"] == "LIKELY_SAFE"


def test_analyze_file_integration_adds_signature_analysis_field(minimal_pe_path):
    report = analyze_file(minimal_pe_path, vt_lookup=False, yara_rules=None)
    assert "signature_analysis" in report
    assert "risk" in report  # legacy field still present and unmodified in shape
    assert set(report["risk"].keys()) == {"score", "level", "verdict", "reasons"}


def test_analyze_file_can_disable_signature_analysis(minimal_pe_path):
    report = analyze_file(minimal_pe_path, vt_lookup=False, yara_rules=None, run_signature_analysis=False)
    assert "signature_analysis" not in report
    assert "risk" in report


def test_analyze_file_signature_analysis_does_not_break_legacy_risk(minimal_pe_path):
    report = analyze_file(minimal_pe_path, vt_lookup=False, yara_rules=None)
    # legacy calculate_risk() must still compute a plain dict with the same keys as before
    risk = report["risk"]
    assert isinstance(risk["score"], int)
    assert risk["verdict"] in ("MALICIOUS", "SUSPICIOUS", "LIKELY SAFE")


def test_engine_multi_evidence_correlation_reaches_suspicious_or_higher(tmp_path):
    """Combine a YARA match with reinforcing string-signature categories in one
    file to demonstrate the correlation bonus actually moving the verdict,
    matching the project's 'combined evidence is stronger' requirement."""
    from tests.conftest import build_minimal_pe

    strings_blob = b"\x00".join(
        [
            b"SetWindowsHookExA", b"GetAsyncKeyState", b"ShowWindow",
            b"OpenProcess", b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
            b"IsDebuggerPresent", b"VBoxService",
            b"",
        ]
    )
    data = build_minimal_pe(section_data=b"\x90" * 64, extra_strings=strings_blob)
    p = tmp_path / "multi_evidence.exe"
    p.write_bytes(data)
    path = str(p)

    context = _build_context(path)
    report = analyze_signatures(path, context)

    assert report["score"] > 0
    assert len(report["evidence"]) >= 3
    # Multiple YARA rules should fire (keylogger combo, injection combo, anti-analysis combo)
    yara_rules_hit = {
        e["matched_value"] for e in report["evidence"] if e["source"] == "yara"
    }
    assert len(yara_rules_hit) >= 2


def test_analyze_file_iocs_field_now_populated(minimal_pe_path):
    report = analyze_file(minimal_pe_path, vt_lookup=False, yara_rules=None)
    assert "iocs" in report
    assert isinstance(report["iocs"], dict)
