from malware_analyzer.signature_analysis import yara_engine


def test_yara_bundled_rules_no_match_on_benign(minimal_pe_path):
    result = yara_engine.analyze_yara(minimal_pe_path)
    assert result["available"] is True
    assert result["matches"] == []
    assert result["evidence"] == []


def test_yara_bundled_rules_positive_match(keylogger_like_pe_path):
    result = yara_engine.analyze_yara(keylogger_like_pe_path)
    assert result["available"] is True
    rule_names = [m["rule"] for m in result["matches"]]
    assert "Suspicious_Keylogger_Combo" in rule_names

    match = next(m for m in result["matches"] if m["rule"] == "Suspicious_Keylogger_Combo")
    assert match["severity"] == "HIGH"
    assert match["category"] == "spyware"
    assert 0.0 < match["confidence"] <= 1.0
    assert match["matched_strings"], "structured match should include string offsets"

    evidence = result["evidence"]
    assert any(e.finding.startswith("YARA rule matched: Suspicious_Keylogger_Combo") for e in evidence)


def test_yara_external_rules_file(tmp_path, minimal_pe_path):
    custom_rule = tmp_path / "custom.yar"
    custom_rule.write_text(
        'rule Always_Matches_MZ {\n'
        '  meta:\n'
        '    description = "test rule"\n'
        '    category = "test"\n'
        '    severity = "low"\n'
        '    confidence = "0.9"\n'
        '  condition:\n'
        '    uint16(0) == 0x5A4D\n'
        '}\n'
    )
    result = yara_engine.analyze_yara(minimal_pe_path, external_rules_path=str(custom_rule))
    rule_names = [m["rule"] for m in result["matches"]]
    assert "Always_Matches_MZ" in rule_names


def test_yara_missing_file_returns_empty():
    result = yara_engine.scan_structured("/nonexistent/path/file.exe")
    assert result == []


def test_yara_negative_match_ordinary_text(benign_text_path):
    result = yara_engine.analyze_yara(benign_text_path)
    assert result["matches"] == []
