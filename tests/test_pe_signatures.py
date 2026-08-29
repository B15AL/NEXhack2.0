from malware_analyzer.signature_analysis import pe_signatures
from malware_analyzer.pe_info import parse_pe


def test_analyze_pe_signatures_non_pe_returns_empty():
    result = pe_signatures.analyze_pe_signatures("/some/path", {"is_pe": False})
    assert result == {"details": {}, "evidence": []}


def test_analyze_pe_signatures_empty_pe_info():
    result = pe_signatures.analyze_pe_signatures("/some/path", {})
    assert result == {"details": {}, "evidence": []}


def test_analyze_pe_signatures_benign_minimal_pe(minimal_pe_path):
    pe_info = parse_pe(minimal_pe_path)
    assert pe_info["is_pe"] is True
    result = pe_signatures.analyze_pe_signatures(minimal_pe_path, pe_info)
    assert "sections" in result["details"]
    # a plain NOP-filled section shouldn't trigger RWX or import-combo evidence
    categories = {e.category for e in result["evidence"]}
    assert "process_injection" not in categories
    assert "spyware" not in categories


def test_analyze_pe_signatures_overlay_detection(minimal_pe_path):
    # Append >1KB of overlay data past the declared sections
    with open(minimal_pe_path, "ab") as f:
        f.write(b"\xAA" * 2048)
    pe_info = parse_pe(minimal_pe_path)
    result = pe_signatures.analyze_pe_signatures(minimal_pe_path, pe_info)
    assert result["details"]["overlay"]["has_overlay"] is True
    assert result["details"]["overlay"]["overlay_size"] >= 2048
    assert any(e.category == "pe_overlay" for e in result["evidence"])


def test_section_flags_executable_and_writable(minimal_pe_path):
    flags = pe_signatures._section_flags(minimal_pe_path)
    assert len(flags) == 1
    assert flags[0]["name"] == ".text"
    assert flags[0]["executable"] is True


def test_import_function_names_empty_for_no_imports(minimal_pe_path):
    names = pe_signatures._import_function_names(minimal_pe_path)
    assert names == {}
