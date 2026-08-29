import base64

from malware_analyzer.signature_analysis import string_signatures


def test_classify_strings_registry_path():
    strings = [r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"]
    findings = string_signatures.classify_strings(strings)
    assert len(findings["registry_path"]) == 1
    assert findings["registry_path"][0]["category"] == "registry_path"


def test_classify_strings_powershell():
    strings = ["powershell.exe -nop -windowstyle hidden -enc SGVsbG8="]
    findings = string_signatures.classify_strings(strings)
    assert len(findings["powershell"]) == 1


def test_classify_strings_cmd_shell():
    strings = ["cmd.exe /c whoami", "rundll32.exe evil.dll,Entry"]
    findings = string_signatures.classify_strings(strings)
    assert len(findings["cmd_shell"]) == 2


def test_classify_strings_suspicious_api():
    strings = ["kernel32.dll", "VirtualAllocEx used here for allocation"]
    findings = string_signatures.classify_strings(strings)
    assert any(i["value"] == "VirtualAllocEx" for i in findings["suspicious_api"])


def test_classify_strings_encoded_blob_safe_decode():
    payload = base64.b64encode(b"this is a safe static decode preview only").decode()
    strings = [f"config={payload}"]
    findings = string_signatures.classify_strings(strings)
    assert len(findings["encoded_blob"]) == 1
    decoded = findings["encoded_blob"][0].get("decoded_preview")
    assert decoded is not None
    assert "safe static decode" in decoded


def test_classify_strings_no_false_positive_on_plain_text():
    strings = ["Hello world", "This is a normal sentence.", "Version 1.2.3"]
    findings = string_signatures.classify_strings(strings)
    assert all(len(v) == 0 for v in findings.values())


def test_iocs_to_evidence_weak_confidence():
    iocs = {"urls": ["http://example.com/a"], "domains": [], "ipv4": ["1.2.3.4"]}
    evidence = string_signatures.iocs_to_evidence(iocs)
    assert len(evidence) == 2
    for e in evidence:
        assert e.confidence <= 0.3
        assert e.possible_false_positive is True


def test_iocs_to_evidence_empty():
    assert string_signatures.iocs_to_evidence({}) == []


def test_analyze_string_signatures_end_to_end():
    strings = ["powershell -enc AAAA", "http://malicious.example/payload"]
    iocs = {"urls": ["http://malicious.example/payload"], "domains": [], "ipv4": []}
    result = string_signatures.analyze_string_signatures(strings, iocs)
    assert result["evidence"]
    categories = {e.category for e in result["evidence"]}
    assert "powershell" in categories
