from malware_analyzer.signature_analysis import byte_signatures


def test_scan_byte_signatures_nop_sled(tmp_path):
    p = tmp_path / "nopsled.bin"
    p.write_bytes(b"\x00" * 100 + b"\x90" * 20 + b"\x00" * 100)
    matches = byte_signatures.scan_byte_signatures(str(p))
    names = [m["name"] for m in matches]
    assert "NOP_Sled_Long" in names


def test_scan_byte_signatures_no_match_on_random(tmp_path):
    p = tmp_path / "clean.bin"
    p.write_bytes(bytes(range(256)) * 4)
    matches = byte_signatures.scan_byte_signatures(str(p))
    assert matches == []


def test_scan_byte_signatures_xor_loop_wildcard(tmp_path):
    p = tmp_path / "xor.bin"
    # 80 34 <any> <any> 40 3D  -- wildcard bytes should match any value there
    p.write_bytes(b"\x00" * 10 + bytes([0x80, 0x34, 0xAB, 0xCD, 0x40, 0x3D]) + b"\x00" * 10)
    matches = byte_signatures.scan_byte_signatures(str(p))
    names = [m["name"] for m in matches]
    assert "Common_XOR_Decoder_Loop_32bit" in names


def test_scan_byte_signatures_min_offset_respected(tmp_path):
    p = tmp_path / "overlay.bin"
    pattern = bytes.fromhex("504500004c01")
    # place pattern before min_offset (4096) -- should NOT be reported
    data = b"\x00" * 100 + pattern + b"\x00" * 5000
    p.write_bytes(data)
    matches = byte_signatures.scan_byte_signatures(str(p))
    assert not any(m["name"] == "Embedded_PE_Overlay_Marker" for m in matches)

    # place pattern after min_offset -- should be reported
    data2 = b"\x00" * 5000 + pattern + b"\x00" * 100
    p.write_bytes(data2)
    matches2 = byte_signatures.scan_byte_signatures(str(p))
    assert any(m["name"] == "Embedded_PE_Overlay_Marker" for m in matches2)


def test_byte_matches_grouped_into_single_evidence(tmp_path):
    p = tmp_path / "many_nops.bin"
    p.write_bytes((b"\x90" * 20 + b"\x00" * 50) * 3)
    matches = byte_signatures.scan_byte_signatures(str(p))
    evidence = byte_signatures.byte_matches_to_evidence(matches)
    nop_evidence = [e for e in evidence if e.category == "shellcode" and "NOP" in e.finding]
    assert len(nop_evidence) == 1  # grouped, not one Evidence per occurrence
    assert nop_evidence[0].finding.count("occurrence") >= 1


def test_informational_pattern_not_scored(tmp_path):
    p = tmp_path / "mz.bin"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    matches = byte_signatures.scan_byte_signatures(str(p))
    assert not any(m["name"] == "PE_MZ_Header" for m in matches)


def test_missing_file_returns_empty():
    assert byte_signatures.scan_byte_signatures("/nonexistent/file.bin") == []
