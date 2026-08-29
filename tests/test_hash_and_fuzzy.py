import hashlib
import json
import os

from malware_analyzer.signature_analysis import hash_signatures, fuzzy_hash, config


def test_analyze_hash_signatures_hits_known_hash(tmp_path):
    p = tmp_path / "known.bin"
    p.write_bytes(b"test")
    from malware_analyzer.hashes import compute_hashes
    hashes = compute_hashes(str(p))
    assert hashes["sha256"] == hashlib.sha256(b"test").hexdigest()

    db = hash_signatures.load_known_hashes()
    assert hashes["sha256"] in db  # bundled fixture entry from known_hashes.json

    evidence = hash_signatures.analyze_hash_signatures(hashes, known_hashes=db)
    assert len(evidence) == 1
    assert evidence[0].severity.value == "CRITICAL"
    assert evidence[0].confidence == 1.0


def test_analyze_hash_signatures_no_match(tmp_path):
    p = tmp_path / "unknown.bin"
    p.write_bytes(os.urandom(64))
    from malware_analyzer.hashes import compute_hashes
    hashes = compute_hashes(str(p))
    evidence = hash_signatures.analyze_hash_signatures(hashes)
    assert evidence == []


def test_analyze_hash_signatures_empty_hashes():
    assert hash_signatures.analyze_hash_signatures({}) == []


def test_compute_tlsh_small_file(tiny_file_path):
    result = fuzzy_hash.compute_tlsh(tiny_file_path)
    assert result["available"] is False
    assert "too small" in result["reason"]


def test_compute_tlsh_empty_file(empty_file_path):
    result = fuzzy_hash.compute_tlsh(empty_file_path)
    assert result["available"] is False


def test_compute_tlsh_normal_file(benign_text_path):
    result = fuzzy_hash.compute_tlsh(benign_text_path)
    if not fuzzy_hash.TLSH_AVAILABLE:
        assert result["available"] is False
        return
    assert result["available"] is True
    assert result["hash"]
    assert result["hash"].startswith("T1")


def test_tlsh_distance_identical():
    if not fuzzy_hash.TLSH_AVAILABLE:
        return
    h = fuzzy_hash.compute_tlsh.__globals__  # noop guard
    import tlsh
    data = (b"The quick brown fox jumps over the lazy dog. " * 20)
    h1 = tlsh.hash(data)
    h2 = tlsh.hash(data)
    assert fuzzy_hash.tlsh_distance(h1, h2) == 0


def test_analyze_fuzzy_hash_matches_reference(tmp_path):
    if not fuzzy_hash.TLSH_AVAILABLE:
        return
    refs = fuzzy_hash.load_reference_signatures()
    assert refs, "bundled tlsh_references.json should ship with synthetic entries"

    # Build a file that reconstructs the exact synthetic reference bytes so
    # distance is guaranteed to be 0 (deterministic, no flakiness).
    import random
    def synth_bytes(seed_text, size=4096):
        random.seed(seed_text)
        base = (seed_text.encode() * (size // len(seed_text) + 1))[:size]
        b = bytearray(base)
        for i in range(0, len(b), 7):
            b[i] = random.randint(0, 255)
        return bytes(b)

    target_name = refs[0]["name"]
    p = tmp_path / "match.bin"
    p.write_bytes(synth_bytes(target_name))

    result = fuzzy_hash.analyze_fuzzy_hash(str(p), references=refs)
    assert result["tlsh"]["available"] is True
    assert any(c["distance"] == 0 for c in result["comparisons"])
    assert any(e.finding.startswith("TLSH similarity") for e in result["evidence"])
    # similarity evidence must never claim to be proof
    assert all("not proof" in e.reason for e in result["evidence"])


def test_analyze_fuzzy_hash_dissimilar_reference(benign_text_path):
    if not fuzzy_hash.TLSH_AVAILABLE:
        return
    result = fuzzy_hash.analyze_fuzzy_hash(benign_text_path)
    # a plain repeated-text file should not spuriously match the malware-shaped refs
    strong_hits = [c for c in result["comparisons"] if c["classification"] == "strong_similarity"]
    assert strong_hits == []


def test_load_known_hashes_missing_file(tmp_path):
    missing = str(tmp_path / "does_not_exist.json")
    assert hash_signatures.load_known_hashes(missing) == {}


def test_load_reference_signatures_missing_file(tmp_path):
    missing = str(tmp_path / "does_not_exist.json")
    assert fuzzy_hash.load_reference_signatures(missing) == []
