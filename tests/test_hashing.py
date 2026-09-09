"""DM-19 — hashing + canonical serialization (DM-16/DM-17)."""
import hashlib

from lykos.hashing import (canonical_json, compute_cache_key, hash_all_file,
                               hash_bytes)


def test_hash_bytes_matches_hashlib():
    assert hash_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()


def test_hash_all_file(tmp_path):
    p = tmp_path / "f.bin"
    data = b"binary\x00content" * 1000
    p.write_bytes(data)
    info = hash_all_file(p)
    assert info["sha256"] == hashlib.sha256(data).hexdigest()
    assert info["md5"] == hashlib.md5(data).hexdigest()
    assert info["size"] == len(data)


def test_canonical_json_is_order_independent():
    a = canonical_json({"b": 1, "a": {"y": 2, "x": 3}})
    b = canonical_json({"a": {"x": 3, "y": 2}, "b": 1})
    assert a == b


def test_cache_key_stable_and_sensitive():
    k1 = compute_cache_key("triage", ["h1", "h2"], {"opt": 1}, "lief-0.14")
    # input-order-insensitive
    assert k1 == compute_cache_key("triage", ["h2", "h1"], {"opt": 1}, "lief-0.14")
    # sensitive to every component
    assert k1 != compute_cache_key("triage", ["h1", "h2"], {"opt": 2}, "lief-0.14")
    assert k1 != compute_cache_key("triage", ["h1", "h2"], {"opt": 1}, "lief-0.15")
    assert k1 != compute_cache_key("other", ["h1", "h2"], {"opt": 1}, "lief-0.14")
    assert k1 != compute_cache_key("triage", ["h1"], {"opt": 1}, "lief-0.14")
