"""House of Water: a leakless arbitrary allocation on modern glibc (>= 2.32). The tcache_perthread_struct
entries[] heads are not safe-linked, so corrupting them points a bin at an arbitrary address with no
heap leak -- the no-leak extension of lykos's heap column."""
from lykos.analyze.poc import heap


def test_recipe_is_leakless_and_in_tcache_range():
    r = heap.house_of_water_recipe(0x40)
    assert r["ok"] and r["leakless"] is True
    assert r["tcache_index"] == heap.tcache_index(heap.request2size(0x40))
    assert any(op[0] == "alloc" for op in r["ops"])
    assert "no heap leak" in r["result"] or "leakless" in r["result"]


def test_recipe_rejects_non_tcache_size():
    r = heap.house_of_water_recipe(0x2000)   # too big for tcache
    assert r["ok"] is False


def test_forge_tcache_perthread_writes_count_and_entry():
    idx, target = 5, 0x4141414141414140             # 16-byte aligned (tcache_get aligned_OK)
    w = heap.forge_tcache_perthread(idx, target, count=1)
    # counts[idx] at idx*2 == 1 ; entries[idx] at 0x80 + idx*8 == target (both unmangled)
    assert w[idx * 2] == b"\x01\x00"
    import struct
    assert w[0x80 + idx * 8] == struct.pack("<Q", target)


def test_forge_rejects_bad_index():
    import pytest
    with pytest.raises(ValueError):
        heap.forge_tcache_perthread(64, 0x1000)


def test_recipe_is_json_serializable():
    import json
    r = heap.house_of_water_recipe(0x40)
    json.dumps(r)                                    # no function objects in evidence
    r2 = heap.house_of_water_recipe(0x40, target=0x404040)
    s = json.loads(json.dumps(r2))
    assert s["ok"] and s["target"] == "0x404040"
    idx = r2["tcache_index"]
    assert s["writes"][hex(0x80 + idx * 8)] == (0x404040).to_bytes(8, "little").hex()


def test_misaligned_target_is_declined_with_reason():
    import json
    import pytest
    r = heap.house_of_water_recipe(0x40, target=0x404048)          # 8- but not 16-byte aligned
    assert r["ok"] is False and "aligned" in r["reason"]
    json.dumps(r)
    with pytest.raises(ValueError, match="aligned"):
        heap.forge_tcache_perthread(3, 0x404048)
