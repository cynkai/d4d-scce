from matcher import _resolve_exact, _typo_match, build_domain_index

VENDORS = [{"vendor_id": "V1", "name": "taesung", "domains": ["taesung-pcb.example"]}]


def test_subdomains_resolve_to_the_vendor():
    idx = build_domain_index(VENDORS)
    assert _resolve_exact("vpn.taesung-pcb.example", idx)[0]["vendor_id"] == "V1"
    assert _resolve_exact("taesung-pcb.example", idx)[1] == "exact"
    assert _resolve_exact("other.example", idx) == (None, None)


def test_typosquats_by_one_edit_or_adjacent_swap():
    assert _typo_match("taesung-pbc", "taesung-pcb")      # adjacent swap
    assert _typo_match("sejong-tactcon", "sejong-tactcom")  # substitution
    assert _typo_match("taesungpcb", "taesung-pcb")       # deletion
    assert not _typo_match("taesung-pcb", "taesung-pcb")  # identical is not a look-alike
    assert not _typo_match("acme", "taesung-pcb")
