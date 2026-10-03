from correlation import detect_campaigns

VENDORS = [{"vendor_id": f"V{i}", "name": f"vendor{i}"} for i in range(1, 5)]


def log(lid, vid, day, c2="192.0.2.1", family="RedLine"):
    return {"log_id": lid, "vendor_id": vid, "infection_date": day, "c2_host": c2,
            "stealer_family": family, "machine_id": lid}


def test_two_vendors_close_in_time_form_a_campaign():
    c = detect_campaigns([log("a", "V1", "2026-06-20"), log("b", "V2", "2026-06-25")], VENDORS)
    assert len(c) == 1 and c[0]["affected_count"] == 2 and set(c[0]["log_ids"]) == {"a", "b"}


def test_same_c2_months_apart_is_not_a_campaign():
    c = detect_campaigns([log("a", "V1", "2026-01-10"), log("b", "V2", "2026-05-01")], VENDORS)
    assert c == []


def test_a_campaign_is_found_inside_a_long_lived_shared_c2():
    # Unrelated infections on the same C2 months earlier must not hide the burst.
    logs = [log("old1", "V3", "2025-09-01"), log("old2", "V4", "2025-12-15"),
            log("a", "V1", "2026-06-20"), log("b", "V2", "2026-06-24")]
    c = detect_campaigns(logs, VENDORS)
    assert [set(x["log_ids"]) for x in c] == [{"a", "b"}]
    assert detect_campaigns(logs, VENDORS, split_by_time=False) == []  # old behaviour


def test_one_vendor_with_many_machines_is_not_a_supply_chain_campaign():
    c = detect_campaigns([log(str(i), "V1", "2026-06-2" + str(i)) for i in range(3)], VENDORS)
    assert c == []
