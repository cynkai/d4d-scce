"""The engine never sees ground-truth labels, and its output cannot depend on them."""
import copy

import generate_synthetic as gen
from correlation import detect_campaigns

LABEL_KEYS = {"campaign_id", "gt_active", "active_compromise", "_campaign", "_gt_active"}


def world():
    vendors, _, stealer = gen.build_world(seed=42)
    raw, truth = gen.split_truth(stealer)
    return vendors, raw, truth


def test_raw_logs_carry_no_labels():
    _, raw, _ = world()
    assert all(not (LABEL_KEYS & log.keys()) for log in raw)


def test_campaign_ids_come_from_observations_not_labels():
    vendors, raw, _ = world()
    before = detect_campaigns(raw, vendors)
    leaked = copy.deepcopy(raw)
    for log in leaked:
        log["campaign_id"] = "LEAKED-LABEL"
    after = detect_campaigns(leaked, vendors)
    assert [c["campaign_id"] for c in after] == [c["campaign_id"] for c in before]
    assert all(not c["campaign_id"].startswith("LEAKED") for c in after)


def test_log_ids_are_unique():
    _, raw, _ = world()
    ids = [log["log_id"] for log in raw]
    assert len(ids) == len(set(ids))
