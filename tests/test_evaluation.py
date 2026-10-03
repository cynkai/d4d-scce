from evaluation import confusion, match_campaigns


def det(cid, ids):
    return {"campaign_id": cid, "log_ids": ids}


def test_campaigns_match_on_member_overlap_not_names():
    truth = [{"campaign_id": "T1", "log_ids": ["a", "b", "c"]}]
    m = match_campaigns([det("ANY-NAME", ["a", "b", "c", "x"])], truth)  # Jaccard 0.75
    assert (m["true_positive"], m["precision"], m["recall"]) == (1, 1.0, 1.0)


def test_low_overlap_is_not_a_match():
    truth = [{"campaign_id": "T1", "log_ids": ["a", "b", "c", "d"]}]
    m = match_campaigns([det("D", ["a", "x", "y", "z"])], truth)  # Jaccard 1/7
    assert (m["true_positive"], m["false_positive"], m["recall"]) == (0, 1, 0.0)


def test_one_truth_matches_at_most_one_detection():
    truth = [{"campaign_id": "T1", "log_ids": ["a", "b"]}]
    m = match_campaigns([det("D1", ["a", "b"]), det("D2", ["a", "b"])], truth)
    assert (m["true_positive"], m["precision"]) == (1, 0.5)


def test_empty_cases_report_none_not_perfect_scores():
    m = match_campaigns([], [])
    assert m["precision"] is None and m["recall"] is None
    c = confusion([(False, False)])
    assert c["precision"] is None and c["recall"] is None
