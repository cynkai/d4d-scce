#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
정답셋 기준 평가 — 탐지 결과를 생성기의 정답셋(ground_truth.json)과 대조한다.

분석 엔진은 정답 라벨을 보지 않는다. 평가는 여기서만, 정답셋을 따로 읽어서 한다.
  - 캠페인: 탐지 묶음과 정답 캠페인을 '구성 로그'의 Jaccard 유사도로 짝짓는다
    (이름 문자열 일치가 아니라 내용 일치). 한 정답에는 한 탐지만 짝지어진다.
  - 활성 침해: 로그 단위로 우리 규칙과 나이브 규칙을 각각 정답과 대조한다.
"""

from scoring import detect_active_compromise

MATCH_JACCARD = 0.5


def confusion(pairs):
    """(예측, 정답) 쌍 리스트 → 혼동행렬 + precision/recall/f1."""
    tp = fp = fn = tn = 0
    for pred, truth in pairs:
        if pred and truth: tp += 1
        elif pred and not truth: fp += 1
        elif not pred and truth: fn += 1
        else: tn += 1
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * prec * rec / (prec + rec)) if prec and rec else 0.0
    rnd = lambda x: None if x is None else round(x, 3)  # noqa: E731
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": rnd(prec), "recall": rnd(rec), "f1": round(f1, 3)}


def _jaccard(a, b):
    a, b = set(a), set(b)
    return len(a & b) / len(a | b) if (a | b) else 0.0


def match_campaigns(detected, truth_campaigns, threshold=MATCH_JACCARD):
    """탐지 캠페인 ↔ 정답 캠페인 1:1 매칭(유사도 높은 쌍부터 탐욕적으로)."""
    pairs = sorted(((_jaccard(d.get("log_ids", []), t["log_ids"]), i, j)
                    for i, d in enumerate(detected) for j, t in enumerate(truth_campaigns)),
                   reverse=True)
    used_d, used_t, matches = set(), set(), []
    for sim, i, j in pairs:
        if sim < threshold or i in used_d or j in used_t:
            continue
        used_d.add(i); used_t.add(j)
        matches.append({"detected": detected[i]["campaign_id"],
                        "truth": truth_campaigns[j]["campaign_id"], "jaccard": round(sim, 2)})
    n_det, n_truth = len(detected), len(truth_campaigns)
    return {
        "ground_truth": n_truth,
        "detected": n_det,
        "true_positive": len(matches),
        "false_positive": n_det - len(matches),
        "precision": round(len(matches) / n_det, 3) if n_det else None,
        "recall": round(len(matches) / n_truth, 3) if n_truth else None,
        "matches": matches,
        "unmatched_detected": [d["campaign_id"] for k, d in enumerate(detected) if k not in used_d],
    }


def evaluate_active(stealers, active_log_ids):
    """활성 침해 판정: 우리 규칙(최근 30일 + HIGH) vs 나이브(회사 감염이면 활성)."""
    truth = set(active_log_ids)
    ours, naive, decoys = [], [], 0
    for log in stealers:
        gt = log.get("log_id") in truth
        if log.get("is_corporate") and not gt:
            decoys += 1  # 나이브가 낚일 수 있는 경우(회사 감염이나 실제로는 비활성)
        ours.append((detect_active_compromise(log)["is_active"], gt))
        naive.append((bool(log.get("is_corporate")), gt))
    return confusion(ours), confusion(naive), decoys
