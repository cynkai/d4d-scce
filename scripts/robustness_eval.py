#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
캠페인 탐지기 강건성 평가 — 무작위 합성 세계 여러 개에서 정밀도·재현율의 분포를 잰다.

데모 시나리오 하나(정답 캠페인 1개)로는 "100%"가 쉽게 나온다. 여기서는 세계마다
  - 배경 감염: 협력사 13곳에 무작위 스틸러 감염. C2는 캠페인과 같은 풀에서 뽑아
    우연한 (스틸러, C2) 겹침이 생긴다 → 실제 오탐 원인.
  - 진짜 캠페인 1~3개: 협력사 2~4곳, 확산 2~30일, 스틸러·C2·시점 무작위.
  - 함정(캠페인 아님): ① 같은 스틸러·C2지만 60~150일에 걸쳐 흩어진 감염,
    ② 한 협력사 안에서만 여러 대가 감염된 경우.
를 만들고, 탐지기는 원시 로그만, 채점은 정답셋(구성 로그 Jaccard ≥ 0.5)으로 한다.

    python3 scripts/robustness_eval.py --worlds 200 --out docs/EVALUATION.md
"""

import argparse
import json
import os
import random
import statistics
import sys
from datetime import date, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import generate_synthetic as gen  # noqa: E402
from correlation import detect_campaigns  # noqa: E402
from evaluation import match_campaigns  # noqa: E402

TODAY = gen.TODAY
NOISE = {"low": 40, "high": 120}  # 배경 감염 로그 수
THRESHOLDS = [0.0, 0.85, 0.9, 0.95]  # 탐지기 confidence 하한별 정밀도·재현율


def _day(age):
    return (TODAY - timedelta(days=age)).isoformat()


def build_world(seed, n_background):
    """무작위 세계 하나: (vendors, raw stealer logs, truth campaigns)."""
    rng = random.Random(seed)
    vendors = gen.build_vendors()
    corp = [(v["vendor_id"], v["domains"][0]) for v in vendors]
    logs, truth = [], []

    def add(family, vid, domain, age, c2, campaign=None):
        log = gen._machine(rng, family, vid, domain, _day(age), c2, campaign, high_prob=0.3)
        log["log_id"] = f"W{len(logs):05d}"
        logs.append(log)
        return log["log_id"]

    # 배경: 회사/개인 감염이 섞인 무작위 로그
    for _ in range(n_background):
        if rng.random() < 0.55:
            vid, domain = rng.choice(corp)
        else:
            vid, domain = None, rng.choice(["example.com", "example.net", "example.org"])
        add(rng.choice(gen.STEALER_FAMILIES), vid, domain, rng.randint(1, 400), rng.choice(gen.C2_POOL))

    # 진짜 캠페인
    for k in range(rng.randint(1, 3)):
        family, c2 = rng.choice(gen.STEALER_FAMILIES), rng.choice(gen.C2_POOL)
        members = rng.sample(corp, rng.randint(2, 4))
        start, spread = rng.randint(5, 300), rng.randint(2, 30)
        ids = [add(family, vid, domain, max(start - rng.randint(0, spread), 0), c2, f"T{k}")
               for vid, domain in members]
        truth.append({"campaign_id": f"TRUTH-{k}", "log_ids": ids})

    # 함정 ①: 같은 스틸러·C2, 두 협력사, 60~150일 간격 → 캠페인 아님
    for _ in range(rng.randint(0, 2)):
        family, c2 = rng.choice(gen.STEALER_FAMILIES), rng.choice(gen.C2_POOL)
        (v1, d1), (v2, d2) = rng.sample(corp, 2)
        first = rng.randint(160, 380)
        add(family, v1, d1, first, c2)
        add(family, v2, d2, first - rng.randint(60, 150), c2)

    # 함정 ②: 한 협력사 안의 다중 감염 → 캠페인 아님(공급망 확산 아님)
    for _ in range(rng.randint(0, 2)):
        family, c2 = rng.choice(gen.STEALER_FAMILIES), rng.choice(gen.C2_POOL)
        vid, domain = rng.choice(corp)
        start = rng.randint(5, 300)
        for _ in range(rng.randint(2, 4)):
            add(family, vid, domain, start - rng.randint(0, 10), c2)

    raw = [{k: v for k, v in log.items() if not k.startswith("_")} for log in logs]
    return vendors, raw, truth


def lead_days(campaign_logs):
    """두 번째 협력사가 감염된 날(탐지 요건 충족)부터 마지막 협력사 감염일까지의 여유."""
    first_by_vendor = {}
    for log in sorted(campaign_logs, key=lambda l: l["infection_date"]):
        first_by_vendor.setdefault(log["vendor_id"], log["infection_date"])
    days = sorted(first_by_vendor.values())
    if len(days) < 2:
        return None
    return (date.fromisoformat(days[-1]) - date.fromisoformat(days[1])).days


def run(worlds, n_background, split_by_time=True):
    per_world, tp = [], {"det": 0, "truth": 0, "tp": 0}
    leads = []
    by_threshold = {t: {"det": 0, "tp": 0, "truth": 0} for t in THRESHOLDS}
    for seed in range(1, worlds + 1):
        vendors, raw, truth = build_world(seed, n_background)
        detected = detect_campaigns(raw, vendors, split_by_time=split_by_time)
        for t in THRESHOLDS:
            mt = match_campaigns([d for d in detected if d["confidence"] >= t], truth)
            by_threshold[t]["det"] += mt["detected"]
            by_threshold[t]["tp"] += mt["true_positive"]
            by_threshold[t]["truth"] += mt["ground_truth"]
        m = match_campaigns(detected, truth)
        per_world.append(m)
        tp["det"] += m["detected"]; tp["truth"] += m["ground_truth"]; tp["tp"] += m["true_positive"]
        by_id = {l["log_id"]: l for l in raw}
        for t in truth:
            if any(x["truth"] == t["campaign_id"] for x in m["matches"]):
                ld = lead_days([by_id[i] for i in t["log_ids"]])
                if ld is not None:
                    leads.append(ld)
    precs = [m["precision"] for m in per_world if m["precision"] is not None]
    recs = [m["recall"] for m in per_world if m["recall"] is not None]
    q = lambda xs, p: sorted(xs)[min(int(p * len(xs)), len(xs) - 1)] if xs else None  # noqa: E731
    return {
        "worlds": worlds, "background_logs": n_background,
        "truth_campaigns": tp["truth"], "detected": tp["det"], "true_positive": tp["tp"],
        "micro_precision": round(tp["tp"] / tp["det"], 3) if tp["det"] else None,
        "micro_recall": round(tp["tp"] / tp["truth"], 3) if tp["truth"] else None,
        "precision_mean": round(statistics.mean(precs), 3), "precision_p10": q(precs, 0.10),
        "recall_mean": round(statistics.mean(recs), 3), "recall_p10": q(recs, 0.10),
        "worlds_perfect": sum(1 for m in per_world if m["precision"] == 1 and m["recall"] == 1),
        "lead_days_median": statistics.median(leads) if leads else None,
        "lead_days_p10": q(leads, 0.10), "lead_days_p90": q(leads, 0.90),
        "lead_days_zero_share": round(sum(1 for x in leads if x == 0) / len(leads), 3) if leads else None,
        "by_confidence": [{"min_confidence": t,
                           "precision": round(c["tp"] / c["det"], 3) if c["det"] else None,
                           "recall": round(c["tp"] / c["truth"], 3) if c["truth"] else None,
                           "detected": c["det"]} for t, c in by_threshold.items()],
    }


def pct(x):
    return "—" if x is None else f"{x * 100:.0f}%"


def render(results, worlds):
    cur, old = results["current"], results["without_time_split"]
    lines = [
        "# 캠페인 탐지 평가 (무작위 합성 세계)",
        "",
        "`python3 scripts/robustness_eval.py` 로 다시 만들 수 있다(결정적: 시드 1~"
        f"{worlds}). 세계 구성과 채점 방식은 스크립트 첫머리에 있다. 요약하면 세계마다 진짜",
        "캠페인 1~3개(협력사 2~4곳, 확산 2~30일)를 심고, 같은 C2 풀을 쓰는 배경 감염과",
        "'흩어진 동일 C2'·'한 협력사 내 다중 감염' 함정을 섞는다. 탐지기는 원시 로그만 보고,",
        "탐지와 정답은 구성 로그 Jaccard ≥ 0.5 로 1:1 짝짓는다.",
        "",
        "## 결과",
        "",
        "| 배경 잡음 | 탐지기 | 정밀도 | 재현율 | 완벽한 세계 |",
        "|---|---|---|---|---|",
    ]
    for noise in NOISE:
        for label, r in (("시간 분할 전", old[noise]), ("현재", cur[noise])):
            lines.append(f"| {noise} ({r['background_logs']}건) | {label} | {pct(r['micro_precision'])} | "
                         f"{pct(r['micro_recall'])} | {r['worlds_perfect']}/{worlds} |")
    lines += [
        "",
        "정밀도·재현율은 전체 세계를 합친 값(micro). '완벽한 세계'는 정밀도·재현율이 모두 100%인 세계 수.",
        "",
        "시간 분할 전 탐지기는 같은 (스틸러, C2) 로그를 기간과 무관하게 한 묶음으로 합친 뒤, 묶음 전체가",
        "42일을 넘으면 버렸다. 공용 C2에 무관한 감염이 섞이면 진짜 캠페인까지 통째로 놓쳤다. 현재 탐지기는",
        "감염일 간격이 14일을 넘는 곳에서 묶음을 나눈다.",
        "",
        "## 신뢰도 기준별 (현재 탐지기)",
        "",
        "| 배경 잡음 | 최소 confidence | 탐지 수 | 정밀도 | 재현율 |",
        "|---|---|---|---|---|",
    ]
    for noise in NOISE:
        for row in cur[noise]["by_confidence"]:
            if row["min_confidence"] in (0.0, 0.9):
                lines.append(f"| {noise} | {row['min_confidence']:.2f} | {row['detected']} | "
                             f"{pct(row['precision'])} | {pct(row['recall'])} |")
    lines += [
        "",
        "confidence ≥ 0.90 은 사실상 '협력사 3곳 이상이 같은 스틸러·C2로 2주 안에 감염'이다. 2곳짜리 묶음은",
        "우연한 공용 C2 겹침과 구별할 근거가 없어서, 모두 경고하면 잡음이 많을 때 정밀도가 크게 떨어진다.",
        "",
        "## 조기경보 리드타임 (맞힌 캠페인, 현재 탐지기)",
        "",
        "두 번째 협력사가 감염된 날(탐지 요건 충족)부터 마지막 협력사 감염일까지의 일수.",
        "",
        "| 배경 잡음 | 중앙값 | 10% | 90% | 0일 비율 |",
        "|---|---|---|---|---|",
    ]
    for noise in NOISE:
        r = cur[noise]
        lines.append(f"| {noise} | {r['lead_days_median']}일 | {r['lead_days_p10']}일 | {r['lead_days_p90']}일 | "
                     f"{pct(r['lead_days_zero_share'])} |")
    lines += [
        "",
        "데모 시나리오의 '8일 전 조기경보'는 협력사 3곳이 11일에 걸쳐 감염된 좋은 경우다. 무작위 캠페인의",
        "중앙값은 이틀이고, 협력사 2곳짜리 캠페인은 탐지 시점이 곧 마지막 감염이라 여유가 0일이다.",
        "",
        "## 한계",
        "",
        "- 세계도, 정답도 이 저장소의 생성기가 만든다. 실제 다크웹·스틸러 피드의 분포와 다를 수 있다.",
        "- 활성 침해 판정은 여기서 평가하지 않는다. 합성 정답이 탐지 규칙과 같은 기준으로 정해지므로,",
        "  합성 데이터로는 규칙 구현 확인 이상을 말할 수 없다.",
        "- 시간 분할은 이 평가에서 약점이 드러난 뒤 추가했다. 같은 벤치마크로 고치고 잰 개선 폭이라",
        "  낙관적일 수 있다. 다만 분할 간격(14일)과 confidence 식은 원래 코드의 값을 그대로 썼고,",
        "  이 평가에 맞춰 조정하지 않았다.",
    ]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--worlds", type=int, default=200)
    ap.add_argument("--out", default="docs/EVALUATION.md")
    ap.add_argument("--json", default="docs/evaluation.json")
    args = ap.parse_args()

    results = {
        "current": {name: run(args.worlds, n) for name, n in NOISE.items()},
        "without_time_split": {name: run(args.worlds, n, split_by_time=False) for name, n in NOISE.items()},
    }
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render(results, args.worlds))
    for variant, by_noise in results.items():
        for noise, r in by_noise.items():
            print(f"{variant:20} {noise:4} precision {pct(r['micro_precision']):>4} recall {pct(r['micro_recall']):>4}")


if __name__ == "__main__":
    main()
