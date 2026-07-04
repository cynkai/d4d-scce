#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FastAPI 백엔드 — report API + 정적 대시보드 서빙.

엔드포인트:
  GET /                     대시보드 (web/index.html)
  GET /api/report           전체 리포트 JSON
  GET /api/vendor/{vid}     업체 드릴다운
  GET /api/advisory/{vid}   통보문
  POST /api/refresh         파이프라인 재실행(데이터 갱신)

실행:
  uvicorn api.server:app --reload   (프로젝트 루트에서)
  또는  ./run.sh
"""

import json
import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "report.json")
WEB = os.path.join(ROOT, "web")

sys.path.insert(0, ROOT)

app = FastAPI(title="SCCE — 방산 공급망 자격증명 노출 조기경보")


def _load():
    if not os.path.exists(DATA):
        raise HTTPException(503, "report.json 없음 — python pipeline.py 먼저 실행")
    with open(DATA, encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/report")
def report():
    return _load()


@app.get("/api/vendor/{vid}")
def vendor(vid: str):
    r = _load()
    v = next((x for x in r["ranked_vendors"] if x["vendor_id"] == vid), None)
    if not v:
        raise HTTPException(404, f"vendor {vid} 없음")
    v = dict(v)
    v["advisory"] = next((a for a in r.get("advisories", []) if a["vendor_id"] == vid), None)
    return v


@app.get("/api/advisory/{vid}")
def advisory(vid: str):
    r = _load()
    a = next((x for x in r.get("advisories", []) if x["vendor_id"] == vid), None)
    if not a:
        raise HTTPException(404, "해당 업체 통보문 없음(활성 침해 아님)")
    return a


@app.post("/api/refresh")
def refresh():
    import pipeline
    pipeline.run("mock")
    return JSONResponse({"status": "ok", "message": "파이프라인 재실행 완료"})


@app.get("/")
def index():
    return FileResponse(os.path.join(WEB, "index.html"))


# 정적 파일 (styles.css, app.js, report_data.js)
app.mount("/", StaticFiles(directory=WEB), name="web")
