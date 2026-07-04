#!/usr/bin/env bash
# SCCE 원커맨드 실행: 데이터 생성 → 파이프라인 → 대시보드 서버
set -e
cd "$(dirname "$0")"
python3 scripts/generate_synthetic.py
python3 pipeline.py
python3 scripts/verify_demo.py
echo ""
echo "대시보드: http://127.0.0.1:8000  (Ctrl+C 로 종료)"
python3 -m uvicorn api.server:app --host 127.0.0.1 --port 8000
