#!/bin/sh

set -e

echo "Starting SentinelLab on 127.0.0.1:8000..."

cd /app/sentinel-lab

uvicorn app:app \
  --host 127.0.0.1 \
  --port 8000 &

LAB_PID=$!

echo "SentinelLab PID: $LAB_PID"

sleep 2

echo "Starting AuthGraph Sentinel API..."

cd /app/backend

uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-10000}" &

API_PID=$!

echo "AuthGraph Sentinel API PID: $API_PID"

trap 'kill $LAB_PID $API_PID 2>/dev/null || true' INT TERM

wait $API_PID
