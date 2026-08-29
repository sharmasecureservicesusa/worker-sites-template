#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

if [[ ! -f .env ]]; then
  echo "Copy .env.example to .env and set production secrets first." >&2
  exit 1
fi

docker compose -f docker-compose.prod.yml up -d --build
echo "Workers Club is starting on port 8000."
echo "Set PUBLIC_BASE_URL in .env to your public HTTPS origin before going live."
