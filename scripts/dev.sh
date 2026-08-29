#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/bin:/usr/local/bin:${PATH}"
DOLT_DIR="${ROOT}/data/members"
mkdir -p "${DOLT_DIR}"

if [[ ! -d "${DOLT_DIR}/.dolt" ]]; then
  (
    cd "${DOLT_DIR}"
    dolt init
    dolt config --local --add user.name "Workers Club"
    dolt config --local --add user.email "club@localhost"
  )
fi

if ! python3 - <<'PY'
import socket
sock = socket.socket()
sock.settimeout(0.4)
try:
    sock.connect(("127.0.0.1", 3306))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
then
  (cd "${DOLT_DIR}" && dolt sql-server --host 127.0.0.1 --port 3306) &
  echo $! > "${ROOT}/data/dolt.pid"
  for _ in $(seq 1 60); do
    if python3 - <<'PY'
import socket
sock = socket.socket()
sock.settimeout(0.4)
try:
    sock.connect(("127.0.0.1", 3306))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
    then
      break
    fi
    sleep 0.25
  done
fi

cd "${ROOT}/backend"
export DATABASE_URL="${DATABASE_URL:-mysql+pymysql://root@127.0.0.1:3306/members}"
export PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://127.0.0.1:8000}"
exec "${ROOT}/.venv/bin/uvicorn" app.main:app --host 0.0.0.0 --port 8000 --reload
