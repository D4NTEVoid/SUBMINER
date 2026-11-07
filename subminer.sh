#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -x "${SCRIPT_DIR}/.venv/bin/uvicorn" ]] || {
    echo "SubMiner is not installed. Run ./install.sh first." >&2
    exit 1
}
GO_BIN="$(command -v go || true)"
if [[ -n "$GO_BIN" ]]; then
    GOPATH_BIN="$("$GO_BIN" env GOPATH)/bin"
    export PATH="${GOPATH_BIN}:$PATH"
    export SUBMINER_HTTPX_BIN="${SUBMINER_HTTPX_BIN:-${GOPATH_BIN}/httpx}"
fi
HOST="${SUBMINER_HOST:-127.0.0.1}"
PORT="${SUBMINER_PORT:-8000}"
cd "$SCRIPT_DIR"
echo "Starting SubMiner at http://${HOST}:${PORT}"
exec "${SCRIPT_DIR}/.venv/bin/uvicorn" app:app --host "$HOST" --port "$PORT"
