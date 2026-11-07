#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${APP_DIR}/.venv"
PYTHON_MIN_MINOR=11

info() { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -ne 0 ]] || die "Do not run this installer as root."
case "$(uname -s)" in
    Linux|Darwin) ;;
    *) die "Supported platforms: Linux and macOS." ;;
esac

# Do not replace system Go installations or perform implicit system upgrades.
GO_BIN="$(command -v go || true)"
[[ -n "$GO_BIN" ]] || die "Go is required. Install Go from https://go.dev/dl/ and rerun this installer."
PYTHON_BIN=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        version="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        major="${version%%.*}"
        minor="${version#*.}"
        if [[ "$major" -eq 3 && "$minor" -ge "$PYTHON_MIN_MINOR" ]]; then
            PYTHON_BIN="$(command -v "$candidate")"
            break
        fi
    fi
done
[[ -n "$PYTHON_BIN" ]] || die "Python 3.11 or newer is required. Install it and rerun this installer."

command -v git >/dev/null 2>&1 || warn "git is not installed (not required to run SubMiner)."
command -v curl >/dev/null 2>&1 || die "curl is required."

GO_VERSION="$("$GO_BIN" version | awk '{print $3}' | sed 's/^go//')"
info "Using Go ${GO_VERSION} and $("$PYTHON_BIN" --version)"

cd "$APP_DIR"
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    info "Creating Python virtual environment..."
    "$PYTHON_BIN" -m venv "$VENV_DIR" || die "Could not create venv. On Debian/Ubuntu, install python3-venv."
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

GOPATH_BIN="$("$GO_BIN" env GOPATH)/bin"
mkdir -p "$GOPATH_BIN"
export PATH="${GOPATH_BIN}:$PATH"

install_go_tool() {
    local name="$1" module="$2"
    if [[ -x "${GOPATH_BIN}/${name}" ]]; then
        ok "${name} already installed at ${GOPATH_BIN}/${name}"
    else
        info "Installing ${name} (latest upstream release)..."
        GOBIN="$GOPATH_BIN" "$GO_BIN" install "$module" || die "Could not install ${name}."
    fi
}

install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest

[[ -x "${GOPATH_BIN}/subfinder" ]] || die "Subfinder binary missing after installation."
[[ -x "${GOPATH_BIN}/httpx" ]] || die "ProjectDiscovery httpx binary missing after installation."

chmod +x "${APP_DIR}/subminer.sh"
ok "Dependencies installed."
printf '\nStart SubMiner with:\n  %s\n\n' "${APP_DIR}/subminer.sh"
printf 'By default it binds to 127.0.0.1. To change the port:\n  SUBMINER_PORT=9090 %s\n' "${APP_DIR}/subminer.sh"
printf '\nGo tools installed in: %s\n' "$GOPATH_BIN"
