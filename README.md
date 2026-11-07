# SubMiner

SubMiner is a local web-based subdomain reconnaissance interface. It combines passive
subdomain sources, ProjectDiscovery Subfinder, Wayback Machine URL history, and
ProjectDiscovery httpx probing in a real-time dashboard.

> **Authorization:** Use SubMiner only against domains you own or are explicitly authorized
> to assess. Passive sources and HTTP probing may disclose the target domain to third-party
> services and generate traffic to discovered hosts.

## Features

- Passive discovery through HackerTarget, urlscan.io, crt.sh, AnubisDB, CertSpotter,
  RapidDNS, and DNSRepo.
- Subdomain enumeration with ProjectDiscovery Subfinder.
- Historical hostname discovery from the Internet Archive CDX API.
- Central validation to retain only hostnames beneath the requested domain.
- Live HTTP probing with ProjectDiscovery httpx.
- Server-sent events (SSE) for live logs, source status, subdomains, and HTTP results.
- Export discovered subdomains and live hosts as TXT or JSON.
- Scan-specific cancellation and subprocess cleanup.
- Results saved to `~/targets/<domain>/subdomains.txt` by default.

## Requirements

- Linux or macOS
- Python 3.11+
- Go (required to install ProjectDiscovery tools)
- ProjectDiscovery [Subfinder](https://github.com/projectdiscovery/subfinder)
- ProjectDiscovery [httpx](https://github.com/projectdiscovery/httpx)

The installer installs Python dependencies in a local virtual environment and installs
Subfinder/httpx with `go install`. It does **not** replace or remove an existing Go
installation, modify shell startup files, or run a system package-manager upgrade.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/subminer.git
cd subminer
chmod +x install.sh subminer.sh
./install.sh
```

The installer uses the latest upstream versions of Subfinder and httpx if the binaries are
not already present in your Go binary directory. For repeatable deployments, install
specific tool versions manually and keep those versions recorded in your environment.

If Go is not installed, install it from [go.dev/dl](https://go.dev/dl/) and rerun the
installer. On Debian/Ubuntu, if virtual-environment creation fails, install the matching
`python3-venv` package.

## Running

```bash
./subminer.sh
```

Open:

```text
http://127.0.0.1:8000
```

Choose a fully qualified domain (for example, `example.com`) and start the scan.

Change the port:

```bash
SUBMINER_PORT=9090 ./subminer.sh
```

By default, the server binds to `127.0.0.1`. This is intentional: the scan and stop endpoints
do not implement user authentication. Do not bind to `0.0.0.0` or expose the service to a
network you do not fully trust.

## Configuration

Configuration is supplied through environment variables. The application does not
automatically load `.env` files. You can copy the example and export values in your shell:

```bash
cp .env.example .env
set -a
source .env
set +a
./subminer.sh
```

| Variable | Default | Purpose |
|---|---|---|
| `SUBMINER_HOST` | `127.0.0.1` | Uvicorn bind address |
| `SUBMINER_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1` | Accepted HTTP Host names; add your hostname explicitly if changing the bind address |
| `SUBMINER_PORT` | `8000` | Uvicorn port |
| `SUBMINER_TARGETS_DIR` | `~/targets` | Output directory |
| `SUBMINER_SUBFINDER_BIN` | `subfinder` | Subfinder executable or path |
| `SUBMINER_HTTPX_BIN` | `~/go/bin/httpx` | ProjectDiscovery httpx executable |
| `SUBMINER_HTTPX_TIMEOUT` | `3600` | Maximum httpx phase duration, seconds |
| `SUBMINER_SUBFINDER_TIMEOUT` | `900` | Maximum Subfinder phase duration, seconds |
| `SUBMINER_MAX_SCANS` | `2` | Maximum simultaneous scans (1–4) |
| `SUBMINER_LOG_LEVEL` | `INFO` | Python log level |

If your Go `GOPATH` is not `~/go`, the launcher detects it for the default httpx path.
You can override either tool path with an absolute executable path.

## Output

For `example.com`, the default output is:

```text
~/targets/
└── example.com/
    └── subdomains.txt
```

Each scan replaces the file atomically with the current sorted discovery results. Export
buttons in the interface let you save subdomains and live HTTP results as TXT or JSON.

## Data sources and network behavior

SubMiner sends lookup requests to the configured passive sources listed in the interface.
The requested domain is therefore disclosed to those providers. The live-probing phase
uses ProjectDiscovery httpx against the discovered in-scope hostnames and can generate
requests to those hosts. Provider availability, rate limits, response formats, and terms
of service may change independently of SubMiner.

SubMiner does not use API keys by default. Some sources may rate-limit or restrict anonymous
requests, so a source can fail without the entire scan failing.

## Security notes

- The web server binds to loopback by default.
- The API validates domains and requires a per-scan identifier.
- Scan cancellation is scoped to the corresponding scan; the application no longer uses
  broad `pkill` commands.
- Subfinder and httpx are launched with argument arrays, not shell command strings.
- Remote source results and HTTP titles are inserted into the page as text, not HTML.
- Response bodies from passive sources are capped to reduce memory-exhaustion risk.
- Scan result paths are constrained beneath the configured targets directory.
- The app does not provide login, multi-user isolation, TLS termination, or production
  deployment hardening. Keep it local unless you add those controls.

## Troubleshooting

**Subfinder is not found**

Check that it is installed and available on `PATH`, or set `SUBMINER_SUBFINDER_BIN` to its
absolute path.

**httpx is not found**

Set `SUBMINER_HTTPX_BIN` to the ProjectDiscovery httpx executable. Be careful not to point
to the unrelated Python package named `httpx`.

**A source reports an error**

Passive providers may be unavailable, rate-limited, or change their response format. Other
sources continue independently. Review the terminal output and server logs.

**Port 8000 is already in use**

```bash
SUBMINER_PORT=9090 ./subminer.sh
```

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8000
```

Run the lightweight unit tests:

```bash
python -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).
