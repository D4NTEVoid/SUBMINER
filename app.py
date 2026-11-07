from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# SubMiner is intended for local, authorized reconnaissance.
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
ICON_DIR = TEMPLATES_DIR / "icon"
TARGETS_DIR = Path(os.environ.get("SUBMINER_TARGETS_DIR", str(Path.home() / "targets"))).expanduser()
SUBFINDER_BIN = os.environ.get("SUBMINER_SUBFINDER_BIN", "subfinder")
HTTPX_BIN = os.environ.get(
    "SUBMINER_HTTPX_BIN", str(Path.home() / "go" / "bin" / "httpx")
)
HTTPX_TIMEOUT = max(30, int(os.environ.get("SUBMINER_HTTPX_TIMEOUT", "3600")))
SOURCE_TIMEOUT = 25.0
SUBFINDER_TIMEOUT = max(60, int(os.environ.get("SUBMINER_SUBFINDER_TIMEOUT", "900")))
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_CONCURRENT_SCANS = max(1, min(4, int(os.environ.get("SUBMINER_MAX_SCANS", "2"))))
ALLOWED_HOSTS = {
    item.strip().lower()
    for item in os.environ.get("SUBMINER_ALLOWED_HOSTS", "localhost,127.0.0.1,::1").split(",")
    if item.strip()
}

COLORS = {
    "hackertarget": "\033[92m", "urlscan": "\033[95m", "crtsh": "\033[93m",
    "jldc": "\033[91m", "certspotter": "\033[96m", "rapiddns": "\033[94m",
    "dnsrepo": "\033[33m", "subfinder": "\033[97m", "wayback": "\033[35m",
    "httpx": "\033[38;5;208m", "recon": "\033[38;5;117m",
}
RESET = "\033[0m"


class ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        for source, color in COLORS.items():
            if f"[{source}]" in message:
                return f"{color}{message}{RESET}"
        return message


logger = logging.getLogger("subminer")
logger.setLevel(os.environ.get("SUBMINER_LOG_LEVEL", "INFO").upper())
logger.propagate = False
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)

app = FastAPI(title="SubMiner", docs_url=None, redoc_url=None)
if ICON_DIR.is_dir():
    app.mount("/icon", StaticFiles(directory=str(ICON_DIR)), name="icon")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@app.middleware("http")
async def validate_host_header(request: Request, call_next):
    host = (request.url.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse("Host not allowed. Configure SUBMINER_ALLOWED_HOSTS explicitly.", status_code=400)
    return await call_next(request)


LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SCAN_ID_RE = re.compile(r"^[a-f0-9-]{36}$")
SOURCES = [
    "hackertarget", "urlscan", "crtsh", "jldc", "certspotter",
    "rapiddns", "dnsrepo", "subfinder", "wayback",
]


@dataclass
class ScanContext:
    scan_id: str
    domain: str
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)
    processes: set[asyncio.subprocess.Process] = field(default_factory=set)
    process_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


active_scans: dict[str, ScanContext] = {}


def normalize_domain(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or any(c in value for c in "/:@\\"):
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        return None
    return value


def normalize_hostname(value: object, domain: str) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(candidate) > 253 or candidate == domain or not candidate.endswith("." + domain):
        return None
    labels = candidate.split(".")
    if any(not LABEL_RE.fullmatch(label) for label in labels):
        return None
    return candidate


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\].*?(?:\x07|\x1b\\))", "", value)


async def emit(queue: asyncio.Queue, event: dict) -> None:
    await queue.put(event)


async def terminate_process(ctx: ScanContext, proc: asyncio.subprocess.Process) -> None:
    try:
        if proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except asyncio.TimeoutError:
                    logger.warning("Could not reap subprocess PID %s promptly", proc.pid)
    finally:
        async with ctx.process_lock:
            ctx.processes.discard(proc)


async def register_process(ctx: ScanContext, proc: asyncio.subprocess.Process) -> None:
    async with ctx.process_lock:
        ctx.processes.add(proc)


async def cleanup_processes(ctx: ScanContext) -> None:
    async with ctx.process_lock:
        processes = list(ctx.processes)
    await asyncio.gather(*(terminate_process(ctx, proc) for proc in processes), return_exceptions=True)


async def fetch_text(client: httpx.AsyncClient, url: str, params: dict | None = None) -> str:
    async with client.stream("GET", url, params=params) as response:
        response.raise_for_status()
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ValueError("Response exceeded configured size limit")
            chunks.append(chunk)
        return b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")


def parse_hackertarget(text: str) -> list[str]:
    if "API count exceeded" in text or "error" in text.lower():
        return []
    return [line.split(",", 1)[0].strip() for line in text.splitlines() if "," in line]


def parse_urlscan(text: str) -> list[str]:
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    return [
        result.get("page", {}).get("domain", "")
        for result in data.get("results", [])
        if isinstance(result, dict) and isinstance(result.get("page"), dict)
    ]


def parse_crtsh(text: str) -> list[str]:
    data = json.loads(text)
    if not isinstance(data, list):
        return []
    names = []
    for entry in data:
        if isinstance(entry, dict):
            names.extend(str(entry.get(key, "")).splitlines() for key in ("common_name", "name_value"))
    return [name for group in names for name in group]


def parse_jldc(text: str) -> list[str]:
    data = json.loads(text)
    return [str(item) for item in data] if isinstance(data, list) else []


def parse_certspotter(text: str) -> list[str]:
    data = json.loads(text)
    if not isinstance(data, list):
        return []
    return [
        str(name)
        for entry in data if isinstance(entry, dict)
        for name in (entry.get("dns_names") or [])
    ]


def parse_rapiddns(text: str) -> list[str]:
    return re.findall(r"<td>\s*([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})\s*</td>", text, re.I)


def parse_dnsrepo(text: str) -> list[str]:
    return re.findall(r"(?<![a-zA-Z0-9_-])([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})(?![a-zA-Z0-9_-])", text, re.I)


async def source_worker(
    name: str, url: str, parser: Callable[[str], list[str]], domain: str,
    queue: asyncio.Queue, ctx: ScanContext, timeout: float = SOURCE_TIMEOUT,
    params: dict | None = None,
) -> list[str]:
    await emit(queue, {"type": "source_status", "source": name, "state": "running"})
    await emit(queue, {"type": "log", "msg": f"[{name}] Fetching source"})
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout), follow_redirects=True, max_redirects=5,
            headers={"User-Agent": "SubMiner/1.0 (security-research-tool)"},
        ) as client:
            for attempt in range(1, 3):
                if ctx.stop_event.is_set():
                    return []
                try:
                    body = await fetch_text(client, url, params)
                    break
                except (httpx.HTTPError, ValueError) as exc:
                    if attempt == 2:
                        raise
                    await emit(queue, {"type": "log", "msg": f"[{name}] Retry after {type(exc).__name__}", "level": "warn"})
                    await asyncio.sleep(attempt)
            parsed = parser(body)
            found = sorted({host for item in parsed if (host := normalize_hostname(item, domain))})
            for host in found:
                await emit(queue, {"type": "subdomain", "data": host, "source": name})
            await emit(queue, {"type": "log", "msg": f"[{name}] Found {len(found)} valid subdomains"})
            await emit(queue, {"type": "source_status", "source": name, "state": "done", "count": len(found)})
            return found
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("[%s] Source failed: %s: %s", name, type(exc).__name__, str(exc)[:180])
        await emit(queue, {"type": "log", "msg": f"[{name}] Failed: {type(exc).__name__}", "level": "warn"})
        await emit(queue, {"type": "source_status", "source": name, "state": "failed", "count": 0})
        return []


async def run_subfinder(domain: str, queue: asyncio.Queue, ctx: ScanContext) -> list[str]:
    name = "subfinder"
    await emit(queue, {"type": "source_status", "source": name, "state": "running"})
    await emit(queue, {"type": "log", "msg": "[subfinder] Starting enumeration"})
    proc = None
    stderr_task = None
    found: set[str] = set()
    try:
        binary = shutil.which(SUBFINDER_BIN) if os.path.sep not in SUBFINDER_BIN else SUBFINDER_BIN
        if not binary or not os.path.isfile(binary):
            raise FileNotFoundError(f"Subfinder executable not found: {SUBFINDER_BIN}")
        proc = await asyncio.create_subprocess_exec(
            binary, "-d", domain, "-silent", "-timeout", "60",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await register_process(ctx, proc)

        async def drain_stderr():
            assert proc and proc.stderr
            data = await proc.stderr.read()
            if data:
                logger.debug("[subfinder] %s", strip_ansi(data.decode(errors="replace"))[:1000])

        stderr_task = asyncio.create_task(drain_stderr())
        assert proc.stdout
        async with asyncio.timeout(SUBFINDER_TIMEOUT):
            while not ctx.stop_event.is_set():
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
                except asyncio.TimeoutError:
                    if proc.returncode is not None:
                        break
                    continue
                if not line:
                    break
                host = normalize_hostname(line.decode(errors="replace").strip(), domain)
                if host and host not in found:
                    found.add(host)
                    await emit(queue, {"type": "subdomain", "data": host, "source": name})
        if ctx.stop_event.is_set():
            await terminate_process(ctx, proc)
        else:
            await proc.wait()
        await stderr_task
        await emit(queue, {"type": "source_status", "source": name, "state": "done", "count": len(found)})
        await emit(queue, {"type": "log", "msg": f"[subfinder] Found {len(found)} valid subdomains"})
        return sorted(found)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning("[subfinder] Failed: %s", exc)
        await emit(queue, {"type": "log", "msg": f"[subfinder] Failed: {type(exc).__name__}", "level": "error"})
        await emit(queue, {"type": "source_status", "source": name, "state": "failed", "count": 0})
        return []
    finally:
        if proc and proc.returncode is None:
            await terminate_process(ctx, proc)
        elif proc:
            async with ctx.process_lock:
                ctx.processes.discard(proc)
        if stderr_task and not stderr_task.done():
            stderr_task.cancel()
            await asyncio.gather(stderr_task, return_exceptions=True)


async def run_wayback(domain: str, queue: asyncio.Queue, ctx: ScanContext) -> list[str]:
    name = "wayback"
    url = "https://web.archive.org/cdx/search/cdx"
    return await source_worker(
        name, url, lambda text: [
            urlsplit(line.strip()).hostname or "" for line in text.splitlines() if line.strip()
        ], domain, queue, ctx, timeout=30.0,
        params={"url": f"*.{domain}/*", "collapse": "urlkey", "output": "text", "fl": "original"},
    )


def write_results(domain: str, hosts: set[str]) -> Path:
    target_dir = (TARGETS_DIR / domain).resolve()
    root = TARGETS_DIR.resolve()
    if target_dir != root and root not in target_dir.parents:
        raise ValueError("Resolved output path escaped the targets directory")
    target_dir.mkdir(parents=True, exist_ok=True)
    destination = target_dir / "subdomains.txt"
    fd, temp_name = tempfile.mkstemp(prefix=".subdomains-", dir=target_dir, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(sorted(hosts)))
            if hosts:
                handle.write("\n")
        os.replace(temp_name, destination)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return destination


async def run_httpx(domain: str, sub_file: Path, queue: asyncio.Queue, ctx: ScanContext):
    name = "httpx"
    binary = shutil.which(HTTPX_BIN) if os.path.sep not in HTTPX_BIN else HTTPX_BIN
    if not binary or not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        await emit(queue, {"type": "log", "msg": f"[httpx] Executable not found or not executable: {HTTPX_BIN}", "level": "error"})
        await emit(queue, {"type": "source_status", "source": name, "state": "failed", "count": 0})
        return
    await emit(queue, {"type": "source_status", "source": name, "state": "running"})
    count = 0
    seen: set[str] = set()
    proc = None
    stderr_task = None
    try:
        await emit(queue, {"type": "log", "msg": "[httpx] Starting live HTTP probing"})
        proc = await asyncio.create_subprocess_exec(
            binary, "-l", str(sub_file), "-sc", "-title", "-silent", "-no-stdin",
            "-json", "-timeout", "10", "-retries", "1", "-threads", "20",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await register_process(ctx, proc)

        async def drain_stderr():
            assert proc and proc.stderr
            data = await proc.stderr.read()
            if data:
                logger.debug("[httpx] %s", strip_ansi(data.decode(errors="replace"))[:1500])

        stderr_task = asyncio.create_task(drain_stderr())
        assert proc.stdout
        async with asyncio.timeout(HTTPX_TIMEOUT):
            while not ctx.stop_event.is_set():
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.5)
                except asyncio.TimeoutError:
                    if proc.returncode is not None:
                        break
                    continue
                if not line:
                    break
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(item, dict):
                    continue
                url = item.get("url") or item.get("input") or ""
                parts = urlsplit(url) if isinstance(url, str) else None
                if not parts or parts.scheme not in ("http", "https") or not parts.hostname:
                    continue
                host = normalize_hostname(parts.hostname, domain)
                if not host or url in seen:
                    continue
                seen.add(url)
                count += 1
                await emit(queue, {
                    "type": "live", "data": url,
                    "status": str(item.get("status_code", "")),
                    "title": str(item.get("title", ""))[:500],
                })
        if ctx.stop_event.is_set():
            await terminate_process(ctx, proc)
        else:
            await proc.wait()
        if stderr_task:
            await stderr_task
        await emit(queue, {"type": "log", "msg": f"[httpx] Completed: {count} live hosts"})
        await emit(queue, {"type": "source_status", "source": name, "state": "done", "count": count})
    except asyncio.TimeoutError:
        await emit(queue, {"type": "log", "msg": f"[httpx] Timed out after {HTTPX_TIMEOUT} seconds", "level": "warn"})
        await emit(queue, {"type": "source_status", "source": name, "state": "failed", "count": count})
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.exception("[httpx] Probe failed")
        await emit(queue, {"type": "log", "msg": f"[httpx] Failed: {type(exc).__name__}", "level": "error"})
        await emit(queue, {"type": "source_status", "source": name, "state": "failed", "count": count})
    finally:
        if proc and proc.returncode is None:
            await terminate_process(ctx, proc)
        elif proc:
            async with ctx.process_lock:
                ctx.processes.discard(proc)
        if stderr_task and not stderr_task.done():
            stderr_task.cancel()
            await asyncio.gather(stderr_task, return_exceptions=True)


async def sse_event(event: dict) -> str:
    return "data: " + json.dumps(event, ensure_ascii=False) + "\n\n"


async def recon_generator(ctx: ScanContext):
    queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
    found: set[str] = set()
    configs = [
        ("hackertarget", "https://api.hackertarget.com/hostsearch/", parse_hackertarget, {"q": ctx.domain}, 15.0),
        ("urlscan", "https://urlscan.io/api/v1/search/", parse_urlscan, {"q": f"page.domain:{ctx.domain}", "size": "100"}, 20.0),
        ("crtsh", "https://crt.sh/", parse_crtsh, {"q": f"%.{ctx.domain}", "output": "json"}, 30.0),
        ("jldc", f"https://anubisdb.com/anubis/subdomains/{quote(ctx.domain, safe='.')}", parse_jldc, None, 15.0),
        ("certspotter", "https://api.certspotter.com/v1/issuances", parse_certspotter,
         {"domain": ctx.domain, "include_subdomains": "true", "expand": "dns_names"}, 20.0),
        ("rapiddns", f"https://rapiddns.io/subdomain/{quote(ctx.domain, safe='.')}", parse_rapiddns, {"full": "1"}, 20.0),
        ("dnsrepo", "https://dnsrepo.noc.org/", parse_dnsrepo, {"domain": ctx.domain}, 20.0),
    ]
    all_names = [item[0] for item in configs] + ["subfinder", "wayback", "httpx"]
    for name in all_names:
        await emit(queue, {"type": "source_status", "source": name, "state": "pending"})

    tasks: list[asyncio.Task] = []
    try:
        for name, url, parser, params, timeout in configs:
            tasks.append(asyncio.create_task(source_worker(
                name, url, parser, ctx.domain, queue, ctx, timeout, params
            )))
        tasks.append(asyncio.create_task(run_subfinder(ctx.domain, queue, ctx)))
        tasks.append(asyncio.create_task(run_wayback(ctx.domain, queue, ctx)))

        pending = set(tasks)
        while pending or not queue.empty():
            if ctx.stop_event.is_set():
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.25)
                if event.get("type") == "subdomain":
                    host = event.get("data", "")
                    if host not in found:
                        found.add(host)
                        yield await sse_event(event)
                else:
                    yield await sse_event(event)
            except asyncio.TimeoutError:
                pending = {task for task in pending if not task.done()}

        if ctx.stop_event.is_set():
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await cleanup_processes(ctx)
            yield await sse_event({"type": "log", "msg": "Scan stopped by user.", "level": "warn"})
            yield await sse_event({"type": "done", "stopped": True})
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                found.update(result)

        output = write_results(ctx.domain, found)
        source_hits = sum(
            1 for result in results if isinstance(result, list) and result
        )
        yield await sse_event({"type": "log", "msg": f"Discovery complete: {len(found)} unique subdomains from {source_hits}/9 discovery sources."})
        yield await sse_event({"type": "discovery_done", "total": len(found), "sources_hit": source_hits})
        if found and not ctx.stop_event.is_set():
            probe_task = asyncio.create_task(run_httpx(ctx.domain, output, queue, ctx))
            while not probe_task.done() or not queue.empty():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=0.25)
                    yield await sse_event(event)
                except asyncio.TimeoutError:
                    continue
            await probe_task
        elif not found:
            yield await sse_event({"type": "log", "msg": "No subdomains found. Skipping live probing.", "level": "warn"})
        yield await sse_event({"type": "done", "stopped": ctx.stop_event.is_set()})
    except asyncio.CancelledError:
        ctx.stop_event.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await cleanup_processes(ctx)
        raise
    except Exception:
        logger.exception("Scan generator failed")
        yield await sse_event({"type": "log", "msg": "Unexpected scan error. Check the server log.", "level": "error"})
        yield await sse_event({"type": "done", "error": True})
    finally:
        await cleanup_processes(ctx)
        active_scans.pop(ctx.scan_id, None)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/api/scan")
async def api_scan(request: Request):
    # Reject cross-origin browser requests. Non-browser clients may omit Origin.
    origin = request.headers.get("origin")
    if origin:
        expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
        if origin.rstrip("/") != expected.rstrip("/"):
            raise HTTPException(status_code=403, detail="Cross-origin requests are not allowed")
    try:
        payload = await request.json()
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    domain = normalize_domain(payload.get("domain"))
    scan_id = payload.get("scan_id")
    if not domain:
        raise HTTPException(status_code=422, detail="Enter a valid fully-qualified domain name")
    if not isinstance(scan_id, str) or not SCAN_ID_RE.fullmatch(scan_id):
        raise HTTPException(status_code=422, detail="A valid scan_id is required")
    if scan_id in active_scans:
        raise HTTPException(status_code=409, detail="Scan ID is already active")
    if len(active_scans) >= MAX_CONCURRENT_SCANS:
        raise HTTPException(status_code=429, detail="Maximum concurrent scan limit reached")
    ctx = ScanContext(scan_id=scan_id, domain=domain)
    active_scans[scan_id] = ctx
    return StreamingResponse(
        recon_generator(ctx), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


@app.post("/api/stop")
async def api_stop(request: Request):
    origin = request.headers.get("origin")
    if origin:
        expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
        if origin.rstrip("/") != expected.rstrip("/"):
            raise HTTPException(status_code=403, detail="Cross-origin requests are not allowed")
    try:
        payload = await request.json()
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")
    scan_id = payload.get("scan_id") if isinstance(payload, dict) else None
    if not isinstance(scan_id, str) or not SCAN_ID_RE.fullmatch(scan_id):
        raise HTTPException(status_code=422, detail="A valid scan_id is required")
    ctx = active_scans.get(scan_id)
    if ctx is None:
        return {"status": "not_running"}
    ctx.stop_event.set()
    await cleanup_processes(ctx)
    return {"status": "stopping"}


@app.get("/health")
async def health():
    return {"status": "ok", "active_scans": len(active_scans)}
