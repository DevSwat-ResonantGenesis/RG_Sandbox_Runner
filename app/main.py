import asyncio
import hashlib
import json
import os
import socket
import time
import uuid
import ipaddress
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field


class HttpGetRequest(BaseModel):
    url: str
    accept: str = "*/*"
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    max_bytes: int = Field(default=1024 * 1024, ge=1, le=5 * 1024 * 1024)
    add_hosts: Optional[List[str]] = None


def _parse_allowed_hosts() -> Optional[Set[str]]:
    raw = (os.getenv("SANDBOX_RUNNER_ALLOWED_HOSTS") or "").strip()
    if not raw:
        return None
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


ALLOWED_HOSTS = _parse_allowed_hosts()
API_KEY = (os.getenv("SANDBOX_RUNNER_API_KEY") or "").strip()
IMAGE = os.getenv("SANDBOX_RUNNER_IMAGE", "python:3.11-alpine")
MEMORY = os.getenv("SANDBOX_RUNNER_MEMORY", "256m")
CPUS = os.getenv("SANDBOX_RUNNER_CPUS", "0.5")


def _parse_deny_cidrs() -> List[ipaddress._BaseNetwork]:
    raw = (os.getenv("SANDBOX_RUNNER_DENY_CIDRS") or "").strip()
    if not raw:
        return []
    out: List[ipaddress._BaseNetwork] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        out.append(ipaddress.ip_network(item, strict=False))
    return out


DENY_CIDRS = _parse_deny_cidrs()


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()


def _audit_log(event: Dict[str, Any]) -> None:
    try:
        print(json.dumps(event, separators=(",", ":"), sort_keys=True), flush=True)
    except Exception:
        return


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for net in DENY_CIDRS:
            if addr in net:
                return False
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            return False
        return True
    except Exception:
        return False


def _resolve_public_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, None)
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr, tuple) and sockaddr[0]:
            ip = sockaddr[0]
            try:
                if ipaddress.ip_address(ip).version != 4:
                    continue
            except Exception:
                continue
            if _is_public_ip(ip):
                return ip
    raise ValueError("No public IPv4 address")


def _validate_url(url: str) -> tuple[str, str, int]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are allowed")
    if parsed.username or parsed.password:
        raise ValueError("Userinfo not allowed")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise ValueError("Missing host")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP literal not allowed")

    if ALLOWED_HOSTS is not None and host not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if port not in (80, 443):
        raise ValueError("Blocked port")

    return parsed.scheme, host, port


async def _docker_http_get(*, url: str, accept: str, timeout_seconds: float, max_bytes: int, add_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
    python_code = """
import os
import json
import urllib.request
from urllib.parse import urlparse

u = os.environ.get('URL', '')
a = os.environ.get('ACCEPT', '*/*')
t = float(os.environ.get('TIMEOUT', '10'))
m = int(os.environ.get('MAX_BYTES', '1048576'))

hdr = {'User-Agent': 'Genesis2026-SandboxRunner/1.0', 'Accept': a}
out = {}

try:
    req = urllib.request.Request(u, headers=hdr)

    orig = urlparse(u)
    oh = (orig.hostname or '').lower()
    osch = (orig.scheme or '').lower()

    class _SafeRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            nu = urlparse(newurl)
            nh = (nu.hostname or '').lower()
            nsch = (nu.scheme or '').lower()
            if not nh or nh != oh:
                raise Exception('Redirect host not allowed')
            if osch == 'https' and nsch != 'https':
                raise Exception('Redirect downgrade not allowed')
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_SafeRedirect())
    resp = opener.open(req, timeout=t)

    status = getattr(resp, 'status', 200)
    ct = (resp.headers.get('content-type') or '').split(';')[0].strip().lower()
    raw = resp.read(m + 1)[:m]
    txt = raw.decode('utf-8', errors='ignore')
    out = {'status': status, 'content_type': ct, 'text': txt}
except Exception as e:
    out = {'error': str(e), 'error_type': e.__class__.__name__}

print(json.dumps(out))
""".strip()

    name = f"sandbox_http_{uuid.uuid4().hex[:12]}"
    cmd: List[str] = [
        "docker",
        "run",
        "--rm",
        f"--name={name}",
        f"--memory={MEMORY}",
        f"--memory-swap={MEMORY}",
        f"--cpus={CPUS}",
        "--pids-limit=80",
        "--security-opt=no-new-privileges",
        "--cap-drop=ALL",
        "--user=nobody",
        "--read-only",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
        "-e",
        f"URL={url}",
        "-e",
        f"ACCEPT={accept}",
        "-e",
        f"TIMEOUT={timeout_seconds}",
        "-e",
        f"MAX_BYTES={max_bytes}",
    ]

    for host_entry in add_hosts or []:
        if host_entry:
            cmd.extend(["--add-host", host_entry])

    cmd.extend([IMAGE, "python", "-c", python_code])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=float(timeout_seconds) + 5.0)
    except asyncio.TimeoutError:
        proc.kill()
        return {"error": "Docker sandbox timeout"}

    if proc.returncode != 0:
        return {"error": (stderr or b"").decode("utf-8", errors="ignore")[:2000] or "Docker sandbox failed"}

    raw = (stdout or b"").decode("utf-8", errors="ignore").strip()
    try:
        return json.loads(raw) if raw else {"error": "Empty sandbox response"}
    except Exception:
        return {"error": "Invalid sandbox JSON", "raw": raw[:2000]}


app = FastAPI()


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {"status": "ok"}


@app.post("/v1/http-get")
async def http_get(
    payload: HttpGetRequest,
    request: Request,
    x_sandbox_runner_key: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    request_id = uuid.uuid4().hex
    started = time.monotonic()
    host: Optional[str] = None
    url_hash = _url_hash(payload.url)

    if API_KEY:
        if not x_sandbox_runner_key or x_sandbox_runner_key != API_KEY:
            _audit_log(
                {
                    "duration_ms": int((time.monotonic() - started) * 1000),
                    "event": "http_get",
                    "host": host,
                    "outcome": "unauthorized",
                    "remote_addr": getattr(getattr(request, "client", None), "host", None),
                    "request_id": request_id,
                    "url_hash": url_hash,
                }
            )
            raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        _, host, _ = _validate_url(payload.url)
    except Exception as e:
        _audit_log(
            {
                "blocked_reason": str(e),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "event": "http_get",
                "host": host,
                "outcome": "blocked",
                "remote_addr": getattr(getattr(request, "client", None), "host", None),
                "request_id": request_id,
                "url_hash": url_hash,
            }
        )
        raise HTTPException(status_code=400, detail=str(e))

    try:
        pinned_ip = _resolve_public_ipv4(host)
    except Exception:
        _audit_log(
            {
                "blocked_reason": "blocked_host",
                "duration_ms": int((time.monotonic() - started) * 1000),
                "event": "http_get",
                "host": host,
                "outcome": "blocked",
                "remote_addr": getattr(getattr(request, "client", None), "host", None),
                "request_id": request_id,
                "url_hash": url_hash,
            }
        )
        raise HTTPException(status_code=400, detail="Blocked host")

    add_hosts = list(payload.add_hosts or [])
    add_hosts.insert(0, f"{host}:{pinned_ip}")

    try:
        result = await _docker_http_get(
            url=payload.url,
            accept=payload.accept,
            timeout_seconds=float(payload.timeout_seconds),
            max_bytes=int(payload.max_bytes),
            add_hosts=add_hosts,
        )
    except Exception as e:
        _audit_log(
            {
                "duration_ms": int((time.monotonic() - started) * 1000),
                "error": str(e),
                "event": "http_get",
                "host": host,
                "outcome": "error",
                "remote_addr": getattr(getattr(request, "client", None), "host", None),
                "request_id": request_id,
                "url_hash": url_hash,
            }
        )
        raise HTTPException(status_code=500, detail="Internal error")

    outcome = "ok" if isinstance(result, dict) and "error" not in result else "error"
    audit_event: Dict[str, Any] = {
        "duration_ms": int((time.monotonic() - started) * 1000),
        "event": "http_get",
        "host": host,
        "outcome": outcome,
        "remote_addr": getattr(getattr(request, "client", None), "host", None),
        "request_id": request_id,
        "sandbox_status": result.get("status") if isinstance(result, dict) else None,
        "url_hash": url_hash,
    }
    if isinstance(result, dict) and result.get("error"):
        audit_event["sandbox_error_hash"] = _hash_text(str(result.get("error")))
        if result.get("error_type"):
            audit_event["sandbox_error_type"] = str(result.get("error_type"))
    _audit_log(audit_event)

    if isinstance(result, dict) and result.get("error"):
        raise HTTPException(status_code=502, detail="Sandbox fetch failed")

    return result
