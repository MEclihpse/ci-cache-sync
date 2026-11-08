#!/usr/bin/env python3
"""Distributed vantage probe with optional SOCKS5 egress (WARP)."""
import json
import os
import random
import socket
import string
import subprocess
import sys
import time

TARGET = os.environ.get("TARGET", "54.179.181.210")
SHARD = os.environ.get("SHARD", "0")
MODE = os.environ.get("MODE", "direct")          # direct | warp
PROXY_PORT = int(os.environ.get("PROXY_PORT", "40000"))
TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "8"))
PORTS = [22, 80, 443, 8000, 8080, 9000, 50051, 5432, 6379]


def log(msg):
    print(msg, flush=True)


def setup_proxy():
    if MODE != "warp":
        return False
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "pysocks"], timeout=120)
        import socks  # noqa
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", PROXY_PORT, rdns=True)
        socket.socket = socks.socksocket
        return True
    except Exception as e:
        log(f"PROXY_SETUP_ERR {type(e).__name__}:{e}")
        return False


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
        return {"state": "refused", "secs": round(time.time() - t0, 2), "err": str(e)[:60]}
    except Exception as e:
        return {"state": "error", "secs": round(time.time() - t0, 2),
                "err": type(e).__name__ + ":" + str(e)[:80]}
    finally:
        s.close()


def banner(host, port, nbytes=200, timeout=6):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return s.recv(nbytes).decode("utf-8", "replace").replace("\r", "").replace("\n", "\\n")[:200]
    except Exception as e:
        return "ERR:" + type(e).__name__ + ":" + str(e)[:60]
    finally:
        s.close()


def http_req(host, port, method, path, headers=None, body=None, timeout=12):
    hdrs = {"Host": host, "User-Agent": "curl/8.5.0", "Accept": "*/*", "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    raw = (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode()
    if body:
        raw += body.encode()
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(raw)
        chunks, total = [], 0
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
            ("content-type:", "content-length:", "server:", "location:", "set-cookie:", "www-authenticate:", "x-"))][:8]
        text = " ".join(rest.decode("utf-8", "replace").split())[:220]
        return {"status": lines[0][:80], "headers": keep, "body": text, "len": len(rest)}
    except Exception as e:
        return {"error": type(e).__name__ + ":" + str(e)[:100]}
    finally:
        s.close()


XKEYS = ["your-api-key", "", "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32)),
         "AKIAIOSFODNN7EXAMPLE", "Qz9worker16545K", "i16879TestKey"]
PATHS = ["/", "/api", "/api/v1", "/health", "/healthz", "/metrics", "/debug/pprof/", "/.env", "/config",
         "/api/v1/health", "/api/v1/market/get-markets?status=running"]


def egress():
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            out = subprocess.run(["curl", "-s", "--max-time", "15", url], capture_output=True, text=True)
            log(f"EGRESS {url} -> {out.stdout.strip()[:60]}")
        except Exception as e:
            log(f"EGRESS {url} ERR {e}")
    try:
        out = subprocess.run(["curl", "-s", "--max-time", "15", "https://ipinfo.io/json"], capture_output=True, text=True)
        log("IPINFO " + " ".join(out.stdout.split())[:400])
    except Exception as e:
        log(f"IPINFO ERR {e}")


def main():
    log(f"=== netprobe2 shard={SHARD} mode={MODE} target={TARGET} ===")
    ok = setup_proxy()
    log(f"PROXY_ACTIVE {ok}")
    egress()
    for host, port in (("52.77.54.246", 443), ("1.1.1.1", 443)):
        log(f"CTRL {host}:{port} {json.dumps(tcp(host, port, timeout=8))}")

    portres = {}
    for p in PORTS:
        attempts = []
        for i in range(2):
            r = tcp(TARGET, p)
            attempts.append(r)
            log(f"PORT {TARGET}:{p} try{i+1} {json.dumps(r)}")
            if r["state"] in ("open", "refused"):
                if i == 1:
                    break
                break
        portres[p] = attempts

    if any(a["state"] == "open" for a in portres.get(22, [])):
        log(f"SSH_BANNER {TARGET}:22 {banner(TARGET, 22)!r}")

    if any(a["state"] == "open" for a in portres.get(50051, [])):
        s = socket.socket()
        s.settimeout(10)
        try:
            s.connect((TARGET, 50051))
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            time.sleep(1)
            d = s.recv(200)
            log(f"GRPC_PREFACE_RESP {d.hex()[:200]} len={len(d)}")
        except Exception as e:
            log(f"GRPC_PREFACE_ERR {type(e).__name__}:{e}")
        finally:
            s.close()
        pc = "/tmp/pc.conf"
        open(pc, "w").write(
            "strict_chain\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 15000\n"
            f"[ProxyList]\nsocks5 127.0.0.1 {PROXY_PORT}\n")
        subprocess.run(["bash", "-c",
                        "curl -sSL --max-time 90 -o /tmp/grpcurl.tgz https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz && tar -xzf /tmp/grpcurl.tgz -C /tmp grpcurl && chmod +x /tmp/grpcurl"],
                       capture_output=True, text=True, timeout=120)
        if os.path.exists("/tmp/grpcurl"):
            prefix = ["proxychains4", "-q", "-f", pc] if MODE == "warp" else []
            for sub in (["list"], ["describe"]):
                cmd = prefix + ["/tmp/grpcurl", "-plaintext", "-max-time", "20", f"{TARGET}:50051"] + sub
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    log("GRPCURL " + " ".join(sub) + f" rc={r.returncode} OUT:" +
                        " | ".join(r.stdout.strip().splitlines()[:80])[:2500] +
                        " ERR:" + " | ".join(r.stderr.strip().splitlines()[:4])[:400])
                except Exception as e:
                    log(f"GRPCURL_ERR {e}")
        else:
            log("GRPCURL_DOWNLOAD_FAILED")

    for p in (8000, 9000, 8080):
        if not any(a["state"] == "open" for a in portres.get(p, [])):
            continue
        for path in PATHS:
            log(f"HTTP {TARGET}:{p} GET {path} -> {json.dumps(http_req(TARGET, p, 'GET', path))[:600]}")
        for key in XKEYS:
            for path in ("/api/v1/user/me", "/api/v1/base/search?searchType=1"):
                log(f"XKEY {TARGET}:{p} key={key!r} {path} -> {json.dumps(http_req(TARGET, p, 'GET', path, headers={'X-API-Key': key}))[:500]}")
        log(f"HTTP {TARGET}:{p} POST /api/v1/user/login -> {json.dumps(http_req(TARGET, p, 'POST', '/api/v1/user/login', headers={'Content-Type': 'application/json'}, body='{\"address\":\"0x0000000000000000000000000000000000000001\"}'))[:500]}")
    log(f"=== done shard={SHARD} mode={MODE} ===")


if __name__ == "__main__":
    main()
