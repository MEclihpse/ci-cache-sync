#!/usr/bin/env python3
"""Multi-vantage SNI/Host virtual-host enumeration against a single TLS origin."""
import json
import os
import socket
import ssl
import time

HOST = os.environ.get("THOST", "52.77.54.246")
SHARD = os.environ.get("SHARD", "0")
SNI = os.environ.get("SNI", "predict.aifos.info")
PORTS = [22, 80, 443, 8080, 8443, 9000, 50051]
TIMEOUT = 8.0
HOSTS = ["predict.aifos.info", "admin.promethex.market", "localhost", "127.0.0.1", "52.77.54.246",
         "intranet", ""]


def log(m):
    print(m, flush=True)


def tcp(port, timeout=TIMEOUT):
    t0 = time.time()
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((HOST, port))
        return {"state": "open", "secs": round(time.time() - t0, 2)}
    except socket.timeout:
        return {"state": "filtered_timeout", "secs": round(time.time() - t0, 2)}
    except ConnectionRefusedError:
        return {"state": "refused", "secs": round(time.time() - t0, 2)}
    except Exception as e:
        return {"state": "error", "secs": round(time.time() - t0, 2), "err": type(e).__name__ + ":" + str(e)[:70]}
    finally:
        s.close()


def tls_http(port, sni, host_header, path="/", timeout=12, read_limit=12000):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception:
        pass
    raw = socket.socket()
    raw.settimeout(timeout)
    out = {"sni": sni, "host": host_header if host_header else "<none>", "port": port, "path": path}
    try:
        raw.connect((HOST, port))
        if sni == "<none>":
            ss = ctx.wrap_socket(raw, server_hostname=None)
        else:
            ss = ctx.wrap_socket(raw, server_hostname=sni)
        try:
            cert = ss.getpeercert(binary_form=False) or {}
        except Exception:
            cert = {}
        out["tls_version"] = ss.version()
        out["cipher"] = ss.cipher()[0] if ss.cipher() else None
        if not cert:
            der = ss.getpeercert(binary_form=True)
            out["cert_der_len"] = len(der) if der else 0
        else:
            out["cert_subject"] = str(cert.get("subject"))
            out["cert_issuer"] = str(cert.get("issuer"))
            out["cert_san"] = str(cert.get("subjectAltName"))[:400]
            out["cert_notAfter"] = cert.get("notAfter")
        req = f"GET {path} HTTP/1.1\r\n"
        if host_header:
            req += f"Host: {host_header}\r\n"
        req += f"User-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        ss.sendall(req.encode())
        data = b""
        while len(data) < read_limit:
            try:
                d = ss.recv(4096)
            except Exception:
                break
            if not d:
                break
            data += d
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin1").split("\r\n")
        out["status"] = lines[0][:80] if lines else ""
        out["headers"] = [l for l in lines[1:] if l.lower().startswith(
            ("server:", "content-type:", "content-length:", "location:", "set-cookie:", "x-", "www-authenticate:", "allow:"))][:8]
        out["body_len"] = len(body)
        out["body_prefix"] = " ".join(body.decode("utf-8", "replace").split())[:200]
        ss.close()
        return out
    except ssl.SSLError as e:
        out["tls_error"] = "SSLError:" + str(e)[:140]
        try:
            raw.close()
        except Exception:
            pass
        return out
    except Exception as e:
        out["error"] = type(e).__name__ + ":" + str(e)[:120]
        try:
            raw.close()
        except Exception:
            pass
        return out


def main():
    log(f"=== netprobe4 shard={SHARD} target={HOST} ===")
    import subprocess
    for url in ("https://api.ipify.org",):
        try:
            r = subprocess.run(["curl", "-s", "--max-time", "12", url], capture_output=True, text=True)
            log(f"EGRESS {r.stdout.strip()[:60]}")
        except Exception as e:
            log(f"EGRESS_ERR {e}")
    try:
        r = subprocess.run(["curl", "-s", "--max-time", "12", "https://ipinfo.io/json"], capture_output=True, text=True)
        log("IPINFO " + " ".join(r.stdout.split())[:300])
    except Exception:
        pass

    # control
    log(f"CTRL {HOST}:443 {json.dumps(tcp(443))}")

    portres = {}
    for p in PORTS:
        a = [tcp(p)]
        if a[0]["state"] == "filtered_timeout":
            a.append(tcp(p))
        portres[p] = a
        log(f"PORT {HOST}:{p} {json.dumps(a)}")

    # A) fixed SNI, Host matrix on 443
    for h in HOSTS:
        log("VHOST " + json.dumps(tls_http(443, SNI, h, "/"))[:900])

    # extra: same Host but on /healthz and /admin when Host=predict
    for path in ("/healthz", "/admin", "/api/v1/user/me"):
        log("PATH " + json.dumps(tls_http(443, SNI, "predict.aifos.info", path))[:700])

    # C) SNI variants (cert / vhost differentiation)
    for sni in ("predict.aifos.info", "admin.promethex.market", "app.promethex.market", "<none>"):
        r = tls_http(443, sni, "predict.aifos.info", "/")
        keep = {k: r.get(k) for k in ("sni", "status", "cert_subject", "cert_san", "tls_error", "error", "tls_version")}
        log("SNI " + json.dumps(keep)[:700])

    # plain HTTP on 80 if reachable
    if any(x["state"] == "open" for x in portres.get(80, [])):
        for h in ("predict.aifos.info", "admin.promethex.market", "localhost"):
            s = socket.socket()
            s.settimeout(8)
            try:
                s.connect((HOST, 80))
                s.sendall(f"GET / HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n".encode())
                d = b""
                while len(d) < 4000:
                    c = s.recv(2048)
                    if not c:
                        break
                    d += c
                log(f"HTTP80 host={h} " + json.dumps({"resp": " ".join(d.decode('latin1').split())[:240]}))
            except Exception as e:
                log(f"HTTP80 host={h} ERR {type(e).__name__}:{e}")
            finally:
                s.close()

    # other ports: if open, grab banner/HTTP
    for p in (8080, 8443, 9000, 50051):
        if any(x["state"] == "open" for x in portres.get(p, [])):
            if p in (8080, 8443, 9000):
                log(f"OTHER {p} " + json.dumps(tls_http(p, SNI, "predict.aifos.info", "/"))[:600])
            else:
                s = socket.socket()
                s.settimeout(6)
                try:
                    s.connect((HOST, p))
                    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
                    time.sleep(1)
                    d = s.recv(200)
                    log(f"OTHER {p} GRPC_PREFACE {d.hex()[:160]} len={len(d)}")
                except Exception as e:
                    log(f"OTHER {p} ERR {type(e).__name__}:{e}")
                finally:
                    s.close()
    log(f"=== done shard={SHARD} ===")


if __name__ == "__main__":
    main()
