#!/usr/bin/env python3
"""Bounded async TCP scan of the predict origin + deep range around interesting ports."""
import asyncio
import json
import os
import socket
import subprocess

HOST = os.environ.get("THOST", "52.77.54.246")
CONC = 300
TIMEOUT = 4.0

# top-1000-ish common ports + explicit ranges of interest
BASE = [21,22,23,25,53,80,81,110,111,135,139,143,161,389,443,445,465,500,512,513,514,515,548,554,587,
        623,631,636,873,902,989,990,993,995,1025,1080,1099,1241,1311,1352,1433,1434,1521,1723,1883,
        1900,2049,2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,2379,3000,3001,3128,3260,3306,
        3389,3478,3632,3690,4000,4040,4369,4443,4444,4505,4506,5000,5001,5432,5555,5601,5672,5900,
        5984,6000,6379,6443,6666,6667,7001,7077,7443,7474,8000,8001,8008,8009,8010,8042,8069,8080,
        8081,8082,8088,8090,8123,8161,8181,8222,8280,8333,8400,8443,8444,8500,8529,8880,8888,8983,
        9000,9001,9002,9042,9090,9091,9092,9100,9200,9300,9418,9443,9999,10000,10250,11211,15672,
        16379,17017,18080,18081,20000,25565,27017,27018,28017,50000,50051,50070,61616]
RANGES = [(3000, 3010), (5000, 5010), (8000, 8100), (9000, 9100), (50051, 50053), (6443, 6445), (2375, 2376)]


def ports():
    ps = set(BASE)
    for a, b in RANGES:
        ps.update(range(a, b + 1))
    return sorted(ps)


async def probe(p):
    try:
        fut = asyncio.open_connection(HOST, p)
        r, w = await asyncio.wait_for(fut, timeout=TIMEOUT)
        w.close()
        return p, "open", None
    except asyncio.TimeoutError:
        return p, "timeout", None
    except ConnectionRefusedError:
        return p, "refused", None
    except Exception as e:
        return p, "err", type(e).__name__


async def main():
    log = lambda m: print(m, flush=True)
    log(f"=== scan {HOST} ports={len(ports())} conc={CONC} ===")
    try:
        r = subprocess.run(["curl", "-s", "--max-time", "12", "https://api.ipify.org"], capture_output=True, text=True)
        log("EGRESS " + r.stdout.strip()[:60])
    except Exception:
        pass
    sem = asyncio.Semaphore(CONC)
    res = []

    async def bounded(p):
        async with sem:
            res.append(await probe(p))

    await asyncio.gather(*(bounded(p) for p in ports()))
    op = sorted(p for p, s, _ in res if s == "open")
    ref = sorted(p for p, s, _ in res if s == "refused")
    log("OPEN " + json.dumps(op))
    log("REFUSED_COUNT " + str(len(ref)))
    log("REFUSED_SAMPLE " + json.dumps(ref[:40]))
    for p in op:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((HOST, p))
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            d = s.recv(400)
            log(f"BANNER {p} " + json.dumps(" ".join(d.decode('latin1', 'replace').split())[:200]))
            s.close()
        except Exception as e:
            log(f"BANNER {p} ERR {type(e).__name__}")
    log("=== scandone ===")


asyncio.run(main())
