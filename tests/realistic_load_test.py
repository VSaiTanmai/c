"""
CLIF Realistic Load Test — LANL-Format Cyber Security Events
=============================================================

Generates production-scale synthetic data matching the Los Alamos National
Laboratory (LANL) Comprehensive Multi-Source Cyber-Security Events dataset:

  • Auth events     → security-events topic  (Windows AD authentication)
  • Process events  → process-events topic   (Windows process start/stop)
  • Network flows   → network-events topic   (router flow records)
  • DNS lookups     → raw-logs topic         (DNS resolution logs)

Includes realistic red-team attack patterns injected into auth events.

Architecture:
  - Parallel producers (1 per topic) for maximum broker utilisation
  - Pre-serialised payloads (JSON encoding outside timing loop)
  - Configurable event count per data source
  - Full pipeline measurement: produce → consumer → ClickHouse arrival

Usage:
    python tests/realistic_load_test.py [--events N] [--skip-verify]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import string
import sys
import time
import uuid
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import orjson
    _json_encode = orjson.dumps       # → bytes, 3-5× faster than stdlib
except ImportError:
    def _json_encode(obj):            # fallback
        return json.dumps(obj).encode()

from confluent_kafka import Producer
from clickhouse_driver import Client as _CHNativeClient
import re as _re

# ── Thin clickhouse-driver wrapper (matches clickhouse-connect API) ──────────
_PARAM_RE = _re.compile(r"\{(\w+):\w+\}")

class _QR:
    __slots__ = ("result_rows",)
    def __init__(self, rows): self.result_rows = rows

class _CHClient:
    def __init__(self, **kw):
        self._c = _CHNativeClient(
            host=kw["host"], port=kw["port"], user=kw.get("username",""),
            password=kw.get("password",""), database=kw.get("database","default"),
            connect_timeout=kw.get("connect_timeout", 30),
            send_receive_timeout=kw.get("send_receive_timeout", 120),
        )
    def query(self, sql, parameters=None):
        sql = _PARAM_RE.sub(r"%(\1)s", sql)
        return _QR(self._c.execute(sql, parameters or {}))
    def close(self):
        self._c.disconnect()

# ── Configuration ────────────────────────────────────────────────────────────

BROKER = os.getenv("BROKER", "localhost:19092,localhost:29092,localhost:39092")
CH_HOST = os.getenv("CH_HOST", "localhost")
CH_PORT = int(os.getenv("CH_PORT", "9000"))
CH_USER = os.getenv("CH_USER", "clif_admin")
CH_PASS = os.getenv("CH_PASS", "Cl1f_Ch@ngeM3_2026!")
CH_DB = os.getenv("CH_DB", "clif_logs")

PRODUCER_CONFIG = {
    "bootstrap.servers": BROKER,
    "linger.ms": 20,                          # 20ms — optimal batch fill for throughput
    "batch.num.messages": 100_000,            # 100K msgs per batch
    "batch.size": 4_194_304,                  # 4 MB batch — bigger = fewer RPCs
    "queue.buffering.max.messages": 4_000_000, # 4M — headroom for 8 workers
    "queue.buffering.max.kbytes": 4_194_304,  # 4 GB queue
    "compression.type": "lz4",               # LZ4 fast compression
    "acks": "1",                              # leader-only ack (2/3 less broker CPU)
    "message.send.max.retries": 10,           # retry on transient broker disconnect
    "retry.backoff.ms": 200,                  # 200ms between retries
    "reconnect.backoff.ms": 100,              # fast reconnect
    "reconnect.backoff.max.ms": 5000,         # max reconnect backoff
    "socket.send.buffer.bytes": 4_194_304,    # 4 MB send buffer
    "log.connection.close": False,            # suppress noisy disconnect logs
}

# ── LANL-Realistic Data Universe ────────────────────────────────────────────

# Simulating a 17,684-computer, 12,425-user enterprise network (LANL scale)
NUM_USERS = 12_425
NUM_COMPUTERS = 17_684
NUM_DOMAINS = 5
NUM_PROCESSES = 62_974

DOMAINS = [f"DOM{i}" for i in range(1, NUM_DOMAINS + 1)]
USERS = [f"U{i}" for i in range(1, NUM_USERS + 1)]
COMPUTERS = [f"C{i}" for i in range(1, NUM_COMPUTERS + 1)]
SYSTEM_ACCOUNTS = ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"]
PROCESSES = [f"P{i}" for i in range(1, min(NUM_PROCESSES + 1, 10001))]  # cap for memory

AUTH_TYPES = ["Negotiate", "Kerberos", "NTLM", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"]
LOGON_TYPES = ["Batch", "Interactive", "Network", "Service", "RemoteInteractive",
               "NetworkCleartext", "Unlock", "CachedInteractive"]
AUTH_ORIENT = ["LogOn", "LogOff", "TGS", "TGT", "AuthMap"]
AUTH_RESULTS = ["Success"] * 95 + ["Failure"] * 5  # 95% success rate

PROTOCOLS = ["6", "17", "1"]  # TCP, UDP, ICMP — LANL uses numeric codes
WELL_KNOWN_PORTS = [80, 443, 445, 389, 88, 135, 139, 53, 3389, 8080, 22, 636]

# Red team attack patterns (LANL has ~750 compromise events over 58 days)
RED_TEAM_USERS = random.sample(USERS[:1000], 20)
RED_TEAM_SRC = random.sample(COMPUTERS[:200], 5)  # compromised workstations
RED_TEAM_TARGETS = random.sample(COMPUTERS[:5000], 50)  # lateral movement targets

MITRE_TACTICS = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "exfiltration", "command-and-control",
]
MITRE_TECHNIQUES = [
    "T1078", "T1059", "T1053", "T1548", "T1036", "T1003", "T1018",
    "T1021", "T1560", "T1041", "T1071", "T1110", "T1190", "T1566",
]
SUSPICIOUS_BINARIES = [
    "/usr/bin/nc", "/usr/bin/nmap", "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\powershell.exe", "C:\\Windows\\Temp\\payload.exe",
    "/tmp/reverse_shell", "C:\\Users\\Public\\mimikatz.exe",
]
# Pre-built ranges for random.choices() — C-level bulk sampling
_R_OCTET_1 = range(1, 224)   # first IP octet
_R_OCTET   = range(256)      # middle IP octets
_R_OCTET_4 = range(1, 255)   # last IP octet
_R_PORT = range(1024, 65536)
_R_PID = range(1, 65536)
_R_PID100 = range(100, 65536)
_R_UID = range(500, 65535)
_R_PPID = range(1, 10001)
_R_BYTES_S = range(64, 1_000_001)
_R_BYTES_R = range(64, 5_000_001)
_R_PKT = range(1, 10001)
_R_DUR = range(3601)
# ── Event Generators (LANL Format → CLIF JSON) ──────────────────────────────


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def gen_auth_event(epoch: int, tag: str, *, is_redteam: bool = False) -> dict:
    """Generate a LANL auth event → maps to security-events topic."""
    if is_redteam:
        user = random.choice(RED_TEAM_USERS)
        src = random.choice(RED_TEAM_SRC)
        dst = random.choice(RED_TEAM_TARGETS)
        result = "Success"
        severity = random.randint(3, 4)
        tactic = random.choice(["lateral-movement", "credential-access", "privilege-escalation"])
        technique = random.choice(["T1021", "T1003", "T1078"])
    else:
        user = random.choice(USERS) if random.random() > 0.3 else random.choice(SYSTEM_ACCOUNTS)
        src = random.choice(COMPUTERS)
        dst = random.choice(COMPUTERS)
        result = random.choice(AUTH_RESULTS)
        severity = 0 if result == "Success" else random.randint(1, 2)
        tactic = ""
        technique = ""

    domain = random.choice(DOMAINS)
    return {
        "timestamp": _now_iso(),
        "severity": severity,
        "category": "auth" if not is_redteam else "lateral-movement",
        "source": f"{src}",
        "description": (
            f"Auth: {user}@{domain} from {src} to {dst} | "
            f"{random.choice(AUTH_TYPES)}/{random.choice(LOGON_TYPES)}/{random.choice(AUTH_ORIENT)} "
            f"→ {result}"
        ),
        "user_id": f"{user}@{domain}",
        "ip_address": _rand_ip(),
        "hostname": dst,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "ai_confidence": round(random.uniform(0.85, 0.99), 2) if is_redteam else 0.0,
        "ai_explanation": "Anomalous lateral movement detected" if is_redteam else "",
        "metadata": {
            "request_id": tag,
            "lanl_epoch": epoch,
            "auth_type": random.choice(AUTH_TYPES),
            "logon_type": random.choice(LOGON_TYPES),
            "orientation": random.choice(AUTH_ORIENT),
            "result": result,
            "src_computer": src,
            "dst_computer": dst,
            "domain": domain,
            "is_redteam": is_redteam,
        },
    }


def gen_process_event(epoch: int, tag: str) -> dict:
    """Generate a LANL process event → maps to process-events topic."""
    computer = random.choice(COMPUTERS)
    user = random.choice(USERS) if random.random() > 0.2 else random.choice(SYSTEM_ACCOUNTS)
    domain = random.choice(DOMAINS)
    process = random.choice(PROCESSES)
    is_start = random.random() > 0.4  # 60% start, 40% end
    is_suspicious = random.random() < 0.002  # 0.2% suspicious

    return {
        "timestamp": _now_iso(),
        "hostname": computer,
        "pid": random.randint(100, 65535),
        "ppid": random.randint(1, 10000),
        "uid": random.randint(500, 65534),
        "gid": random.randint(500, 65534),
        "binary_path": random.choice(SUSPICIOUS_BINARIES) if is_suspicious else f"C:\\Windows\\System32\\{process}.exe",
        "arguments": f"--user {user}@{domain}" if is_start else "",
        "cwd": f"C:\\Users\\{user}" if user not in SYSTEM_ACCOUNTS else "C:\\Windows\\System32",
        "exit_code": 0 if is_start else random.choice([0, 0, 0, 1, -1]),
        "container_id": "",
        "pod_name": "",
        "namespace": "windows",
        "syscall": "CreateProcess" if is_start else "TerminateProcess",
        "is_suspicious": 1 if is_suspicious else 0,
        "detection_rule": "proc_anomaly_001" if is_suspicious else "",
        "metadata": {
            "tag": tag,
            "lanl_epoch": epoch,
            "process_name": process,
            "action": "Start" if is_start else "End",
            "user": f"{user}@{domain}",
            "computer": computer,
        },
    }


def gen_network_flow(epoch: int, tag: str) -> dict:
    """Generate a LANL network flow → maps to network-events topic."""
    src = random.choice(COMPUTERS)
    dst = random.choice(COMPUTERS)
    duration = random.randint(0, 3600)
    protocol = random.choice(PROTOCOLS)
    is_suspicious = random.random() < 0.001  # 0.1% suspicious

    return {
        "timestamp": _now_iso(),
        "hostname": src,
        "src_ip": _rand_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_ip": _rand_ip(),
        "dst_port": random.choice(WELL_KNOWN_PORTS) if random.random() > 0.3 else random.randint(1024, 65535),
        "protocol": {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(protocol, "TCP"),
        "direction": random.choice(["outbound", "inbound"]),
        "bytes_sent": random.randint(64, 1_000_000),
        "bytes_received": random.randint(64, 5_000_000),
        "duration_ms": duration * 1000,
        "pid": random.randint(1, 65535),
        "binary_path": "",
        "container_id": "",
        "pod_name": "",
        "namespace": "enterprise",
        "dns_query": f"{dst}.lanl.internal",
        "geo_country": "US",
        "is_suspicious": 1 if is_suspicious else 0,
        "detection_rule": "flow_anomaly_001" if is_suspicious else "",
        "metadata": {
            "tag": tag,
            "lanl_epoch": epoch,
            "src_computer": src,
            "dst_computer": dst,
            "packet_count": random.randint(1, 10000),
            "duration_sec": duration,
        },
    }


def gen_dns_event(epoch: int, tag: str) -> dict:
    """Generate a LANL DNS lookup → maps to raw-logs topic."""
    src = random.choice(COMPUTERS)
    resolved = random.choice(COMPUTERS)
    return {
        "timestamp": _now_iso(),
        "level": "INFO",
        "source": "dns-server",
        "message": f"DNS lookup: {src} → {resolved}.lanl.internal (A record)",
        "metadata": {
            "request_id": tag,
            "lanl_epoch": epoch,
            "src_computer": src,
            "resolved_computer": resolved,
            "record_type": random.choice(["A", "AAAA", "CNAME", "PTR", "SRV"]),
        },
    }


# ── Topic wiring ────────────────────────────────────────────────────────────

TOPIC_CONFIG = {
    "security-events": {
        "generator": gen_auth_event,
        "table": "security_events",
        "weight": 0.35,  # LANL: ~1B auth events / 1.65B total ≈ 60%, we skew for variety
    },
    "process-events": {
        "generator": gen_process_event,
        "table": "process_events",
        "weight": 0.25,  # LANL: ~380M process events
    },
    "network-events": {
        "generator": gen_network_flow,
        "table": "network_events",
        "weight": 0.25,  # LANL: ~130M network flows
    },
    "raw-logs": {
        "generator": gen_dns_event,
        "table": "raw_logs",
        "weight": 0.15,  # LANL: ~70M DNS lookups
    },
}


# ── Fast Batch Generators ────────────────────────────────────────────────────
# Pre-compute random selections in chunks via random.choices() (C-level loop)
# then serialise with orjson.  Combined with ProcessPoolExecutor (own GIL per
# topic) this eliminates the two largest bottlenecks: GIL contention and
# per-event random.choice() + json.dumps() overhead.

_RAND_BATCH = 25_000  # events per chunk — larger = fewer iterations


def _fast_ips(n):
    """Generate n random IPs via 4 single C-level random.choices() calls."""
    a = random.choices(_R_OCTET_1, k=n)
    b = random.choices(_R_OCTET, k=n)
    c = random.choices(_R_OCTET, k=n)
    d = random.choices(_R_OCTET_4, k=n)
    return [f"{a[i]}.{b[i]}.{c[i]}.{d[i]}" for i in range(n)]


def _batch_auth_payloads(n, tag, ts, epoch_offset, redteam_pct):
    """Generate n auth event payloads as pre-serialised bytes."""
    rt_thresh = redteam_pct / 100
    r_rt = [random.random() for _ in range(n)]
    r_user = [random.random() for _ in range(n)]
    users = random.choices(USERS, k=n)
    sys_accts = random.choices(SYSTEM_ACCOUNTS, k=n)
    srcs = random.choices(COMPUTERS, k=n)
    dsts = random.choices(COMPUTERS, k=n)
    doms = random.choices(DOMAINS, k=n)
    at1 = random.choices(AUTH_TYPES, k=n)
    lt1 = random.choices(LOGON_TYPES, k=n)
    ao1 = random.choices(AUTH_ORIENT, k=n)
    at2 = random.choices(AUTH_TYPES, k=n)
    lt2 = random.choices(LOGON_TYPES, k=n)
    ao2 = random.choices(AUTH_ORIENT, k=n)
    res = random.choices(AUTH_RESULTS, k=n)
    rt_u = random.choices(RED_TEAM_USERS, k=n)
    rt_s = random.choices(RED_TEAM_SRC, k=n)
    rt_d = random.choices(RED_TEAM_TARGETS, k=n)
    rt_tac = random.choices(
        ["lateral-movement", "credential-access", "privilege-escalation"], k=n)
    rt_tec = random.choices(["T1021", "T1003", "T1078"], k=n)
    ips = _fast_ips(n)
    _sev12 = random.choices((1, 2), k=n)
    sev_norm = [0 if res[i] == "Success" else _sev12[i] for i in range(n)]
    sev_rt = random.choices((3, 4), k=n)
    conf_rt = [round(random.uniform(0.85, 0.99), 2) for _ in range(n)]

    payloads = []
    _enc = _json_encode
    for i in range(n):
        is_rt = r_rt[i] < rt_thresh
        if is_rt:
            u, s, d, r = rt_u[i], rt_s[i], rt_d[i], "Success"
            sev, tac, tec = sev_rt[i], rt_tac[i], rt_tec[i]
            cat, conf, expl = "lateral-movement", conf_rt[i], "Anomalous lateral movement detected"
        else:
            u = sys_accts[i] if r_user[i] < 0.3 else users[i]
            s, d, r = srcs[i], dsts[i], res[i]
            sev, tac, tec = sev_norm[i], "", ""
            cat, conf, expl = "auth", 0.0, ""
        dom = doms[i]
        payloads.append(_enc({
            "timestamp": ts, "severity": sev, "category": cat, "source": s,
            "description": f"Auth: {u}@{dom} from {s} to {d} | {at1[i]}/{lt1[i]}/{ao1[i]} \u2192 {r}",
            "user_id": f"{u}@{dom}", "ip_address": ips[i], "hostname": d,
            "mitre_tactic": tac, "mitre_technique": tec,
            "ai_confidence": conf, "ai_explanation": expl,
            "metadata": {
                "request_id": tag, "lanl_epoch": epoch_offset + i,
                "auth_type": at2[i], "logon_type": lt2[i], "orientation": ao2[i],
                "result": r, "src_computer": s, "dst_computer": d,
                "domain": dom, "is_redteam": is_rt,
            },
        }))
    return payloads


def _batch_process_payloads(n, tag, ts, epoch_offset):
    """Generate n process event payloads as pre-serialised bytes."""
    comps = random.choices(COMPUTERS, k=n)
    users = random.choices(USERS, k=n)
    sys_accts = random.choices(SYSTEM_ACCOUNTS, k=n)
    doms = random.choices(DOMAINS, k=n)
    procs = random.choices(PROCESSES, k=n)
    r_user = [random.random() for _ in range(n)]
    r_start = [random.random() for _ in range(n)]
    r_susp = [random.random() for _ in range(n)]
    pids = random.choices(_R_PID100, k=n)
    ppids = random.choices(_R_PPID, k=n)
    uids = random.choices(_R_UID, k=n)
    gids = random.choices(_R_UID, k=n)
    exits = random.choices([0, 0, 0, 1, -1], k=n)
    susp_bins = random.choices(SUSPICIOUS_BINARIES, k=n)

    payloads = []
    _enc = _json_encode
    _sys_set = frozenset(SYSTEM_ACCOUNTS)
    for i in range(n):
        u = sys_accts[i] if r_user[i] < 0.2 else users[i]
        is_start = r_start[i] > 0.4
        is_susp = r_susp[i] < 0.002
        comp, proc, dom = comps[i], procs[i], doms[i]
        payloads.append(_enc({
            "timestamp": ts, "hostname": comp,
            "pid": pids[i], "ppid": ppids[i], "uid": uids[i], "gid": gids[i],
            "binary_path": susp_bins[i] if is_susp else f"C:\\Windows\\System32\\{proc}.exe",
            "arguments": f"--user {u}@{dom}" if is_start else "",
            "cwd": f"C:\\Users\\{u}" if u not in _sys_set else "C:\\Windows\\System32",
            "exit_code": 0 if is_start else exits[i],
            "container_id": "", "pod_name": "", "namespace": "windows",
            "syscall": "CreateProcess" if is_start else "TerminateProcess",
            "is_suspicious": 1 if is_susp else 0,
            "detection_rule": "proc_anomaly_001" if is_susp else "",
            "metadata": {
                "tag": tag, "lanl_epoch": epoch_offset + i,
                "process_name": proc, "action": "Start" if is_start else "End",
                "user": f"{u}@{dom}", "computer": comp,
            },
        }))
    return payloads


def _batch_network_payloads(n, tag, ts, epoch_offset):
    """Generate n network flow payloads as pre-serialised bytes."""
    srcs = random.choices(COMPUTERS, k=n)
    dsts = random.choices(COMPUTERS, k=n)
    protos = random.choices(PROTOCOLS, k=n)
    dirs_ = random.choices(["outbound", "inbound"], k=n)
    ports_wk = random.choices(WELL_KNOWN_PORTS, k=n)
    r_port = [random.random() for _ in range(n)]
    r_susp = [random.random() for _ in range(n)]
    durs = random.choices(_R_DUR, k=n)
    src_ports = random.choices(_R_PORT, k=n)
    dst_ports_r = random.choices(_R_PORT, k=n)
    bsent = random.choices(_R_BYTES_S, k=n)
    brecv = random.choices(_R_BYTES_R, k=n)
    pids = random.choices(_R_PID, k=n)
    pkts = random.choices(_R_PKT, k=n)
    src_ips = _fast_ips(n)
    dst_ips = _fast_ips(n)
    _pm = {"6": "TCP", "17": "UDP", "1": "ICMP"}

    payloads = []
    _enc = _json_encode
    for i in range(n):
        s, d = srcs[i], dsts[i]
        payloads.append(_enc({
            "timestamp": ts, "hostname": s,
            "src_ip": src_ips[i], "src_port": src_ports[i],
            "dst_ip": dst_ips[i],
            "dst_port": ports_wk[i] if r_port[i] > 0.3 else dst_ports_r[i],
            "protocol": _pm.get(protos[i], "TCP"), "direction": dirs_[i],
            "bytes_sent": bsent[i], "bytes_received": brecv[i],
            "duration_ms": durs[i] * 1000, "pid": pids[i],
            "binary_path": "", "container_id": "", "pod_name": "",
            "namespace": "enterprise",
            "dns_query": f"{d}.lanl.internal", "geo_country": "US",
            "is_suspicious": 1 if r_susp[i] < 0.001 else 0,
            "detection_rule": "flow_anomaly_001" if r_susp[i] < 0.001 else "",
            "metadata": {
                "tag": tag, "lanl_epoch": epoch_offset + i,
                "src_computer": s, "dst_computer": d,
                "packet_count": pkts[i], "duration_sec": durs[i],
            },
        }))
    return payloads


def _batch_dns_payloads(n, tag, ts, epoch_offset):
    """Generate n DNS event payloads as pre-serialised bytes."""
    srcs = random.choices(COMPUTERS, k=n)
    ress = random.choices(COMPUTERS, k=n)
    rtypes = random.choices(["A", "AAAA", "CNAME", "PTR", "SRV"], k=n)

    payloads = []
    _enc = _json_encode
    for i in range(n):
        s, r = srcs[i], ress[i]
        payloads.append(_enc({
            "timestamp": ts, "level": "INFO", "source": "dns-server",
            "message": f"DNS lookup: {s} \u2192 {r}.lanl.internal (A record)",
            "metadata": {
                "request_id": tag, "lanl_epoch": epoch_offset + i,
                "src_computer": s, "resolved_computer": r,
                "record_type": rtypes[i],
            },
        }))
    return payloads


_BATCH_GENERATORS = {
    "security-events": _batch_auth_payloads,
    "process-events": _batch_process_payloads,
    "network-events": _batch_network_payloads,
    "raw-logs": _batch_dns_payloads,
}


def _produce_worker(topic, count, tag, redteam_pct, start_offset=0,
                    duration_sec=0):
    """Generate + produce events for one topic partition of work.

    Runs in its own **process** via ProcessPoolExecutor \u2192 own GIL, own core.
    Uses batch-random pre-computation + orjson for maximum throughput.
    No per-message callbacks \u2014 uses flush() return for delivery counting.

    When *duration_sec* > 0, production is **paced** so events are spread
    evenly across the requested wall-clock window.  This yields multiple
    data-points on the dashboard Events/Minute graph and a live EPS counter.
    """
    p = Producer(PRODUCER_CONFIG)
    produced = 0

    batch_gen = _BATCH_GENERATORS[topic]
    is_auth = topic == "security-events"

    t0 = time.perf_counter()
    offset = start_offset
    end = start_offset + count

    # ---- pacing setup ----
    # When duration_sec > 0 we compute a *target_eps* and inject
    # time.sleep() between waves so production rate roughly matches.
    target_eps = 0.0
    if duration_sec > 0 and count > 0:
        target_eps = count / duration_sec

    while offset < end:
        wave_t0 = time.perf_counter()
        chunk = min(_RAND_BATCH, end - offset)
        ts = _now_iso()
        payloads = (batch_gen(chunk, tag, ts, offset, redteam_pct)
                    if is_auth else batch_gen(chunk, tag, ts, offset))
        for payload in payloads:
            while True:
                try:
                    p.produce(topic, payload)
                    produced += 1
                    break
                except BufferError:
                    p.poll(100)  # drain queue, wait for space
        p.poll(0)
        offset += chunk

        # ---- pace if needed ----
        if target_eps > 0:
            wave_elapsed = time.perf_counter() - wave_t0
            expected_wave = chunk / target_eps
            sleep_time = expected_wave - wave_elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

    remaining = p.flush(300)
    elapsed = time.perf_counter() - t0
    return topic, produced - remaining, remaining, elapsed


# ── Pipeline measurement ────────────────────────────────────────────────────


def wait_for_ingestion(ch, table_counts_before: dict, expected: dict,
                       timeout: float = 120) -> dict[str, dict]:
    """Wait until ClickHouse has ingested all expected events. Returns per-table stats."""
    results = {}
    deadline = time.monotonic() + timeout
    pending = dict(expected)

    while pending and time.monotonic() < deadline:
        for table in list(pending.keys()):
            try:
                r = ch.query(f"SELECT count() FROM {table}")
                current = r.result_rows[0][0]
                arrived = current - table_counts_before[table]
                if arrived >= pending[table]:
                    results[table] = {"arrived": arrived, "expected": pending[table]}
                    del pending[table]
            except Exception:
                pass
        if pending:
            time.sleep(0.1)

    # Capture any remaining
    for table, expected_count in pending.items():
        try:
            r = ch.query(f"SELECT count() FROM {table}")
            current = r.result_rows[0][0]
            arrived = current - table_counts_before[table]
        except Exception:
            arrived = 0
        results[table] = {"arrived": arrived, "expected": expected_count}

    return results


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="CLIF Realistic Load Test — LANL Format")
    parser.add_argument("--events", type=int, default=1_000_000,
                        help="Total events to generate (default: 1M)")
    parser.add_argument("--skip-verify", action="store_true",
                        help="Skip ClickHouse verification (produce-only benchmark)")
    parser.add_argument("--redteam-pct", type=float, default=0.05,
                        help="Percentage of auth events that are red-team (default: 0.05%%)")
    parser.add_argument("--workers-per-topic", type=int, default=2,
                        help="Producer processes per topic (default: 2)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Spread production over N seconds (0 = burst mode). "
                             "Use e.g. --duration 300 to pace events over 5 minutes "
                             "for live dashboard graph visibility.")
    args = parser.parse_args()

    total = args.events
    tag = f"lanl-{uuid.uuid4().hex[:8]}"

    print("=" * 72)
    print("  CLIF Realistic Load Test — LANL Cyber Security Format")
    print("=" * 72)
    print(f"  Total events:     {total:>12,}")
    print(f"  Broker:           {BROKER}")
    print(f"  ClickHouse:       {CH_HOST}:{CH_PORT}")
    print(f"  Tag:              {tag}")
    print(f"  Red team rate:    {args.redteam_pct:.2f}%")
    print(f"  Workers/topic:    {args.workers_per_topic}")
    if args.duration > 0:
        print(f"  Duration:         {args.duration}s (paced mode — live dashboard)")
    else:
        print(f"  Duration:         burst (max speed)")
    print()

    # ── Phase 1: Compute event distribution ────────────────────────────
    print("[1/4] Computing event distribution …")
    event_counts: dict[str, int] = {}
    for topic, cfg in TOPIC_CONFIG.items():
        event_counts[topic] = int(total * cfg["weight"])
    actual_total = sum(event_counts.values())

    for topic, count in event_counts.items():
        print(f"        {topic}: {count:>10,} events")
    print(f"      Total: {actual_total:,} events (streaming — no pre-generation)")
    print()

    # ── Phase 2: Snapshot ClickHouse counts before ────────────────────────
    ch = None
    counts_before = {}
    if not args.skip_verify:
        ch = _CHClient(
            host=CH_HOST, port=CH_PORT, username=CH_USER,
            password=CH_PASS, database=CH_DB, connect_timeout=30,
        )
        for cfg in TOPIC_CONFIG.values():
            table = cfg["table"]
            r = ch.query(f"SELECT count() FROM {table}")
            counts_before[table] = r.result_rows[0][0]
        print(f"[2/4] ClickHouse baseline: " +
              "  ".join(f"{t}={c:,}" for t, c in counts_before.items()))
        print()

    # ── Phase 3: Parallel streaming produce ─────────────────────────────
    wpt = args.workers_per_topic
    num_workers = len(TOPIC_CONFIG) * wpt
    mode_label = "paced" if args.duration > 0 else "burst"
    print(f"[3/4] Streaming {actual_total:,} events across {len(TOPIC_CONFIG)} topics "
          f"({num_workers} workers, {mode_label}, multiprocess + orjson + batch-random) \u2026")
    t_produce_start = time.perf_counter()

    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = {}
        for topic in TOPIC_CONFIG:
            total_for_topic = event_counts[topic]
            per_worker = total_for_topic // wpt
            remainder = total_for_topic % wpt
            off = 0
            for w in range(wpt):
                wc = per_worker + (1 if w < remainder else 0)
                fut = pool.submit(
                    _produce_worker, topic, wc, tag, args.redteam_pct, off,
                    args.duration,
                )
                futures[fut] = topic
                off += wc

        # Aggregate per-topic results
        _topic_agg = defaultdict(lambda: {"delivered": 0, "errors": 0, "elapsed": 0.0})
        for fut in as_completed(futures):
            topic, delivered, errors, elapsed = fut.result()
            _topic_agg[topic]["delivered"] += delivered
            _topic_agg[topic]["errors"] += errors
            _topic_agg[topic]["elapsed"] = max(_topic_agg[topic]["elapsed"], elapsed)

        produce_results = dict(_topic_agg)
        for topic, r in produce_results.items():
            rate = r["delivered"] / r["elapsed"] if r["elapsed"] > 0 else 0
            print(f"      {topic:<20s}  {r['delivered']:>10,} delivered  "
                  f"{r['errors']:>3} errors  {r['elapsed']:.2f}s  ({rate:>10,.0f} msg/s)")

    t_produce = time.perf_counter() - t_produce_start
    total_delivered = sum(r["delivered"] for r in produce_results.values())
    total_errors = sum(r["errors"] for r in produce_results.values())
    produce_rate = total_delivered / t_produce if t_produce > 0 else 0

    print(f"\n      TOTAL: {total_delivered:,} delivered | {total_errors} errors | "
          f"{t_produce:.2f}s | {produce_rate:,.0f} events/sec")
    print()

    # ── Record producer EPS to pipeline_metrics for dashboard display ───
    try:
        from urllib.request import urlopen, Request
        from urllib.parse import urlencode
        _ch_http = os.getenv("CH_HTTP_PORT", "8123")
        _qs = urlencode({"user": CH_USER, "password": CH_PASS, "database": CH_DB})
        _sql = f"INSERT INTO clif_logs.pipeline_metrics (metric, value) VALUES ('producer_eps', {produce_rate})"
        _rq = Request(f"http://{CH_HOST}:{_ch_http}/?{_qs}", data=_sql.encode())
        urlopen(_rq, timeout=5)
        print(f"      ✓ Recorded producer EPS ({produce_rate:,.0f}) to pipeline_metrics")
    except Exception as _e:
        print(f"      ⚠ Could not record EPS to pipeline_metrics: {_e}")

    # ── Phase 4: Verify ingestion ─────────────────────────────────────────
    if args.skip_verify:
        print("[4/4] Skipping ClickHouse verification (--skip-verify)")
    else:
        expected_tables = {}
        for cfg in TOPIC_CONFIG.values():
            table = cfg["table"]
            expected_tables[table] = event_counts.get(
                next(t for t, c in TOPIC_CONFIG.items() if c["table"] == table), 0
            )

        print(f"[4/4] Waiting for consumer to ingest {total_delivered:,} events into ClickHouse …")
        t_ingest_start = time.perf_counter()
        ingestion = wait_for_ingestion(ch, counts_before, expected_tables, timeout=180)
        t_ingest = time.perf_counter() - t_ingest_start

        all_arrived = True
        total_arrived = 0
        for table, stats in ingestion.items():
            arrived = stats["arrived"]
            expected = stats["expected"]
            total_arrived += arrived
            pct = (arrived / expected * 100) if expected > 0 else 0
            status = "✓" if arrived >= expected else "✗"
            if arrived < expected:
                all_arrived = False
            print(f"      {status} {table:<20s}  {arrived:>10,}/{expected:>10,}  ({pct:.1f}%)")

        t_e2e = time.perf_counter() - t_produce_start
        e2e_rate = total_arrived / t_e2e if t_e2e > 0 else 0
        consumer_rate = total_arrived / t_ingest if t_ingest > 0 else 0

        print()
        print("─" * 72)
        print("  RESULTS SUMMARY")
        print("─" * 72)
        print(f"  Events generated:     {actual_total:>12,}  (streamed)")
        print(f"  Events delivered:     {total_delivered:>12,}")
        print(f"  Events ingested:      {total_arrived:>12,}")
        print(f"  Delivery errors:      {total_errors:>12}")
        print(f"  Data loss:            {total_delivered - total_arrived:>12,}")
        print()
        print(f"  Produce time:         {t_produce:>12.2f}s  ({produce_rate:>10,.0f} events/sec)")
        print(f"  Ingestion wait:       {t_ingest:>12.2f}s  ({consumer_rate:>10,.0f} events/sec)")
        print(f"  Total E2E time:       {t_e2e:>12.2f}s  ({e2e_rate:>10,.0f} events/sec)")
        print()

        # Red team detection check
        try:
            r = ch.query(
                "SELECT count() FROM security_events "
                "WHERE ai_confidence > 0.5 AND metadata['request_id'] = {tag:String}",
                parameters={"tag": tag},
            )
            redteam_count = r.result_rows[0][0]
            print(f"  Red team events:      {redteam_count:>12,}  "
                  f"(injected at {args.redteam_pct:.2f}% rate)")
        except Exception:
            pass

        print("─" * 72)

        if not all_arrived:
            print("\n  ⚠  Some events did not arrive within timeout!")
            print("     This may indicate consumer backlog — check consumer logs.")
            sys.exit(1)
        else:
            print(f"\n  ✓  All {total_arrived:,} events ingested successfully.")

        ch.close()


if __name__ == "__main__":
    main()
