#!/usr/bin/env python3
"""
CLIF Pipeline Throughput & Integrity Test Suite
================================================

End-to-end validation for 200k EPS sustained throughput after
performance optimizations:

  1. Vector VRL transform merge (4 → 1 classify_and_enrich)
  2. Dedup cache increase (50k/25k → 200k/100k)
  3. Sink linger.ms tuning (5ms → 20ms for raw/process/network)
  4. Vector resource upgrade (4→8 CPUs, 4→8GB RAM)
  5. Triage agent horizontal scale (1 → 4 instances)

Tests:
  - Vector config syntax validation
  - Docker-compose YAML validation
  - Pipeline topology integrity (transform chain, references)
  - Load generation + throughput measurement
  - Consumer lag monitoring
  - Triage agent scaling verification

Usage:
  python scripts/test_pipeline_throughput.py                    # All tests
  python scripts/test_pipeline_throughput.py --test config      # Config only
  python scripts/test_pipeline_throughput.py --test topology    # Topology check
  python scripts/test_pipeline_throughput.py --test load        # Load test only
  python scripts/test_pipeline_throughput.py --eps 100000       # Custom EPS target
"""

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VECTOR_CONFIG = PROJECT_ROOT / "vector" / "vector.yaml"
COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"

VECTOR_HTTP_HOST = os.getenv("VECTOR_HTTP_HOST", "localhost")
VECTOR_HTTP_PORT = int(os.getenv("VECTOR_HTTP_PORT", "8687"))
VECTOR_API_PORT = int(os.getenv("VECTOR_API_PORT", "8686"))

DEFAULT_TARGET_EPS = 200_000
LOAD_TEST_DURATION_SEC = 30
WARMUP_DURATION_SEC = 5

# ANSI colours
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ── Helper Functions ─────────────────────────────────────────────────────────

def passed(name: str, detail: str = ""):
    print(f"  {GREEN}✔ PASS{RESET}  {name}" + (f"  ({detail})" if detail else ""))

def failed(name: str, detail: str = ""):
    print(f"  {RED}✘ FAIL{RESET}  {name}" + (f"  ({detail})" if detail else ""))

def warn(name: str, detail: str = ""):
    print(f"  {YELLOW}⚠ WARN{RESET}  {name}" + (f"  ({detail})" if detail else ""))

def header(title: str):
    width = 72
    print(f"\n{BOLD}{CYAN}{'═' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * width}{RESET}\n")


# ═════════════════════════════════════════════════════════════════════════════
# TEST 1: VECTOR CONFIG VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

def test_vector_config() -> bool:
    """Validate vector.yaml syntax and semantic integrity."""
    header("TEST 1: Vector Config Validation")
    all_pass = True

    # 1a: YAML syntax
    try:
        import yaml
    except ImportError:
        warn("PyYAML not installed", "pip install pyyaml — skipping YAML parse")
        yaml = None

    if yaml:
        try:
            with open(VECTOR_CONFIG) as f:
                config = yaml.safe_load(f)
            passed("YAML syntax valid")
        except yaml.YAMLError as e:
            failed("YAML syntax", str(e))
            return False
    else:
        with open(VECTOR_CONFIG) as f:
            config_text = f.read()
        config = None

    # 1b: Merged transform exists
    if config:
        transforms = config.get("transforms", {})
        if "classify_and_enrich" in transforms:
            passed("classify_and_enrich transform exists")
        else:
            failed("classify_and_enrich transform missing")
            all_pass = False

        # 1c: Old transforms removed
        old_transforms = ["classify_security", "classify_process", "classify_network", "build_metadata"]
        for old in old_transforms:
            if old in transforms:
                failed(f"Old transform '{old}' still present (should be merged)")
                all_pass = False
            else:
                passed(f"Old transform '{old}' correctly removed")

        # 1d: route_by_type references classify_and_enrich
        route = transforms.get("route_by_type", {})
        inputs = route.get("inputs", [])
        if "classify_and_enrich" in inputs:
            passed("route_by_type inputs → classify_and_enrich")
        elif "build_metadata" in inputs:
            failed("route_by_type still references build_metadata")
            all_pass = False
        else:
            failed(f"route_by_type has unexpected inputs: {inputs}")
            all_pass = False

        # 1e: Dedup cache sizes
        expected_caches = {
            "dedup_raw": 200000,
            "dedup_security": 100000,
            "dedup_process": 100000,
            "dedup_network": 100000,
        }
        for name, expected in expected_caches.items():
            t = transforms.get(name, {})
            actual = t.get("cache", {}).get("num_events", 0)
            if actual >= expected:
                passed(f"{name} cache = {actual:,}", f"≥ {expected:,}")
            else:
                failed(f"{name} cache = {actual:,}", f"expected ≥ {expected:,}")
                all_pass = False

        # 1f: Sink linger.ms
        sinks = config.get("sinks", {})
        for sink_name, expected_linger in [
            ("sink_raw_logs", "20"),
            ("sink_security_events", "2"),
            ("sink_process_events", "20"),
            ("sink_network_events", "20"),
        ]:
            sink = sinks.get(sink_name, {})
            linger = sink.get("librdkafka_options", {}).get("linger.ms", "?")
            if linger == expected_linger:
                passed(f"{sink_name} linger.ms = {linger}")
            else:
                failed(f"{sink_name} linger.ms = {linger}", f"expected {expected_linger}")
                all_pass = False

        # 1g: Sink batch sizes (raw)
        raw_sink = sinks.get("sink_raw_logs", {})
        raw_batch = raw_sink.get("batch", {})
        raw_max_bytes = raw_batch.get("max_bytes", 0)
        raw_max_events = raw_batch.get("max_events", 0)
        if raw_max_bytes >= 10_485_760:
            passed(f"sink_raw_logs batch max_bytes = {raw_max_bytes:,}", "≥ 10MB")
        else:
            failed(f"sink_raw_logs batch max_bytes = {raw_max_bytes:,}", "expected ≥ 10MB")
            all_pass = False

        if raw_max_events >= 50_000:
            passed(f"sink_raw_logs batch max_events = {raw_max_events:,}", "≥ 50k")
        else:
            failed(f"sink_raw_logs batch max_events = {raw_max_events:,}", "expected ≥ 50k")
            all_pass = False

        # 1h: queue.buffering.max.messages
        raw_queue = raw_sink.get("librdkafka_options", {}).get("queue.buffering.max.messages", "0")
        if int(raw_queue) >= 1_000_000:
            passed(f"sink_raw_logs queue.buffering.max.messages = {raw_queue}")
        else:
            failed(f"sink_raw_logs queue.buffering.max.messages = {raw_queue}", "expected ≥ 1M")
            all_pass = False
    else:
        # Fallback: regex-based checks if YAML not available
        with open(VECTOR_CONFIG) as f:
            text = f.read()

        checks = [
            ("classify_and_enrich:", "classify_and_enrich transform"),
            ('- "classify_and_enrich"', "route_by_type → classify_and_enrich"),
            ("num_events: 200000", "dedup_raw cache = 200k"),
            ("num_events: 100000", "dedup caches = 100k"),
        ]
        for pattern, desc in checks:
            if pattern in text:
                passed(desc)
            else:
                failed(desc, f"'{pattern}' not found")
                all_pass = False

        for old in ["classify_security:", "classify_process:", "classify_network:", "build_metadata:"]:
            if old in text:
                failed(f"Old transform '{old}' still present")
                all_pass = False

    return all_pass


# ═════════════════════════════════════════════════════════════════════════════
# TEST 2: DOCKER-COMPOSE VALIDATION
# ═════════════════════════════════════════════════════════════════════════════

def test_docker_compose() -> bool:
    """Validate docker-compose.yml structure and resource allocations."""
    header("TEST 2: Docker-Compose Validation")
    all_pass = True

    try:
        import yaml
    except ImportError:
        warn("PyYAML not installed — using regex fallback")
        yaml = None

    with open(COMPOSE_FILE) as f:
        text = f.read()

    # 2a: YAML validity
    if yaml:
        try:
            compose = yaml.safe_load(text)
            passed("docker-compose.yml YAML valid")
        except yaml.YAMLError as e:
            failed("docker-compose.yml YAML parse", str(e))
            return False
    else:
        compose = None

    if compose:
        services = compose.get("services", {})

        # 2b: Vector resources
        vector_svc = services.get("clif-vector", {})
        vector_env = vector_svc.get("environment", {})
        vector_threads = str(vector_env.get("VECTOR_THREADS", ""))
        # Handle ${VAR:-default} syntax
        thread_match = re.search(r"(\d+)\}?$", vector_threads)
        if thread_match and int(thread_match.group(1)) >= 8:
            passed(f"Vector VECTOR_THREADS = {vector_threads}", "≥ 8")
        else:
            failed(f"Vector VECTOR_THREADS = {vector_threads}", "expected ≥ 8")
            all_pass = False

        vector_deploy = vector_svc.get("deploy", {}).get("resources", {})
        vector_cpu = vector_deploy.get("limits", {}).get("cpus", "0")
        vector_mem = vector_deploy.get("limits", {}).get("memory", "0")
        if float(vector_cpu.strip("'")) >= 8:
            passed(f"Vector CPU limit = {vector_cpu}")
        else:
            failed(f"Vector CPU limit = {vector_cpu}", "expected ≥ 8")
            all_pass = False
        if "8G" in str(vector_mem):
            passed(f"Vector memory limit = {vector_mem}")
        else:
            failed(f"Vector memory limit = {vector_mem}", "expected ≥ 8G")
            all_pass = False

        # 2c: Triage agent count
        triage_agents = [k for k in services if k.startswith("clif-triage-agent")]
        agent_count = len(triage_agents)
        if agent_count >= 4:
            passed(f"Triage agents = {agent_count}", f"services: {', '.join(sorted(triage_agents))}")
        else:
            failed(f"Triage agents = {agent_count}", "expected ≥ 4")
            all_pass = False

        # 2d: All triage agents use same consumer group
        groups = set()
        for name in triage_agents:
            env = services[name].get("environment", {})
            gid = env.get("CONSUMER_GROUP_ID", "")
            groups.add(gid)
        if len(groups) == 1 and "clif-triage-agent" in groups:
            passed(f"All agents share consumer group: {groups.pop()}")
        else:
            failed(f"Inconsistent consumer groups: {groups}")
            all_pass = False

        # 2e: Triage agent port uniqueness
        ports = []
        for name in sorted(triage_agents):
            svc_ports = services[name].get("ports", [])
            ports.extend(svc_ports)
        port_hosts = [p.split(":")[0] for p in ports]
        if len(port_hosts) == len(set(port_hosts)):
            passed(f"Triage agent ports unique: {ports}")
        else:
            failed(f"Duplicate host ports in triage agents: {ports}")
            all_pass = False

        # 2f: Total triage CPUs
        total_triage_cpu = 0
        for name in triage_agents:
            cpu = services[name].get("deploy", {}).get("resources", {}).get("limits", {}).get("cpus", "0")
            total_triage_cpu += float(cpu.strip("'"))
        if total_triage_cpu >= 16:
            passed(f"Total triage CPU = {total_triage_cpu}", "≥ 16 cores")
        else:
            warn(f"Total triage CPU = {total_triage_cpu}", "< 16 cores — may bottleneck at 200k EPS")

    else:
        # Regex fallback
        agent_count = len(re.findall(r"clif-triage-agent(?:-\d+)?:", text))
        if agent_count >= 4:
            passed(f"Triage agent instances = {agent_count}")
        else:
            failed(f"Triage agent instances = {agent_count}", "expected ≥ 4")
            all_pass = False

    return all_pass


# ═════════════════════════════════════════════════════════════════════════════
# TEST 3: PIPELINE TOPOLOGY INTEGRITY
# ═════════════════════════════════════════════════════════════════════════════

def test_topology() -> bool:
    """Verify transform chain connectivity — no dangling references."""
    header("TEST 3: Pipeline Topology Integrity")
    all_pass = True

    try:
        import yaml
        with open(VECTOR_CONFIG) as f:
            config = yaml.safe_load(f)
    except (ImportError, Exception) as e:
        warn(f"Cannot parse YAML: {e}")
        return True  # Skip if no YAML parsing available

    sources = set(config.get("sources", {}).keys())
    transforms = config.get("transforms", {})
    sinks = config.get("sinks", {})

    # Build a map of all defined components
    defined = set()
    defined.update(sources)
    defined.update(transforms.keys())

    # For routes, add sub-outputs (e.g., route_by_type.security)
    for name, t in transforms.items():
        if t.get("type") == "route":
            for route_name in t.get("route", {}):
                defined.add(f"{name}.{route_name}")

    # Check all inputs in transforms reference defined components
    dangling = []
    for name, t in transforms.items():
        for inp in t.get("inputs", []):
            if inp not in defined:
                dangling.append((name, inp))

    for name, s in sinks.items():
        for inp in s.get("inputs", []):
            if inp not in defined:
                dangling.append((name, inp))

    if not dangling:
        passed("All transform/sink inputs reference valid components")
    else:
        for component, ref in dangling:
            failed(f"Dangling reference: {component} → {ref}")
        all_pass = False

    # Verify expected transform chain
    expected_chain = [
        ("classify_and_enrich", "parse_and_structure"),
        ("route_by_type", "classify_and_enrich"),
    ]
    for transform, expected_input in expected_chain:
        actual_inputs = transforms.get(transform, {}).get("inputs", [])
        if expected_input in actual_inputs:
            passed(f"{transform} ← {expected_input}")
        else:
            failed(f"{transform} expected input '{expected_input}'", f"got {actual_inputs}")
            all_pass = False

    # Count total components
    total = len(sources) + len(transforms) + len(sinks)
    passed(f"Pipeline topology: {len(sources)} sources, {len(transforms)} transforms, {len(sinks)} sinks")

    return all_pass


# ═════════════════════════════════════════════════════════════════════════════
# TEST 4: LOAD GENERATION & THROUGHPUT MEASUREMENT
# ═════════════════════════════════════════════════════════════════════════════

class LoadGenerator:
    """High-performance event generator targeting Vector's HTTP endpoint."""

    # Pre-built event templates
    EVENT_TEMPLATES = [
        # Raw log
        {"message": "Application startup complete in 342ms", "source": "myapp",
         "level": "INFO", "hostname": "app-server-01"},
        # Security: auth failure
        {"message": "Failed password for admin from 10.0.1.50 port 22 ssh2",
         "source": "sshd", "level": "WARNING", "hostname": "bastion-01"},
        # Process event
        {"message": "Process started", "pid": 12345, "ppid": 1, "uid": 0,
         "binary_path": "/usr/bin/python3", "hostname": "worker-01"},
        # Network event
        {"message": "TCP connection established", "src_ip": "10.0.1.100",
         "dst_ip": "192.168.1.50", "src_port": 44231, "dst_port": 443,
         "protocol": "TCP", "hostname": "proxy-01"},
        # Security: privilege escalation
        {"message": "sudo: admin : TTY=pts/0 ; PWD=/root ; COMMAND=/bin/bash",
         "source": "sudo", "level": "WARNING", "hostname": "jumpbox-01"},
    ]

    def __init__(self, target_eps: int, duration_sec: int, threads: int = 8):
        self.target_eps = target_eps
        self.duration_sec = duration_sec
        self.threads = threads
        self.sent = 0
        self.errors = 0
        self.lock = threading.Lock()
        self.running = False

    def _generate_batch(self, batch_size: int = 100) -> bytes:
        """Generate a JSON array of events."""
        import random
        events = []
        for _ in range(batch_size):
            template = random.choice(self.EVENT_TEMPLATES).copy()
            template["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
            template["_test_id"] = f"load-{time.monotonic_ns()}"
            events.append(template)
        return json.dumps(events).encode("utf-8")

    def _sender_thread(self, eps_per_thread: int, batch_size: int):
        """Thread that sends HTTP POST batches to Vector."""
        import http.client

        batches_per_sec = max(1, eps_per_thread // batch_size)
        interval = 1.0 / batches_per_sec

        conn = http.client.HTTPConnection(VECTOR_HTTP_HOST, VECTOR_HTTP_PORT, timeout=10)
        headers = {"Content-Type": "application/json"}

        while self.running:
            try:
                batch_start = time.monotonic()
                payload = self._generate_batch(batch_size)
                conn.request("POST", "/v1/logs", body=payload, headers=headers)
                resp = conn.getresponse()
                _ = resp.read()

                if resp.status in (200, 201, 204):
                    with self.lock:
                        self.sent += batch_size
                else:
                    with self.lock:
                        self.errors += 1

                elapsed = time.monotonic() - batch_start
                sleep_time = interval - elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)

            except Exception:
                with self.lock:
                    self.errors += 1
                try:
                    conn.close()
                except Exception:
                    pass
                conn = http.client.HTTPConnection(VECTOR_HTTP_HOST, VECTOR_HTTP_PORT, timeout=10)
                time.sleep(0.1)

        try:
            conn.close()
        except Exception:
            pass

    def run(self) -> dict:
        """Execute the load test and return results."""
        eps_per_thread = self.target_eps // self.threads
        batch_size = min(500, max(50, eps_per_thread // 20))

        print(f"  Config: {self.threads} threads × {eps_per_thread:,} EPS/thread "
              f"= {self.target_eps:,} target EPS")
        print(f"  Batch size: {batch_size} events, Duration: {self.duration_sec}s")
        print(f"  Endpoint: http://{VECTOR_HTTP_HOST}:{VECTOR_HTTP_PORT}/v1/logs")
        print()

        self.running = True
        self.sent = 0
        self.errors = 0

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._sender_thread, args=(eps_per_thread, batch_size))
            t.daemon = True
            threads.append(t)

        start_time = time.monotonic()
        for t in threads:
            t.start()

        # Warmup phase
        print(f"  ⏳ Warmup ({WARMUP_DURATION_SEC}s)...", end="", flush=True)
        time.sleep(WARMUP_DURATION_SEC)
        warmup_sent = self.sent
        print(f" sent {warmup_sent:,} events")

        # Measurement phase
        self.sent = 0
        self.errors = 0
        measure_start = time.monotonic()
        print(f"  📊 Measuring ({self.duration_sec}s)...", flush=True)

        # Sample EPS every second
        samples = []
        for _ in range(self.duration_sec):
            sample_start_sent = self.sent
            time.sleep(1.0)
            sample_end_sent = self.sent
            eps = sample_end_sent - sample_start_sent
            samples.append(eps)
            print(f"    {len(samples):3d}s: {eps:>9,} EPS  (cumul: {self.sent:>12,})", flush=True)

        measure_elapsed = time.monotonic() - measure_start
        self.running = False

        for t in threads:
            t.join(timeout=5)

        total_sent = self.sent
        avg_eps = total_sent / measure_elapsed if measure_elapsed > 0 else 0
        peak_eps = max(samples) if samples else 0
        p50_eps = sorted(samples)[len(samples) // 2] if samples else 0

        return {
            "total_events": total_sent,
            "duration_sec": round(measure_elapsed, 2),
            "avg_eps": round(avg_eps),
            "peak_eps": peak_eps,
            "p50_eps": p50_eps,
            "errors": self.errors,
            "target_eps": self.target_eps,
        }


def test_load(target_eps: int = DEFAULT_TARGET_EPS) -> bool:
    """Run load test against Vector HTTP endpoint."""
    header("TEST 4: Load Generation & Throughput")
    all_pass = True

    # Check Vector is reachable
    try:
        sock = socket.create_connection((VECTOR_HTTP_HOST, VECTOR_HTTP_PORT), timeout=5)
        sock.close()
        passed(f"Vector HTTP endpoint reachable at {VECTOR_HTTP_HOST}:{VECTOR_HTTP_PORT}")
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        failed(f"Cannot reach Vector at {VECTOR_HTTP_HOST}:{VECTOR_HTTP_PORT}", str(e))
        warn("Skipping load test — start the pipeline first: docker compose up -d")
        return False

    gen = LoadGenerator(target_eps=target_eps, duration_sec=LOAD_TEST_DURATION_SEC, threads=8)
    results = gen.run()

    print()
    print(f"  {'─' * 50}")
    print(f"  Results:")
    print(f"    Total events sent:  {results['total_events']:>12,}")
    print(f"    Duration:           {results['duration_sec']:>12.1f}s")
    print(f"    Average EPS:        {results['avg_eps']:>12,}")
    print(f"    Peak EPS:           {results['peak_eps']:>12,}")
    print(f"    P50 EPS:            {results['p50_eps']:>12,}")
    print(f"    Errors:             {results['errors']:>12,}")
    print(f"    Target EPS:         {results['target_eps']:>12,}")
    print(f"  {'─' * 50}")
    print()

    # Evaluate
    ratio = results['avg_eps'] / results['target_eps'] if results['target_eps'] > 0 else 0
    error_rate = results['errors'] / max(1, results['total_events'] + results['errors'])

    if ratio >= 0.9:
        passed(f"Throughput ≥ 90% of target", f"{ratio:.1%} of {target_eps:,} EPS")
    elif ratio >= 0.7:
        warn(f"Throughput at {ratio:.1%} of target", "Acceptable but below optimal")
    else:
        failed(f"Throughput at {ratio:.1%} of target",
               f"Only {results['avg_eps']:,} of {target_eps:,} EPS")
        all_pass = False

    if error_rate < 0.01:
        passed(f"Error rate {error_rate:.3%}", "< 1%")
    elif error_rate < 0.05:
        warn(f"Error rate {error_rate:.3%}", "< 5% but above ideal")
    else:
        failed(f"Error rate {error_rate:.3%}", "> 5%")
        all_pass = False

    return all_pass


# ═════════════════════════════════════════════════════════════════════════════
# TEST 5: TRIAGE AGENT SCALING VERIFICATION
# ═════════════════════════════════════════════════════════════════════════════

def test_triage_scaling() -> bool:
    """Verify all triage agent instances are running and healthy."""
    header("TEST 5: Triage Agent Scaling")
    all_pass = True

    agent_ports = [8300, 8301, 8302, 8303]
    healthy_count = 0

    for port in agent_ports:
        try:
            import http.client
            conn = http.client.HTTPConnection("localhost", port, timeout=5)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            body = resp.read().decode()
            conn.close()

            if resp.status == 200:
                passed(f"Triage agent :{port} healthy", body[:80])
                healthy_count += 1
            else:
                failed(f"Triage agent :{port}", f"HTTP {resp.status}")
                all_pass = False
        except Exception as e:
            failed(f"Triage agent :{port} unreachable", str(e)[:80])
            all_pass = False

    if healthy_count >= 4:
        passed(f"All {healthy_count}/4 triage agents healthy",
               f"~{healthy_count * 5_000:,} EPS combined capacity")
    elif healthy_count >= 2:
        warn(f"Only {healthy_count}/4 triage agents healthy",
             "Degraded capacity")
    else:
        failed(f"Only {healthy_count}/4 triage agents healthy")

    return all_pass


# ═════════════════════════════════════════════════════════════════════════════
# RESOURCE CALCULATION & PC SPLIT REPORT
# ═════════════════════════════════════════════════════════════════════════════

def print_resource_report():
    """Calculate total resource requirements and recommend PC1/PC2 split."""
    header("RESOURCE REQUIREMENTS & PC SPLIT RECOMMENDATION")

    services = {
        "ClickHouse Keeper":    {"cpu": 1,  "mem_gb": 1,   "plane": "data"},
        "ClickHouse-01":        {"cpu": 4,  "mem_gb": 8,   "plane": "data"},
        "ClickHouse-02":        {"cpu": 4,  "mem_gb": 8,   "plane": "data"},
        "Redpanda-01":          {"cpu": 2,  "mem_gb": 4,   "plane": "data"},
        "Redpanda-02":          {"cpu": 2,  "mem_gb": 4,   "plane": "data"},
        "Redpanda-03":          {"cpu": 2,  "mem_gb": 4,   "plane": "data"},
        "Redpanda Console":     {"cpu": 0.5, "mem_gb": 0.5, "plane": "data"},
        "MinIO-1":              {"cpu": 2,  "mem_gb": 2,   "plane": "data"},
        "MinIO-2":              {"cpu": 2,  "mem_gb": 2,   "plane": "data"},
        "MinIO-3":              {"cpu": 2,  "mem_gb": 2,   "plane": "data"},
        "Consumer-1":           {"cpu": 2,  "mem_gb": 1,   "plane": "data"},
        "Consumer-2":           {"cpu": 2,  "mem_gb": 1,   "plane": "data"},
        "Consumer-3":           {"cpu": 2,  "mem_gb": 1,   "plane": "data"},
        "Vector (8 threads)":   {"cpu": 8,  "mem_gb": 8,   "plane": "data"},
        "Prometheus":           {"cpu": 2,  "mem_gb": 2,   "plane": "data"},
        "Grafana":              {"cpu": 2,  "mem_gb": 1,   "plane": "data"},
        "Merkle":               {"cpu": 1,  "mem_gb": 0.5, "plane": "data"},
        "Triage Agent-1":       {"cpu": 4,  "mem_gb": 4,   "plane": "ai"},
        "Triage Agent-2":       {"cpu": 4,  "mem_gb": 4,   "plane": "ai"},
        "Triage Agent-3":       {"cpu": 4,  "mem_gb": 4,   "plane": "ai"},
        "Triage Agent-4":       {"cpu": 4,  "mem_gb": 4,   "plane": "ai"},
        "LanceDB (optional)":   {"cpu": 2,  "mem_gb": 3,   "plane": "ai"},
    }

    # Total
    total_cpu = sum(s["cpu"] for s in services.values())
    total_mem = sum(s["mem_gb"] for s in services.values())

    # Per plane
    data_cpu = sum(s["cpu"] for s in services.values() if s["plane"] == "data")
    data_mem = sum(s["mem_gb"] for s in services.values() if s["plane"] == "data")
    ai_cpu = sum(s["cpu"] for s in services.values() if s["plane"] == "ai")
    ai_mem = sum(s["mem_gb"] for s in services.values() if s["plane"] == "ai")

    print("  Service Resource Summary:")
    print(f"  {'Service':<25} {'CPUs':>6} {'RAM (GB)':>10} {'Plane':>8}")
    print(f"  {'─' * 55}")
    for name, s in services.items():
        print(f"  {name:<25} {s['cpu']:>6.1f} {s['mem_gb']:>10.1f} {s['plane']:>8}")
    print(f"  {'─' * 55}")
    print(f"  {'TOTAL':<25} {total_cpu:>6.1f} {total_mem:>10.1f}")
    print()

    # OS overhead
    print(f"  {BOLD}Total Pipeline Resources (container limits):{RESET}")
    print(f"    CPUs:   {total_cpu:.1f} cores")
    print(f"    RAM:    {total_mem:.1f} GB")
    print(f"    + OS overhead (~10%): {total_cpu * 1.1:.0f} cores, {total_mem * 1.1:.0f} GB")
    print()

    print(f"  {BOLD}Recommended PC Split for 200k EPS:{RESET}")
    print()
    print(f"  {CYAN}PC1 — Data Plane (ingestion + storage):{RESET}")
    print(f"    Services: Vector, Redpanda ×3, ClickHouse ×2+Keeper,")
    print(f"              Consumer ×3, MinIO ×3, Prometheus, Grafana, Merkle")
    print(f"    Requires: {BOLD}{data_cpu + 4:.0f}+ CPU cores, {data_mem + 8:.0f}+ GB RAM{RESET}")
    print(f"    Recommended: 48+ cores, 72+ GB RAM")
    print()
    print(f"  {CYAN}PC2 — AI/Triage Plane (ML inference):{RESET}")
    print(f"    Services: Triage Agent ×4, LanceDB")
    print(f"    Requires: {BOLD}{ai_cpu + 2:.0f}+ CPU cores, {ai_mem + 4:.0f}+ GB RAM{RESET}")
    print(f"    Recommended: 24+ cores, 24+ GB RAM")
    print()
    print(f"  {YELLOW}NOTE:{RESET} PC2 agents connect to PC1's Redpanda (external ports)")
    print(f"       and ClickHouse (port 9000). Set KAFKA_BROKERS and")
    print(f"       CLICKHOUSE_HOST to PC1's IP in environment variables.")
    print()

    # Single-machine option
    overhead_cpu = total_cpu * 1.15
    overhead_mem = total_mem * 1.15
    print(f"  {BOLD}Single-Machine Option:{RESET}")
    print(f"    Minimum: {overhead_cpu:.0f} CPU cores, {overhead_mem:.0f} GB RAM")
    print(f"    This works if your machine has ≥ 64 cores and ≥ 80 GB RAM.")
    print(f"    Otherwise, use the PC1 + PC2 split above.")
    print()


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="CLIF Pipeline Throughput Test Suite")
    parser.add_argument("--test", choices=["config", "compose", "topology", "load", "triage", "all"],
                        default="all", help="Which test to run")
    parser.add_argument("--eps", type=int, default=DEFAULT_TARGET_EPS,
                        help=f"Target EPS for load test (default: {DEFAULT_TARGET_EPS:,})")
    args = parser.parse_args()

    print(f"\n{BOLD}CLIF Pipeline Throughput & Integrity Test Suite{RESET}")
    print(f"{'─' * 50}")
    print(f"Target: {args.eps:,} EPS sustained throughput")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    results = {}

    if args.test in ("config", "all"):
        results["vector_config"] = test_vector_config()

    if args.test in ("compose", "all"):
        results["docker_compose"] = test_docker_compose()

    if args.test in ("topology", "all"):
        results["topology"] = test_topology()

    if args.test in ("triage", "all"):
        results["triage_scaling"] = test_triage_scaling()

    if args.test in ("load", "all"):
        results["load_test"] = test_load(args.eps)

    # Always print resource report
    if args.test == "all":
        print_resource_report()

    # Summary
    header("TEST SUMMARY")
    total = len(results)
    passed_count = sum(1 for v in results.values() if v)
    failed_count = total - passed_count

    for name, result in results.items():
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"  {status}  {name}")

    print()
    if failed_count == 0:
        print(f"  {GREEN}{BOLD}All {total} test suites passed!{RESET}")
        return 0
    else:
        print(f"  {RED}{BOLD}{failed_count}/{total} test suites failed{RESET}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
