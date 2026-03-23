"""Quick test: run inside triage container to reproduce dimension mismatch."""
import json, numpy as np
from feature_extractor import FeatureExtractor, FEATURE_NAMES
from drain3_miner import Drain3Miner
from model_ensemble import ModelEnsemble

dm = Drain3Miner()
ext = FeatureExtractor(drain3_miner=dm)

# Test events matching validation script format
events = [
    {
        "event_id": "test-fw-1",
        "clif_event_type": "security",
        "timestamp": "2025-06-04T11:35:00+00:00",
        "severity": 3,
        "category": "firewall",
        "source": "fw-01",
        "description": "Firewall alert: Exploits - 175.45.176.3:29090 -> 149.171.126.2:21 proto=UDP service=dns state=INT bytes_sent=24 bytes_recv=0",
        "user_id": "",
        "ip_address": "175.45.176.3",
        "hostname": "gt2-test",
        "mitre_tactic": "lateral-movement",
        "mitre_technique": "T1021",
        "ai_confidence": 0.0,
        "message_body": "Firewall alert: Exploits - 175.45.176.3:29090 -> 149.171.126.2:21 proto=UDP service=dns state=INT bytes_sent=24 bytes_recv=0",
        "source_type": "firewall",
        "original_log_level": 3,
        "metadata": {},
    },
    {
        "event_id": "test-ids-1",
        "clif_event_type": "security",
        "timestamp": "2025-06-04T11:35:01+00:00",
        "severity": 1,
        "category": "network",
        "source": "ids-01",
        "description": "IDS: normal traffic - proto=TCP service=http flag=SF duration=0s src=172.16.1.1 dst=10.10.1.1",
        "user_id": "",
        "ip_address": "172.16.1.1",
        "hostname": "gt2-test",
        "mitre_tactic": "",
        "mitre_technique": "",
        "ai_confidence": 0.0,
        "message_body": "IDS: normal traffic - proto=TCP service=http flag=SF duration=0s src=172.16.1.1 dst=10.10.1.1",
        "source_type": "ids_ips",
        "original_log_level": 0,
        "metadata": {},
    },
]

# Feature extraction
features_list = []
for ev in events:
    feat = ext.extract(ev, "security-events")
    features_list.append(feat)
    print(f"  Event {ev['event_id']}: {len([k for k in feat if not k.startswith('_')])} non-meta features")

# batch_to_numpy
X = ext.batch_to_numpy(features_list)
print(f"\nX shape from batch_to_numpy: {X.shape}")
print(f"X dtype: {X.dtype}")
print(f"FEATURE_NAMES count: {len(FEATURE_NAMES)}")

# Load ensemble  
print("\nLoading ensemble...")
me = ModelEnsemble()
me.load()
print(f"Ensemble feature_cols: {len(me.feature_cols)}")

# Full predict
print("\nRunning predict_batch...")
try:
    scores = me.predict_batch(X)
    print(f"  lgbm: {scores['lgbm']}")
    print(f"  eif: {scores['eif']}")
    print(f"  arf: {scores['arf']}")
    print("SUCCESS!")
except Exception as e:
    print(f"FAILED: {e}")

# Also test what the LightGBM ONNX gets directly
print(f"\nDirect LightGBM test:")
print(f"  X shape going to ONNX: {X.shape}")
try:
    lgbm_out = me._lgbm.predict_batch(X)
    print(f"  LightGBM output: {lgbm_out}")
    print("  LightGBM OK!")
except Exception as e:
    print(f"  LightGBM FAILED: {e}")
