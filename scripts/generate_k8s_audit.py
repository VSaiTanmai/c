"""
Generate synthetic Kubernetes audit logs for CLIF training.
Produces realistic k8s API server audit events covering:
  - Normal: pod lifecycle, config reads, health probes, service ops
  - Attack: privilege escalation, secrets theft, container escape, RBAC abuse

Output: k8s_audit_training.csv  (labeled, ready for preprocessing)
"""
import csv
import json
import random
import os
from datetime import datetime, timedelta

random.seed(42)

OUT_DIR = r"C:\CLIF\agents\Data\Latest_Dataset\07_Kubernetes"
OUT_FILE = os.path.join(OUT_DIR, "k8s_audit_training.csv")

# ── Vocabularies ──────────────────────────────────────────────────

NORMAL_USERS = [
    "system:serviceaccount:kube-system:coredns",
    "system:serviceaccount:kube-system:kube-proxy",
    "system:serviceaccount:default:default",
    "system:serviceaccount:monitoring:prometheus",
    "system:serviceaccount:monitoring:grafana",
    "system:serviceaccount:ingress:nginx-ingress",
    "system:serviceaccount:cert-manager:cert-manager",
    "system:node:node-01", "system:node:node-02", "system:node:node-03",
    "system:kube-scheduler", "system:kube-controller-manager",
    "developer-alice", "developer-bob", "developer-carol",
    "ci-pipeline", "argocd-application-controller",
]

ATTACK_USERS = [
    "compromised-pod-sa", "attacker-shell", "anonymous",
    "system:serviceaccount:default:default",  # abused default SA
    "developer-alice",  # compromised dev account
]

NORMAL_GROUPS = [
    '["system:serviceaccounts","system:authenticated"]',
    '["system:nodes","system:authenticated"]',
    '["system:authenticated"]',
    '["dev-team","system:authenticated"]',
]

ADMIN_GROUPS = [
    '["system:masters","system:authenticated"]',
]

NAMESPACES = [
    "default", "kube-system", "kube-public", "monitoring",
    "production", "staging", "ingress", "cert-manager", "logging",
]

NORMAL_RESOURCES = ["pods", "services", "endpoints", "configmaps",
                    "deployments", "replicasets", "namespaces",
                    "events", "nodes", "leases", "serviceaccounts"]

SENSITIVE_RESOURCES = ["secrets", "clusterroles", "clusterrolebindings",
                       "rolebindings", "roles", "pods/exec",
                       "persistentvolumes", "tokenreviews",
                       "certificatesigningrequests"]

NORMAL_VERBS = ["get", "list", "watch", "create", "update", "patch", "delete"]
SAFE_VERBS = ["get", "list", "watch"]
WRITE_VERBS = ["create", "update", "patch", "delete"]

USER_AGENTS = [
    "kubectl/v1.28.2 (linux/amd64)",
    "kubectl/v1.27.4 (darwin/arm64)",
    "kube-scheduler/v1.28.2",
    "kube-controller-manager/v1.28.2",
    "kubelet/v1.28.2",
    "Go-http-client/2.0",
    "argocd/v2.8.0",
    "prometheus/2.47.0",
]

ATTACK_USER_AGENTS = [
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "kubectl/v1.28.2 (linux/amd64)",  # stolen kubectl
]

# ── Event generators ────────────────────────────────────────────

def ts_str(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def gen_normal_event(dt):
    """Generate a normal K8s audit event."""
    user = random.choice(NORMAL_USERS)
    groups = random.choice(NORMAL_GROUPS)
    resource = random.choice(NORMAL_RESOURCES)
    namespace = random.choice(NAMESPACES)
    verb = random.choice(NORMAL_VERBS)
    # Bias toward read operations
    if random.random() < 0.7:
        verb = random.choice(SAFE_VERBS)
    code = 200
    if verb == "create":
        code = 201
    elif verb == "delete":
        code = random.choice([200, 200, 200, 404])  # occasional 404
    if random.random() < 0.03:
        code = random.choice([403, 404, 409, 422])  # rare errors
    ua = random.choice(USER_AGENTS)
    src_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    return {
        "timestamp": ts_str(dt),
        "verb": verb,
        "resource": resource,
        "namespace": namespace,
        "user": user,
        "groups": groups,
        "response_code": code,
        "is_admin": 0,
        "user_agent": ua,
        "source_ip": src_ip,
        "object_name": f"{resource[:-1] if resource.endswith('s') else resource}-{random.randint(1000,9999)}",
        "label": "benign",
        "attack_type": "",
    }


def gen_attack_event(dt, attack_type):
    """Generate an attack K8s audit event."""
    base = {
        "timestamp": ts_str(dt),
        "label": "attack",
        "attack_type": attack_type,
    }

    if attack_type == "secrets_access":
        # Accessing secrets from unusual SA or user
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": random.choice(["get", "list", "watch"]),
            "resource": "secrets",
            "namespace": random.choice(["kube-system", "default", "production"]),
            "user": user,
            "groups": random.choice(NORMAL_GROUPS),
            "response_code": 200,
            "is_admin": 0,
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": random.choice(["db-credentials", "tls-secret", "api-key", "registry-pull-secret"]),
        })

    elif attack_type == "rbac_escalation":
        # Creating/modifying cluster role bindings to gain admin
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": random.choice(["create", "update", "patch"]),
            "resource": random.choice(["clusterrolebindings", "clusterroles", "rolebindings"]),
            "namespace": random.choice(["default", "kube-system", ""]),
            "user": user,
            "groups": random.choice(NORMAL_GROUPS),
            "response_code": random.choice([201, 200, 403]),
            "is_admin": 0,
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": random.choice(["backdoor-admin-binding", "escalate-binding", "privilege-role"]),
        })

    elif attack_type == "container_exec":
        # Exec into containers (potential breakout)
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": "create",
            "resource": "pods/exec",
            "namespace": random.choice(NAMESPACES),
            "user": user,
            "groups": random.choice(NORMAL_GROUPS),
            "response_code": random.choice([101, 200, 403]),
            "is_admin": 0,
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": f"pod-{random.randint(1000,9999)}",
        })

    elif attack_type == "privileged_pod":
        # Creating privileged containers or hostPath mounts
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": "create",
            "resource": "pods",
            "namespace": random.choice(["default", "kube-system"]),
            "user": user,
            "groups": random.choice(NORMAL_GROUPS),
            "response_code": random.choice([201, 201, 403]),
            "is_admin": 0,
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": random.choice(["priv-container", "host-mount-pod", "debug-pod", "nsenter-pod"]),
        })

    elif attack_type == "token_theft":
        # Accessing service account tokens
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": random.choice(["get", "create"]),
            "resource": random.choice(["serviceaccounts/token", "tokenreviews", "secrets"]),
            "namespace": random.choice(["kube-system", "default"]),
            "user": user,
            "groups": random.choice(NORMAL_GROUPS),
            "response_code": random.choice([200, 201]),
            "is_admin": 0,
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": random.choice(["admin-token", "kube-proxy-token", "default-token"]),
        })

    elif attack_type == "namespace_escape":
        # Creating resources in kube-system or attempting cross-namespace access
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": random.choice(["create", "update", "delete"]),
            "resource": random.choice(["pods", "deployments", "daemonsets"]),
            "namespace": "kube-system",
            "user": user,
            "groups": random.choice(NORMAL_GROUPS),
            "response_code": random.choice([201, 200, 403, 403]),
            "is_admin": 0,
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": random.choice(["backdoor-daemonset", "reverse-shell-pod", "miner-deploy"]),
        })

    elif attack_type == "admin_impersonation":
        # Using admin groups without being a legitimate admin
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": random.choice(WRITE_VERBS),
            "resource": random.choice(SENSITIVE_RESOURCES[:4]),
            "namespace": random.choice(["kube-system", "default", ""]),
            "user": user,
            "groups": random.choice(ADMIN_GROUPS),
            "response_code": random.choice([200, 201]),
            "is_admin": 1,
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": random.choice(["cluster-admin-binding", "escalated-role", "shadow-admin"]),
        })

    elif attack_type == "mass_deletion":
        # Deleting many resources (sabotage)
        user = random.choice(ATTACK_USERS)
        base.update({
            "verb": "delete",
            "resource": random.choice(["pods", "deployments", "services", "namespaces", "persistentvolumeclaims"]),
            "namespace": random.choice(["production", "default", "staging"]),
            "user": user,
            "groups": random.choice(NORMAL_GROUPS + ADMIN_GROUPS),
            "response_code": 200,
            "is_admin": random.choice([0, 1]),
            "user_agent": random.choice(ATTACK_USER_AGENTS),
            "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "object_name": f"victim-resource-{random.randint(1,999)}",
        })

    return base


# ── Generate dataset ────────────────────────────────────────────

ATTACK_TYPES = [
    "secrets_access", "rbac_escalation", "container_exec",
    "privileged_pod", "token_theft", "namespace_escape",
    "admin_impersonation", "mass_deletion",
]

# Target: ~20K events (15K normal + 5K attack)
N_NORMAL = 15000
N_ATTACK = 5000

start_dt = datetime(2024, 1, 15, 0, 0, 0)
end_dt = datetime(2024, 2, 15, 0, 0, 0)
span_seconds = int((end_dt - start_dt).total_seconds())

rows = []

# Normal events — spread across the full time range with business-hour bias
for _ in range(N_NORMAL):
    offset = random.randint(0, span_seconds)
    dt = start_dt + timedelta(seconds=offset)
    # Business-hour bias: 60% of events during 8-18 UTC
    if dt.hour < 8 or dt.hour >= 18:
        if random.random() < 0.6:
            dt = dt.replace(hour=random.randint(8, 17))
    rows.append(gen_normal_event(dt))

# Attack events — clustered in attack windows (realistic)
n_attack_windows = 20
attacks_per_window = N_ATTACK // n_attack_windows

for window_i in range(n_attack_windows):
    # Pick a random attack window start
    window_start_offset = random.randint(0, span_seconds - 7200)
    window_start = start_dt + timedelta(seconds=window_start_offset)
    attack_type = random.choice(ATTACK_TYPES)

    for _ in range(attacks_per_window):
        # Events within a 1-2 hour window
        event_offset = random.randint(0, 7200)
        dt = window_start + timedelta(seconds=event_offset)
        rows.append(gen_attack_event(dt, attack_type))

# Sort by timestamp
rows.sort(key=lambda r: r["timestamp"])

# Write CSV
COLUMNS = ["timestamp", "verb", "resource", "namespace", "user", "groups",
           "response_code", "is_admin", "user_agent", "source_ip",
           "object_name", "label", "attack_type"]

os.makedirs(OUT_DIR, exist_ok=True)
with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)

# Stats
total = len(rows)
benign = sum(1 for r in rows if r["label"] == "benign")
attack = sum(1 for r in rows if r["label"] == "attack")
attack_dist = {}
for r in rows:
    at = r["attack_type"]
    if at:
        attack_dist[at] = attack_dist.get(at, 0) + 1

print(f"Generated {total:,} Kubernetes audit events -> {OUT_FILE}")
print(f"  Benign: {benign:,} ({100*benign/total:.1f}%)")
print(f"  Attack: {attack:,} ({100*attack/total:.1f}%)")
print(f"\nAttack type distribution:")
for k, v in sorted(attack_dist.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")
print(f"\nFile size: {os.path.getsize(OUT_FILE)/1024/1024:.2f} MB")
