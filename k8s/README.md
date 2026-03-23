# CLIF Kubernetes Deployment — Production Architecture

> **SIH1733 Smart India Hackathon** | Cognitive Log Investigation Framework

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster (clif namespace)              │
│                                                                         │
│  ┌─── DATA TIER (nodeSelector: clif/tier=data) ─────────────────────┐  │
│  │  StatefulSet: redpanda (3)    StatefulSet: clickhouse (2)        │  │
│  │  StatefulSet: minio (3)       StatefulSet: clickhouse-keeper (1) │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                              │                                          │
│  ┌─── COMPUTE TIER (nodeSelector: clif/tier=compute) ───────────────┐  │
│  │  Deployment: consumer (3→12)  Deployment: vector (1→3)           │  │
│  │  Deployment: triage-agent (1→4)  Deployment: hunter-agent (1→3)  │  │
│  │  Deployment: verifier-agent (1)  Deployment: ai-classifier (1→3) │  │
│  │  Deployment: merkle (1)       StatefulSet: lancedb (1)           │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌─── MONITORING TIER ──────────────────────────────────────────────┐  │
│  │  Deployment: prometheus (1)   Deployment: grafana (1)            │  │
│  │  Deployment: redpanda-console (1)                                │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌─── AUTO-SCALING (HPA) ──────────────────────────────────────────┐  │
│  │  consumer: 3→12 (CPU 70%)    triage-agent: 1→4 (CPU 75%)       │  │
│  │  hunter-agent: 1→3           vector: 1→3                        │  │
│  │  ai-classifier: 1→3                                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Resource Summary

| Kind                     | Count | Examples                                                   |
|--------------------------|-------|-----------------------------------------------------------|
| Namespace                | 1     | `clif`                                                     |
| StatefulSet              | 5     | redpanda, clickhouse, clickhouse-keeper, minio, lancedb   |
| Deployment               | 10    | consumer, vector, triage-agent, hunter, verifier, etc.    |
| Service                  | 19    | Headless (5), ClusterIP (10), NodePort (4)                |
| ConfigMap                | 8     | ClickHouse configs, Prometheus, Grafana, RP Console       |
| Secret                   | 1     | `clif-credentials` (ClickHouse, MinIO, Grafana)           |
| HPA                      | 5     | consumer, triage, hunter, vector, ai-classifier           |
| Job                      | 2     | minio-init (S3 buckets), redpanda-init (14 topics)        |
| NetworkPolicy            | 5     | Default deny + tier-specific allow rules                  |
| PDB (prod only)          | 4     | redpanda, clickhouse, minio, consumer                     |
| RBAC                     | 3     | ServiceAccount + ClusterRole + ClusterRoleBinding         |
| **Total**                | **59+** |                                                          |

## Directory Structure

```
k8s/
├── base/
│   ├── kustomization.yaml              # Main Kustomize config
│   ├── namespace.yaml                  # clif namespace
│   ├── rbac.yaml                       # Prometheus ServiceAccount + RBAC
│   ├── network-policy.yaml             # Zero-trust NetworkPolicies
│   ├── hpa.yaml                        # HorizontalPodAutoscalers
│   ├── configmaps/
│   │   ├── clickhouse.yaml             # Keeper, node01/02, users, storage policy
│   │   ├── grafana.yaml                # Datasources + dashboard provider
│   │   ├── prometheus.yaml             # Scrape config
│   │   └── redpanda-console.yaml       # Broker config
│   ├── secrets/
│   │   └── credentials.yaml            # ClickHouse, MinIO, Grafana creds
│   ├── statefulsets/
│   │   ├── redpanda.yaml               # 3-node Kafka-compatible streaming
│   │   ├── clickhouse.yaml             # 2-node replicated analytics DB
│   │   ├── clickhouse-keeper.yaml      # Consensus (ZK replacement)
│   │   └── minio-lancedb.yaml          # 3-node S3 + vector search
│   ├── deployments/
│   │   ├── consumer.yaml               # Redpanda → ClickHouse pipeline
│   │   ├── vector.yaml                 # Log aggregation & normalization
│   │   ├── triage-agent.yaml           # ML-based triage scoring
│   │   ├── agents.yaml                 # Hunter + Verifier agents
│   │   ├── classifier-merkle.yaml      # AI classifier + evidence chain
│   │   └── monitoring.yaml             # Prometheus, Grafana, RP Console
│   ├── services/
│   │   ├── headless.yaml               # StatefulSet DNS (5 headless)
│   │   └── application.yaml            # ClusterIP + NodePort services
│   └── jobs/
│       └── init-jobs.yaml              # MinIO buckets + Redpanda topics
├── overlays/
│   ├── development/
│   │   └── kustomization.yaml          # Single-node, reduced resources
│   └── production/
│       ├── kustomization.yaml          # Full HA, anti-affinity, scaling
│       └── pdb.yaml                    # PodDisruptionBudgets
├── generate-configmaps.ps1             # Generate large ConfigMaps from source
└── README.md                           # This file
```

## Deployment

### Prerequisites
- Kubernetes 1.28+ cluster (AKS, EKS, GKE, or K3s)
- `kubectl` v1.28+
- Container registry with CLIF images (see Image Build section)

### Quick Deploy (Development)
```bash
# Generate large ConfigMaps from source files
./k8s/generate-configmaps.ps1

# Deploy with development overlay (single-node, reduced resources)
kubectl apply -k k8s/overlays/development/

# Watch rollout
kubectl -n clif get pods -w
```

### Production Deploy
```bash
# Label nodes by tier
kubectl label node <data-node-1> clif/tier=data
kubectl label node <data-node-2> clif/tier=data
kubectl label node <compute-node-1> clif/tier=compute

# Deploy with production overlay
kubectl apply -k k8s/overlays/production/

# Verify all pods
kubectl -n clif get pods -o wide
kubectl -n clif get hpa
```

### Image Build (8 custom images)
```bash
# Build and push to your registry
REGISTRY=ghcr.io/clif-siem

docker build -t $REGISTRY/consumer:latest      ./consumer/
docker build -t $REGISTRY/vector:latest         ./vector/
docker build -t $REGISTRY/triage-agent:latest   ./agents/triage/
docker build -t $REGISTRY/hunter-agent:latest   ./agents/hunter/
docker build -t $REGISTRY/verifier-agent:latest ./agents/verifier/
docker build -t $REGISTRY/ai-classifier:latest  ./ai-agents/
docker build -t $REGISTRY/merkle:latest         ./merkle-service/
docker build -t $REGISTRY/lancedb:latest        ./lancedb-service/

# Push all
for img in consumer vector triage-agent hunter-agent verifier-agent ai-classifier merkle lancedb; do
  docker push $REGISTRY/$img:latest
done
```

## Kustomize Overlays

| Overlay       | Purpose                  | Replicas                  | Resources          |
|---------------|--------------------------|---------------------------|--------------------|
| **base**      | Shared manifests         | Default (3/2/3/3/1/1/1)  | Standard           |
| **development** | Local/single-node      | 1/1/1/1 (reduced)        | 50% of base        |
| **production**  | Multi-node HA cluster  | 3/2/3/6/2/2 (scaled up)  | 2-4x base + PDBs   |

### Validate without applying:
```bash
kubectl kustomize k8s/base/
kubectl kustomize k8s/overlays/development/
kubectl kustomize k8s/overlays/production/
```

## Scaling Capabilities

### Horizontal Pod Autoscaling
| Component      | Min→Max | Scale Trigger | Scale-Up Window | Scale-Down Window |
|----------------|---------|---------------|-----------------|-------------------|
| Consumer       | 3→12   | CPU > 70%     | 60s             | 300s              |
| Triage Agent   | 1→4     | CPU > 75%     | 120s            | 300s              |
| Hunter Agent   | 1→3     | CPU > 75%     | 120s            | 300s              |
| Vector         | 1→3     | CPU > 70%     | 60s             | 300s              |
| AI Classifier  | 1→3     | CPU > 70%     | 120s            | 300s              |

### Manual Scaling
```bash
# Scale consumers for burst ingestion
kubectl -n clif scale deployment/consumer --replicas=12

# Scale agents for investigation surge
kubectl -n clif scale deployment/triage-agent --replicas=4
kubectl -n clif scale deployment/hunter-agent --replicas=3
```

## Network Security (NetworkPolicy)

```
                    ┌─ default-deny-ingress (all pods) ─┐
                    │                                     │
  External ──────► │  Vector (1514, 8687)               │ ◄── allow-vector-ingest
                    │                                     │
  Namespace ═════► │  Data Tier (ClickHouse, Redpanda)  │ ◄── allow-data-tier
                    │  Compute Tier (Agents, Consumer)   │ ◄── allow-compute-tier
                    │  Monitoring (Grafana:3000, RP:8080)│ ◄── allow-monitoring-tier
                    └─────────────────────────────────────┘
```

## Exposed Endpoints (NodePort)

| Service           | NodePort | Internal Port | Purpose              |
|-------------------|----------|---------------|----------------------|
| Redpanda External | 31092    | 19092         | Kafka client access  |
| Redpanda Console  | 31080    | 8080          | Broker management UI |
| Grafana           | 31300    | 3000          | Dashboards           |
| MinIO Console     | 31900    | 9001          | Object storage UI    |

Access via: `http://<node-ip>:<nodeport>`

## Production Features Showcase

- **StatefulSets** with ordinal-based init containers for per-node config
- **Kustomize overlays** for environment-specific deployments
- **HPA** with fine-grained scale-up/down policies
- **PodDisruptionBudgets** for zero-downtime cluster upgrades
- **NetworkPolicies** implementing zero-trust network segmentation
- **RBAC** for Prometheus K8s service discovery
- **ConfigMap separation** — small configs inline, large files via generator
- **Secret management** — all credentials in Kubernetes Secrets
- **Pod Anti-Affinity** (production) — ensures HA across failure domains
- **Multi-tier architecture** — data/compute/monitoring node affinity
