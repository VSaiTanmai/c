"""
Normalize label columns across all CLIF training datasets.

Problem: Each dataset uses different column names and value conventions:
  01_Syslog:    label={benign,attack,suspicious,unknown,context}
  03_Firewall:  attack_cat={Normal,Exploits,DoS,...}  label={0,1}
  04_AD:        label={benign,attack,suspicious,unknown,context}
  05_DNS DGA:   isDGA={dga,legit}
  06_Cloud:     (no explicit label — needs inference from eventName)
  07_K8s:       label={benign,attack}  attack_type={...}
  08_Web:       classification={0,1}  (CSIC)
  09_NetFlow:   Attack={Benign,Exploits,...}  Label={0,1}
  10_IDS:       Label={BENIGN,SSH-Patator,...}  binary_label={0,1}
                label={normal,neptune,...}  (KDD)

Solution: Add two standardized columns to each dataset:
  - clif_label:       0=benign, 1=attack
  - clif_attack_type: string describing attack (empty for benign)

Reads originals, writes *_normalized.csv alongside.
"""
import csv
import os
import sys

BASE = r"C:\CLIF\agents\Data\Latest_Dataset"


def normalize_file(input_path, output_path, label_fn, desc):
    """Read a CSV, add clif_label and clif_attack_type columns, write output."""
    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) + ["clif_label", "clif_attack_type"]

        rows_written = 0
        stats = {"benign": 0, "attack": 0}
        attack_types = {}

        with open(output_path, "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                row.pop(None, None)  # Drop overflow fields from ragged rows
                clif_label, clif_attack_type = label_fn(row)
                row["clif_label"] = clif_label
                row["clif_attack_type"] = clif_attack_type
                writer.writerow(row)
                rows_written += 1

                if clif_label == 0:
                    stats["benign"] += 1
                else:
                    stats["attack"] += 1
                    attack_types[clif_attack_type] = attack_types.get(clif_attack_type, 0) + 1

    size_mb = os.path.getsize(output_path) / 1024 / 1024
    print(f"  [{desc}] {rows_written:,} rows -> {os.path.basename(output_path)} ({size_mb:.1f} MB)")
    print(f"    benign={stats['benign']:,}  attack={stats['attack']:,}")
    if attack_types:
        top = sorted(attack_types.items(), key=lambda x: -x[1])[:8]
        print(f"    attack_types: {dict(top)}")
    return rows_written


# ── Per-dataset label mappers ───────────────────────────────────

def label_syslog(row):
    l = row.get("label", "").strip().lower()
    if l in ("attack", "suspicious"):
        return 1, l
    return 0, ""

def label_firewall(row):
    cat = row.get("attack_cat", "").strip()
    lbl = row.get("label", row.get("Label", "0")).strip()
    if cat and cat.lower() not in ("normal", "", "0"):
        return 1, cat.lower()
    if lbl == "1":
        return 1, "unknown_attack"
    return 0, ""

def label_ad(row):
    return label_syslog(row)  # Same schema

def label_dga(row):
    v = row.get("isDGA", "").strip().lower()
    if v == "dga":
        sc = row.get("subclass", "dga").strip()
        return 1, f"dga_{sc}" if sc else "dga"
    return 0, ""

def label_dns_benign(row):
    # CSV_benign.csv, CSV_malware.csv, CSV_phishing.csv, CSV_spam.csv
    # Inferred from filename
    return None, None  # Handled per-file

def label_dns_exfil_attack(row):
    return 1, "dns_exfiltration"

def label_dns_exfil_benign(row):
    return 0, ""

def label_k8s(row):
    l = row.get("label", "").strip().lower()
    at = row.get("attack_type", "").strip()
    if l == "attack":
        return 1, at or "k8s_attack"
    return 0, ""

def label_csic(row):
    c = row.get("classification", "0").strip()
    if c == "1":
        return 1, "web_attack"
    return 0, ""

def label_netflow(row):
    atk = row.get("Attack", "").strip()
    lbl = row.get("Label", row.get("binary_label", "0")).strip()
    if atk and atk.lower() not in ("benign", "normal", "0", ""):
        return 1, atk.lower()
    if lbl == "1":
        return 1, "unknown_attack"
    return 0, ""

def label_cicids(row):
    # Try both ' Label' and 'Label' (CIC uses space-prefixed sometimes)
    l = row.get("Label", row.get(" Label", "BENIGN")).strip()
    if l.upper() == "BENIGN":
        return 0, ""
    return 1, l.lower().replace(" ", "_")

def label_nsl_kdd(row):
    bl = row.get("binary_label", "0").strip()
    at = row.get("attack_type", row.get("label", "")).strip()
    if bl == "1":
        return 1, at.lower() if at else "unknown_attack"
    return 0, ""

def label_kdd_raw(row):
    """KDDTrain+.txt / KDDTest+.txt — no header, last-1 col = attack label."""
    # These files have no header; we handle them separately
    return None, None


# ── Main normalization pipeline ────────────────────────────────

def run():
    total = 0
    print("=" * 60)
    print("LABEL NORMALIZATION")
    print("=" * 60)

    # 01_Syslog
    print("\n--- 01_Syslog ---")
    f = os.path.join(BASE, "01_Syslog", "lanl_auth_training.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_syslog, "LANL-syslog")

    # 03_Firewall
    print("\n--- 03_Firewall ---")
    f = os.path.join(BASE, "03_Firewall", "unsw_stratified.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_firewall, "UNSW-FW")

    # 04_Active_Directory
    print("\n--- 04_Active_Directory ---")
    f = os.path.join(BASE, "04_Active_Directory", "lanl_auth_ad_training.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_ad, "LANL-AD")

    # 05_DNS — DGA
    print("\n--- 05_DNS ---")
    f = os.path.join(BASE, "05_DNS", "dga_data.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_dga, "DGA")

    # 05_DNS — benign/malware/phishing/spam CSVs
    for kind, lbl_val, atk_val in [
        ("CSV_benign.csv", 0, ""),
        ("CSV_malware.csv", 1, "malware_domain"),
        ("CSV_phishing.csv", 1, "phishing_domain"),
        ("CSV_spam.csv", 1, "spam_domain"),
    ]:
        f = os.path.join(BASE, "05_DNS", kind)
        if os.path.exists(f):
            fn = lambda row, lv=lbl_val, av=atk_val: (lv, av)
            total += normalize_file(f,
                f.replace(".csv", "_normalized.csv"),
                fn, kind.replace(".csv",""))

    # 05_DNS — CIC exfiltration CSVs (stateless features only for simplicity)
    exfil_dir = os.path.join(BASE, "05_DNS", "CIC-Bell-DNS-EXFil-2021", "CSV")
    if os.path.isdir(exfil_dir):
        for root, dirs, files in os.walk(exfil_dir):
            for fname in files:
                if "stateless" in fname.lower() and fname.endswith(".csv"):
                    fp = os.path.join(root, fname)
                    rel = os.path.relpath(root, exfil_dir)
                    is_attack = "attack" in rel.lower()
                    if is_attack:
                        lfn = label_dns_exfil_attack
                    else:
                        lfn = label_dns_exfil_benign
                    out = fp.replace(".csv", "_normalized.csv")
                    total += normalize_file(fp, out, lfn,
                        f"DNS-exfil-{'atk' if is_attack else 'ben'}")

    # 07_Kubernetes
    print("\n--- 07_Kubernetes ---")
    f = os.path.join(BASE, "07_Kubernetes", "k8s_audit_training.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_k8s, "K8s-audit")

    # 08_Web_Server
    print("\n--- 08_Web_Server ---")
    f = os.path.join(BASE, "08_Web_Server", "csic_database.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_csic, "CSIC")

    # 09_NetFlow
    print("\n--- 09_NetFlow ---")
    f = os.path.join(BASE, "09_NetFlow", "nf_unsw_stratified.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_netflow, "NF-UNSW")

    f = os.path.join(BASE, "09_NetFlow", "nf_ton_iot_temporal.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_netflow, "NF-TON")

    # 10_IDS_IPS
    print("\n--- 10_IDS_IPS ---")
    f = os.path.join(BASE, "10_IDS_IPS", "cicids2017_stratified.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_cicids, "CICIDS2017")

    f = os.path.join(BASE, "10_IDS_IPS", "nsl_kdd_stratified.csv")
    if os.path.exists(f):
        total += normalize_file(f,
            f.replace(".csv", "_normalized.csv"),
            label_nsl_kdd, "NSL-KDD")

    print(f"\n{'='*60}")
    print(f"TOTAL NORMALIZED: {total:,} rows across all datasets")
    print("=" * 60)


if __name__ == "__main__":
    run()
