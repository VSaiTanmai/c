import { NextResponse } from "next/server";
import { queryClickHouse, assertValidTable } from "@/lib/clickhouse";
import { createHash } from "crypto";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

/** Tables for which we know hash expressions — strict allowlist */
const HASH_TABLES = new Set(["raw_logs", "security_events", "process_events", "network_events", "triage_scores", "hunter_investigations", "verifier_results"]);

const RATE_LIMIT = { maxTokens: 80, refillRate: 2 }; // Allow batch verification of all evidence

function sha256Hex(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

function buildMerkleTree(leafHashes: string[]): { root: string; depth: number } {
  if (leafHashes.length === 0) {
    return { root: sha256Hex("EMPTY_BATCH"), depth: 0 };
  }

  const n = leafHashes.length;
  const depth = n > 1 ? Math.ceil(Math.log2(n)) : 1;
  const target = Math.pow(2, depth);
  const padded = [...leafHashes];
  while (padded.length < target) {
    padded.push(leafHashes[leafHashes.length - 1]);
  }

  let level = padded;
  while (level.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      nextLevel.push(sha256Hex(level[i] + level[i + 1]));
    }
    level = nextLevel;
  }

  return { root: level[0], depth };
}

// Hash expression per table (must match merkle_anchor.py exactly)
function getHashExpr(table: string): string {
  switch (table) {
    case "raw_logs":
      return "hex(SHA256(concat(toString(event_id), toString(timestamp), toString(source), toString(level), message)))";
    case "security_events":
      return "hex(SHA256(concat(toString(event_id), toString(timestamp), toString(severity), toString(category), toString(source), description, toString(mitre_tactic), toString(mitre_technique))))";
    case "process_events":
      return "hex(SHA256(concat(toString(event_id), toString(timestamp), hostname, toString(pid), toString(ppid), binary_path, arguments)))";
    case "network_events":
      return "hex(SHA256(concat(toString(event_id), toString(timestamp), hostname, IPv4NumToString(src_ip), IPv4NumToString(dst_ip), toString(src_port), toString(dst_port), protocol)))";
    case "triage_scores":
      return "hex(SHA256(concat(toString(event_id), toString(timestamp), source_type, hostname, toString(adjusted_score), toString(action), mitre_tactic, mitre_technique)))";
    case "hunter_investigations":
      return "hex(SHA256(concat(toString(investigation_id), toString(started_at), hostname, source_ip, toString(severity), finding_type, summary)))";
    case "verifier_results":
      return "hex(SHA256(concat(toString(verification_id), toString(started_at), toString(verdict), toString(confidence), toString(priority), analyst_summary)))";
    default:
      throw new Error(`Unknown table: ${table}`);
  }
}

/** Return the timestamp column name for a table (must match merkle_anchor.py) */
function tsColumn(table: string): string {
  if (table === "hunter_investigations" || table === "verifier_results") return "started_at";
  return "timestamp";
}

/** Return the primary ID column for ordering (must match merkle_anchor.py) */
function idColumn(table: string): string {
  if (table === "hunter_investigations") return "investigation_id";
  if (table === "verifier_results") return "verification_id";
  if (table === "triage_scores") return "score_id";
  return "event_id";
}

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), RATE_LIMIT);
  if (limited) return limited;

  const { searchParams } = new URL(request.url);
  const batchId = searchParams.get("batchId");

  if (!batchId) {
    return NextResponse.json(
      { error: "batchId query parameter is required" },
      { status: 400 }
    );
  }

  // Validate batchId format — prevent injection via malformed IDs
  if (batchId.length > 128 || !/^[A-Za-z0-9_\-]+$/.test(batchId)) {
    return NextResponse.json(
      { error: "Invalid batchId format" },
      { status: 400 }
    );
  }

  try {
    // Fetch the stored anchor record
    const anchorResult = await queryClickHouse<{
      table_name: string;
      time_from: string;
      time_to: string;
      merkle_root: string;
      event_count: string;
      merkle_depth: string;
      prev_merkle_root: string;
      status: string;
    }>(
      `SELECT
         table_name,
         time_from,
         time_to,
         merkle_root,
         event_count,
         merkle_depth,
         prev_merkle_root,
         status
       FROM clif_logs.evidence_anchors
       WHERE batch_id = {batchId:String}`,
      { batchId }
    );

    if (anchorResult.data.length === 0) {
      return NextResponse.json(
        { error: `Batch ${batchId} not found` },
        { status: 404 }
      );
    }

    const anchor = anchorResult.data[0];
    const tableName = anchor.table_name;
    const storedRoot = anchor.merkle_root;
    const prevRoot = anchor.prev_merkle_root;

    // CRITICAL: Validate table name from DB before SQL interpolation
    assertValidTable(tableName);
    if (!HASH_TABLES.has(tableName)) {
      log.error("Evidence verify: unsupported hash table from DB", { tableName, batchId, component: "api/evidence/verify" });
      return NextResponse.json(
        { error: "Unsupported table for hash verification" },
        { status: 400 }
      );
    }

    // Re-fetch event hashes from ClickHouse and recompute Merkle root
    const hashExpr = getHashExpr(tableName);
    const ts = tsColumn(tableName);
    const id = idColumn(tableName);
    const hashResult = await queryClickHouse<{ h: string }>(
      `SELECT ${hashExpr} AS h
       FROM clif_logs.${tableName}
       WHERE ${ts} >= {t0:String} AND ${ts} < {t1:String}
       ORDER BY ${id}`,
      { t0: anchor.time_from, t1: anchor.time_to }
    );

    const leafHashes = hashResult.data.map((r) => r.h);
    let { root: computedRoot, depth } = buildMerkleTree(leafHashes);

    // Apply chain hash (must match merkle_anchor.py logic)
    if (prevRoot) {
      computedRoot = sha256Hex(prevRoot + computedRoot);
    }

    const verified = computedRoot === storedRoot;
    const countMismatch = leafHashes.length !== Number(anchor.event_count);

    let status: string;
    if (verified) {
      status = "PASS";
    } else if (countMismatch) {
      status = `FAIL — EVENT COUNT CHANGED (${anchor.event_count} anchored, ${leafHashes.length} current). Data was added to this time window after anchoring.`;
    } else {
      status = "FAIL — TAMPERING DETECTED";
    }

    return NextResponse.json({
      batchId,
      table: tableName,
      storedRoot,
      computedRoot,
      storedCount: Number(anchor.event_count),
      actualCount: leafHashes.length,
      verified,
      countMismatch,
      depth,
      status,
    });
  } catch (err) {
    log.error("Evidence verification failed", { batchId: searchParams.get("batchId"), error: err instanceof Error ? err.message : "unknown", component: "api/evidence/verify" });
    return NextResponse.json(
      { error: "Verification failed" },
      { status: 500 }
    );
  }
}
