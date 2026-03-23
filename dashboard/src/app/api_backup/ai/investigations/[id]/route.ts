import { NextRequest, NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";

/**
 * GET /api/ai/investigations/[id] — Fetch investigation from ClickHouse
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } },
) {
  try {
    const result = await queryClickHouse<Record<string, unknown>>(
      `SELECT * FROM clif_logs.hunter_investigations
       WHERE toString(investigation_id) = {id:String}
       LIMIT 1`,
      { id: params.id },
    );

    if (!result.data.length) {
      return NextResponse.json(
        { error: "Investigation not found" },
        { status: 404 },
      );
    }

    return NextResponse.json(result.data[0]);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Failed to fetch investigation";
    return NextResponse.json(
      { error: msg },
      { status: 500 },
    );
  }
}
