import { NextRequest, NextResponse } from "next/server";

/**
 * POST /api/ai/chat — Chat with CLIF AI assistant
 * Note: LLM chat endpoint not yet deployed. Returns helpful message.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const userMessage = body.message ?? body.prompt ?? "";

    return NextResponse.json({
      response: `The CLIF AI chat assistant is not currently deployed. Your question was: "${userMessage.slice(0, 100)}". ` +
        "For security analysis, use the AI Agents page to classify events through the Triage pipeline, " +
        "or visit the Explainability page for SHAP-based feature explanations.",
      model: "none",
      available: false,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Chat request failed";
    return NextResponse.json(
      { error: msg, response: "Chat service unavailable.", available: false },
      { status: 200 },
    );
  }
}
