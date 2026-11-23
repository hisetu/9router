import { NextResponse } from "next/server";
import { CursorService } from "@/lib/oauth/services/cursor";
import { createProviderConnection } from "@/models";
import { randomUUID } from "node:crypto";
import { isCursorUserApiKey, exchangeCursorApiKey } from "open-sse/services/cursorApiKey.js";

/**
 * POST /api/oauth/cursor/import
 * Import and validate access token from Cursor IDE's local SQLite database
 *
 * Request body:
 * - accessToken: string - Access token from cursorAuth/accessToken, or a Cursor
 *   user API key (dashboard → API Keys). An API key is exchanged for a
 *   short-lived access token and kept so the token can be re-minted.
 * - apiKey: string (optional) - Cursor user API key, same as above
 * - machineId: string - Machine ID from storage.serviceMachineId
 */
export async function POST(request) {
  try {
    const body = await request.json();
    const { accessToken, machineId } = body;

    const apiKeyCandidate = typeof body.apiKey === "string" && body.apiKey.trim()
      ? body.apiKey.trim()
      : (typeof accessToken === "string" ? accessToken.trim() : "");
    if (isCursorUserApiKey(apiKeyCandidate)) {
      return await importFromApiKey(apiKeyCandidate, machineId);
    }

    if (!accessToken || typeof accessToken !== "string") {
      return NextResponse.json(
        { error: "Access token is required" },
        { status: 400 }
      );
    }

    if (!machineId || typeof machineId !== "string") {
      return NextResponse.json(
        { error: "Machine ID is required" },
        { status: 400 }
      );
    }

    const cursorService = new CursorService();

    // Validate token by making API call
    const tokenData = await cursorService.validateImportToken(
      accessToken.trim(),
      machineId.trim()
    );

    // Try to extract user info from token
    const userInfo = cursorService.extractUserInfo(tokenData.accessToken);

    // Save to database
    const connection = await createProviderConnection({
      provider: "cursor",
      authType: "oauth",
      accessToken: tokenData.accessToken,
      refreshToken: null, // Cursor doesn't have public refresh endpoint
      expiresAt: new Date(Date.now() + tokenData.expiresIn * 1000).toISOString(),
      email: userInfo?.email || null,
      providerSpecificData: {
        machineId: tokenData.machineId,
        authMethod: "imported",
        provider: "Imported",
        userId: userInfo?.userId,
      },
      testStatus: "active",
    });

    return NextResponse.json({
      success: true,
      connection: {
        id: connection.id,
        provider: connection.provider,
        email: connection.email,
      },
    });
  } catch (error) {
    console.log("Cursor import token error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

async function importFromApiKey(apiKey, machineIdInput) {
  // The Cursor CLI has no IDE machine id; accept the user's if given, else mint one.
  const machineId = typeof machineIdInput === "string" && machineIdInput.trim()
    ? machineIdInput.trim()
    : randomUUID();
  if (!/^[a-f0-9]{32,}$/i.test(machineId.replace(/-/g, ""))) {
    return NextResponse.json({ error: "Invalid machine ID format. Expected UUID format." }, { status: 400 });
  }

  let tokens;
  try {
    tokens = await exchangeCursorApiKey(apiKey);
  } catch (error) {
    const status = error.status === 401 || error.status === 403 ? 400 : 502;
    return NextResponse.json({ error: error.message }, { status });
  }

  const userInfo = new CursorService().extractUserInfo(tokens.accessToken);
  // Same masked form Cursor's dashboard uses (…xxxx), so the row is
  // recognisable as an API-key connection and tells keys apart.
  const connection = await createProviderConnection({
    provider: "cursor",
    authType: "oauth",
    name: `API Key …${apiKey.slice(-4)}`,
    apiKey,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    expiresAt: tokens.expiresAt,
    email: userInfo?.email || null,
    providerSpecificData: {
      machineId,
      authMethod: "api_key",
      provider: "API Key",
      userId: userInfo?.userId,
    },
    testStatus: "active",
  });

  return NextResponse.json({
    success: true,
    connection: {
      id: connection.id,
      provider: connection.provider,
      email: connection.email,
    },
  });
}

/**
 * GET /api/oauth/cursor/import
 * Get instructions for importing Cursor token
 */
export async function GET() {
  const cursorService = new CursorService();
  const instructions = cursorService.getTokenStorageInstructions();

  return NextResponse.json({
    provider: "cursor",
    method: "import_token",
    instructions,
    requiredFields: [
      {
        name: "accessToken",
        label: "Access Token",
        description: "From cursorAuth/accessToken in state.vscdb, or a Cursor user API key (dashboard → API Keys)",
        type: "textarea",
      },
      {
        name: "machineId",
        label: "Machine ID",
        description: "From storage.serviceMachineId in state.vscdb",
        type: "text",
      },
    ],
  });
}
