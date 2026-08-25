import i18n from "@/i18n";

const apiText = (key: string, options?: Record<string, unknown>) => i18n.t(`apiErrors.${key}`, options);

export type VertexCredentials = { clientEmail: string; privateKey: string; projectId: string; tokenUri: string };

const DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token";
const VERTEX_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
const TOKEN_REFRESH_MARGIN_MS = 60_000;

/** Required fields for a Vertex AI import: a GCP service-account key JSON exported from Google Cloud Console. */
export function parseVertexCredentials(raw: string): VertexCredentials {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new Error(apiText("vertexCredentialsInvalid"));
    }
    if (!parsed || typeof parsed !== "object") throw new Error(apiText("vertexCredentialsInvalid"));
    const record = parsed as Record<string, unknown>;
    const clientEmail = typeof record.client_email === "string" ? record.client_email : "";
    const privateKey = typeof record.private_key === "string" ? record.private_key : "";
    const projectId = typeof record.project_id === "string" ? record.project_id : "";
    if (!clientEmail || !privateKey || !projectId) throw new Error(apiText("vertexCredentialsInvalid"));
    const tokenUri = typeof record.token_uri === "string" && record.token_uri ? record.token_uri : DEFAULT_TOKEN_URI;
    return { clientEmail, privateKey, projectId, tokenUri };
}

export function vertexProjectId(rawCredentials: string): string {
    return parseVertexCredentials(rawCredentials).projectId;
}

/** Vertex location comes from the baseUrl subdomain (e.g. https://us-central1-aiplatform.googleapis.com). A bare https://aiplatform.googleapis.com (no region prefix) is the "global" endpoint, which Gemini 3-family models require; it's also the default when unset or custom. */
export function vertexLocationFromBaseUrl(baseUrl: string): string {
    const trimmed = baseUrl.trim();
    if (/^https?:\/\/aiplatform\.googleapis\.com/i.test(trimmed)) return "global";
    const match = trimmed.match(/^https?:\/\/([a-z0-9-]+)-aiplatform\.googleapis\.com/i);
    return match ? match[1] : "global";
}

const tokenCache = new Map<string, { token: string; expiresAt: number }>();

export async function getVertexAccessToken(rawCredentials: string): Promise<string> {
    const cached = tokenCache.get(rawCredentials);
    const now = Date.now();
    if (cached && cached.expiresAt - now > TOKEN_REFRESH_MARGIN_MS) return cached.token;

    const credentials = parseVertexCredentials(rawCredentials);
    const jwt = await signVertexJwt(credentials);
    const response = await fetch(credentials.tokenUri, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }),
    });
    const payload = (await response.json().catch(() => null)) as { access_token?: string; expires_in?: number; error_description?: string; error?: string } | null;
    if (!response.ok || !payload?.access_token) throw new Error(payload?.error_description || payload?.error || apiText("vertexAuthFailed"));

    const expiresIn = Number(payload.expires_in) || 3600;
    tokenCache.set(rawCredentials, { token: payload.access_token, expiresAt: now + expiresIn * 1000 });
    return payload.access_token;
}

async function signVertexJwt(credentials: VertexCredentials): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: "RS256", typ: "JWT" };
    const claims = { iss: credentials.clientEmail, scope: VERTEX_SCOPE, aud: credentials.tokenUri, iat: now, exp: now + 3600 };
    const unsigned = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(claims))}`;
    const key = await importPrivateKey(credentials.privateKey);
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
    return `${unsigned}.${base64urlEncodeBytes(new Uint8Array(signature))}`;
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
    const base64 = pem.replace(/-----BEGIN PRIVATE KEY-----/, "").replace(/-----END PRIVATE KEY-----/, "").replace(/\s+/g, "");
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    try {
        return await crypto.subtle.importKey("pkcs8", bytes.buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
    } catch {
        throw new Error(apiText("vertexCredentialsInvalid"));
    }
}

function base64urlEncode(input: string) {
    return base64urlEncodeBytes(new TextEncoder().encode(input));
}

function base64urlEncodeBytes(bytes: Uint8Array) {
    let binary = "";
    bytes.forEach((byte) => (binary += String.fromCharCode(byte)));
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
