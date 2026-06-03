// OmniSec™ © HARSH MALIK — OAuth Gap-Closure Scanner
// Discovers OAuth/OIDC endpoints + tests redirect_uri tampering, missing state/PKCE,
// implicit-flow enablement. Inserts findings into recon_findings (live stream).

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const PRIVATE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.|::1|localhost)/i;

const DISCOVERY_PATHS = [
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
  "/oauth/.well-known/openid-configuration",
];

const AUTHORIZE_HINTS = ["/oauth/authorize", "/authorize", "/oauth2/authorize", "/connect/authorize", "/o/authorize"];

async function safeFetch(url: string, init: RequestInit = {}, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, redirect: "manual" });
  } finally {
    clearTimeout(t);
  }
}

function norm(t: string) {
  let u = t.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  try { return new URL(u); } catch { return null; }
}

async function runOAuthScan(target: string, scanId: string, admin: any) {
  const findings: any[] = [];
  const base = norm(target);
  if (!base || PRIVATE.test(base.hostname)) return findings;
  const host = base.hostname;

  const insert = async (f: any) => {
    const hash = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(`${f.title}|${f.url_path}|${f.vulnerable_parameter || ""}`)
    );
    const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
    await admin.from("recon_findings").insert({
      target_host: host,
      url_path: f.url_path,
      finding_type: f.finding_type,
      title: f.title,
      description: f.description,
      severity: f.severity,
      vulnerable_parameter: f.vulnerable_parameter || null,
      confidence_score: f.confidence || 70,
      verification_status: "pending",
      source_module: "vapt-oauth",
      evidence: f.evidence,
      raw_data: { scan_id: scanId, owasp: f.owasp, mitre: f.mitre, cwe: f.cwe, payload: f.payload },
      hash_signature: hashHex,
    });
    findings.push(f);
  };

  // 1. Discovery
  let config: any = null;
  let configUrl: string | null = null;
  for (const p of DISCOVERY_PATHS) {
    try {
      const url = new URL(p, base).toString();
      const r = await safeFetch(url, {}, 6000);
      if (r.status === 200) {
        const j = await r.json().catch(() => null);
        if (j?.authorization_endpoint || j?.token_endpoint) {
          config = j; configUrl = url; break;
        }
      }
    } catch { /* skip */ }
  }

  if (config && configUrl) {
    await insert({
      url_path: configUrl,
      finding_type: "oauth_discovery",
      title: "OAuth/OIDC Discovery Document Exposed",
      description: `OAuth metadata exposed — issuer=${config.issuer || "n/a"}. Endpoints: authorize=${config.authorization_endpoint}, token=${config.token_endpoint}.`,
      severity: "info",
      confidence: 100,
      owasp: "A05",
      evidence: {
        issuer: config.issuer,
        scopes_supported: config.scopes_supported?.slice(0, 20),
        response_types: config.response_types_supported,
        grant_types: config.grant_types_supported,
        token_endpoint_auth_methods: config.token_endpoint_auth_methods_supported,
      },
    });

    // 2. Implicit flow enabled?
    const rts = (config.response_types_supported || []).join(" ");
    if (/token/i.test(rts) && !/code\s+id_token/i.test(rts)) {
      await insert({
        url_path: config.authorization_endpoint || configUrl,
        finding_type: "oauth_implicit_flow",
        title: "OAuth Implicit Flow Supported",
        description: "Server advertises 'token' / 'id_token token' response types. Implicit flow leaks tokens in URL fragment and is deprecated by OAuth 2.1.",
        severity: "medium",
        confidence: 90,
        owasp: "A02",
        cwe: "CWE-200",
        evidence: { response_types_supported: config.response_types_supported },
      });
    }

    // 3. PKCE not required?
    if (!config.code_challenge_methods_supported || config.code_challenge_methods_supported.length === 0) {
      await insert({
        url_path: configUrl,
        finding_type: "oauth_no_pkce",
        title: "PKCE Not Advertised by OAuth Server",
        description: "Discovery doc does not declare 'code_challenge_methods_supported'. Public clients are vulnerable to authorization-code interception.",
        severity: "medium",
        confidence: 85,
        owasp: "A07",
        cwe: "CWE-345",
        evidence: { discovery: configUrl },
      });
    }
  }

  // 4. Authorize endpoint probes
  const probes: string[] = [];
  if (config?.authorization_endpoint) probes.push(config.authorization_endpoint);
  for (const p of AUTHORIZE_HINTS) {
    try { probes.push(new URL(p, base).toString()); } catch { /* skip */ }
  }

  const tested = new Set<string>();
  for (const auth of probes) {
    if (tested.has(auth)) continue;
    tested.add(auth);
    try {
      // redirect_uri tampering — try off-domain
      const evil = "https://attacker.example.com/cb";
      const tamper = `${auth}${auth.includes("?") ? "&" : "?"}response_type=code&client_id=test&redirect_uri=${encodeURIComponent(evil)}&scope=openid&state=test`;
      const r = await safeFetch(tamper, {}, 6000);
      const loc = r.headers.get("location") || "";
      const txt = r.status >= 300 && r.status < 400 ? "" : await r.text();
      const acceptedEvil = loc.startsWith(evil) || /attacker\.example\.com/.test(txt);
      const explicitReject = /redirect_uri|invalid_request|unauthorized_client/i.test(txt + loc);
      if (acceptedEvil) {
        await insert({
          url_path: auth,
          finding_type: "oauth_open_redirect_uri",
          title: "OAuth redirect_uri Validation Bypass",
          description: "Authorization endpoint accepted an attacker-controlled redirect_uri. Authorization codes can be stolen via open redirect.",
          severity: "critical",
          confidence: 90,
          owasp: "A01",
          mitre: ["T1539"],
          cwe: "CWE-601",
          vulnerable_parameter: "redirect_uri",
          payload: tamper,
          evidence: { location: loc, status: r.status },
        });
      } else if (!explicitReject && r.status === 200) {
        // Server returned HTML page (login) without rejecting redirect_uri — needs manual review
        await insert({
          url_path: auth,
          finding_type: "oauth_redirect_uri_unverified",
          title: "OAuth redirect_uri Not Explicitly Validated",
          description: "Authorization endpoint did not return an error for an off-domain redirect_uri. Manual retest recommended with a registered client_id.",
          severity: "low",
          confidence: 50,
          owasp: "A01",
          vulnerable_parameter: "redirect_uri",
          payload: tamper,
          evidence: { status: r.status, body_sample: txt.slice(0, 300) },
        });
      }
    } catch { /* skip */ }
  }

  return findings;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const body = await req.json();
    const { scanId, target, passNumber = 8, passName = "oauth_scan" } = body;
    if (!scanId || !target) {
      return new Response(JSON.stringify({ error: "scanId and target required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    const admin = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    await admin.from("scan_passes").update({
      status: "running", started_at: new Date().toISOString()
    }).eq("scan_id", scanId).eq("pass_number", passNumber);

    const findings = await runOAuthScan(target, scanId, admin);

    await admin.from("scan_passes").update({
      status: "completed",
      completed_at: new Date().toISOString(),
      findings_count: findings.length,
    }).eq("scan_id", scanId).eq("pass_number", passNumber);

    return new Response(JSON.stringify({ success: true, findings_count: findings.length, findings }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
