// OmniSec™ © HARSH MALIK — BOPLA / BOLA Gap-Closure Scanner
// Broken Object-Level Authorization + Broken Object-Property-Level Authorization.
// Uses two stored auth sessions (scan_auth_sessions) and diffs responses between users.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const PRIVATE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.|::1|localhost)/i;

const SENSITIVE_PROP = /(password|hash|salt|token|secret|api[_-]?key|ssn|credit|cvv|private[_-]?key|role|is_admin|permission|account_balance|email|phone)/i;

const COMMON_ID_PATHS = [
  "/api/users/1", "/api/users/2", "/api/user/1", "/api/user/2",
  "/api/profile/1", "/api/profile/2", "/api/account/1", "/api/account/2",
  "/api/v1/users/1", "/api/v1/users/2", "/api/orders/1", "/api/orders/2",
  "/api/invoices/1", "/api/invoices/2", "/users/1", "/users/2",
];

async function safeFetch(url: string, init: RequestInit = {}, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, redirect: "follow" });
  } finally {
    clearTimeout(t);
  }
}

function norm(t: string) {
  let u = t.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  try { return new URL(u); } catch { return null; }
}

function buildHeaders(session: any): HeadersInit {
  const h: Record<string, string> = { Accept: "application/json,*/*" };
  if (session?.bearer_token) h["Authorization"] = `Bearer ${session.bearer_token}`;
  if (session?.cookies && typeof session.cookies === "object") {
    const c = Object.entries(session.cookies).map(([k, v]) => `${k}=${v}`).join("; ");
    if (c) h["Cookie"] = c;
  }
  if (session?.custom_headers && typeof session.custom_headers === "object") {
    for (const [k, v] of Object.entries(session.custom_headers)) h[k] = String(v);
  }
  return h;
}

function extractSensitiveProps(body: string): string[] {
  try {
    const j = JSON.parse(body);
    const found: string[] = [];
    const walk = (obj: any, path = "") => {
      if (obj === null || obj === undefined) return;
      if (Array.isArray(obj)) { obj.slice(0, 3).forEach((x, i) => walk(x, `${path}[${i}]`)); return; }
      if (typeof obj === "object") {
        for (const [k, v] of Object.entries(obj)) {
          if (SENSITIVE_PROP.test(k)) found.push(`${path}.${k}`);
          if (typeof v === "object") walk(v, `${path}.${k}`);
        }
      }
    };
    walk(j);
    return [...new Set(found)];
  } catch { return []; }
}

async function runBOPLA(target: string, scanId: string, admin: any) {
  const findings: any[] = [];
  const base = norm(target);
  if (!base || PRIVATE.test(base.hostname)) return findings;
  const host = base.hostname;

  // Load auth sessions for this scan
  const { data: sessions } = await admin
    .from("scan_auth_sessions")
    .select("*")
    .eq("scan_id", scanId);

  const sA = sessions?.find((s: any) => s.user_label === "user_a") || sessions?.[0];
  const sB = sessions?.find((s: any) => s.user_label === "user_b") || sessions?.[1];

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
      source_module: "vapt-bopla",
      evidence: f.evidence,
      raw_data: { scan_id: scanId, owasp: f.owasp, mitre: f.mitre, cwe: f.cwe, payload: f.payload },
      hash_signature: hashHex,
    });
    findings.push(f);
  };

  // Pass 1: BOPLA — single-session sensitive property exposure
  for (const path of COMMON_ID_PATHS) {
    try {
      const url = new URL(path, base).toString();
      const r = await safeFetch(url, { headers: sA ? buildHeaders(sA) : { Accept: "application/json" } }, 6000);
      if (r.status !== 200) continue;
      const txt = await r.text();
      if (txt.length > 100000) continue;
      const leaks = extractSensitiveProps(txt);
      if (leaks.length > 0) {
        await insert({
          url_path: url,
          finding_type: "bopla_excessive_data",
          title: "Excessive Data Exposure (BOPLA — API3:2023)",
          description: `Endpoint returns sensitive object properties: ${leaks.slice(0, 5).join(", ")}. Client filtering is insufficient; server should not return these fields.`,
          severity: leaks.some(l => /password|hash|secret|token|api[_-]?key|private/i.test(l)) ? "high" : "medium",
          confidence: 85,
          owasp: "A01",
          mitre: ["T1213"],
          cwe: "CWE-213",
          evidence: { leaked_properties: leaks.slice(0, 20), sample: txt.slice(0, 500) },
        });
      }
    } catch { /* skip */ }
  }

  // Pass 2: BOLA — cross-session diff (only if both sessions exist)
  if (sA && sB) {
    for (const path of COMMON_ID_PATHS) {
      try {
        const url = new URL(path, base).toString();
        const [rA, rB] = await Promise.all([
          safeFetch(url, { headers: buildHeaders(sA) }, 6000),
          safeFetch(url, { headers: buildHeaders(sB) }, 6000),
        ]);
        if (rA.status === 200 && rB.status === 200) {
          const [tA, tB] = await Promise.all([rA.text(), rB.text()]);
          if (tA.length > 50 && tB.length > 50 && tA === tB) {
            // Both users see identical data for a numeric ID resource — suggests no ownership check
            await insert({
              url_path: url,
              finding_type: "bola_cross_user_access",
              title: "Broken Object-Level Authorization (BOLA — API1:2023)",
              description: "Two different authenticated users received identical responses for an ID-scoped resource. The server is not enforcing object ownership.",
              severity: "critical",
              confidence: 85,
              owasp: "A01",
              mitre: ["T1190"],
              cwe: "CWE-639",
              vulnerable_parameter: "id",
              evidence: {
                user_a: sA.user_label,
                user_b: sB.user_label,
                response_a_sample: tA.slice(0, 400),
                response_b_sample: tB.slice(0, 400),
              },
            });
          }
        } else if (rA.status === 200 && rB.status >= 400 && rB.status !== 404) {
          // user_a authorized, user_b denied — proper authz, do nothing
        } else if (rA.status === 200 && rB.status === 200) {
          // both 200 with different bodies — review needed but lower confidence
        }
      } catch { /* skip */ }
    }
  }

  return findings;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const body = await req.json();
    const { scanId, target, passNumber = 9, passName = "bopla_scan" } = body;
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

    const findings = await runBOPLA(target, scanId, admin);

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
