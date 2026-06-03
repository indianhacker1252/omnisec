// OmniSec™ © HARSH MALIK — GraphQL Gap-Closure Scanner
// Introspection probe + suggestion-leak + auth/field fuzz. Inserts findings into recon_findings
// so they appear in the live stream. Closes pass 7 of the multi-pass chain.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const PRIVATE = /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.|::1|localhost)/i;

const GQL_PATHS = [
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query",
  "/graphiql", "/api", "/v1/api", "/gql",
];

const INTROSPECTION_QUERY = `query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind fields { name args { name } type { name } } }
  }
}`;

const SUGGESTION_PROBES = [
  `{ __schema { types { name } } }`,
  `{ users { id email password } }`,
  `{ user(id: "1") { email role } }`,
  `query { invalidField }`,
];

async function safeFetch(url: string, init: RequestInit, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal, redirect: "follow" });
  } finally {
    clearTimeout(t);
  }
}

function normalizeTarget(t: string) {
  let u = t.trim();
  if (!/^https?:\/\//i.test(u)) u = "https://" + u;
  try { return new URL(u); } catch { return null; }
}

async function findGraphQLEndpoint(base: URL): Promise<string | null> {
  for (const p of GQL_PATHS) {
    try {
      const url = new URL(p, base).toString();
      const r = await safeFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ query: "{ __typename }" }),
      }, 5000);
      const txt = await r.text();
      if (
        r.status < 500 &&
        (txt.includes("__typename") ||
          txt.toLowerCase().includes("graphql") ||
          txt.includes("errors") && txt.includes("query"))
      ) return url;
    } catch { /* skip */ }
  }
  return null;
}

async function runGraphQLScan(target: string, scanId: string, admin: any) {
  const findings: any[] = [];
  const url = normalizeTarget(target);
  if (!url) return findings;
  if (PRIVATE.test(url.hostname)) return findings;

  const endpoint = await findGraphQLEndpoint(url);
  if (!endpoint) return findings;

  const host = url.hostname;
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
      source_module: "vapt-graphql",
      evidence: f.evidence,
      raw_data: { scan_id: scanId, owasp: f.owasp, mitre: f.mitre, cwe: f.cwe, payload: f.payload },
      hash_signature: hashHex,
    });
    findings.push(f);
  };

  // 1. Introspection enabled?
  try {
    const r = await safeFetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: INTROSPECTION_QUERY }),
    }, 10000);
    const data = await r.json().catch(() => ({}));
    if (data?.data?.__schema?.types) {
      const types = data.data.__schema.types || [];
      const sensitive = types.filter((t: any) =>
        /user|admin|token|secret|password|credential|payment|invoice/i.test(t?.name || "")
      );
      await insert({
        url_path: endpoint,
        finding_type: "graphql_introspection",
        title: "GraphQL Introspection Enabled",
        description: `Introspection query returned full schema (${types.length} types). Sensitive types exposed: ${sensitive.map((t: any) => t.name).slice(0, 10).join(", ") || "none"}.`,
        severity: sensitive.length > 0 ? "high" : "medium",
        confidence: 95,
        owasp: "A05",
        mitre: ["T1592", "T1213"],
        cwe: "CWE-200",
        payload: INTROSPECTION_QUERY.slice(0, 200),
        evidence: {
          type_count: types.length,
          sensitive_types: sensitive.map((t: any) => t.name).slice(0, 20),
          query_type: data.data.__schema.queryType?.name,
          mutation_type: data.data.__schema.mutationType?.name,
        },
      });
    }
  } catch { /* ignore */ }

  // 2. Suggestion / field-name leak via misspellings
  try {
    const r = await safeFetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: `{ usrs { id } }` }),
    }, 8000);
    const txt = await r.text();
    if (/did you mean/i.test(txt)) {
      await insert({
        url_path: endpoint,
        finding_type: "graphql_field_suggestion",
        title: "GraphQL Field Suggestions Enabled",
        description: "Server returns 'Did you mean ...' hints for unknown fields, leaking schema info even when introspection is disabled.",
        severity: "low",
        confidence: 90,
        owasp: "A05",
        cwe: "CWE-209",
        evidence: { sample: txt.slice(0, 400) },
      });
    }
  } catch { /* ignore */ }

  // 3. Auth-on-introspection: same query without Authorization header
  for (const probe of SUGGESTION_PROBES) {
    try {
      const r = await safeFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: probe }),
      }, 6000);
      const txt = await r.text();
      // Heuristic: returns data field for sensitive query without auth
      if (r.status === 200 && /"data":\s*\{[^}]*"users"/i.test(txt) && !/null/.test(txt)) {
        await insert({
          url_path: endpoint,
          finding_type: "graphql_unauthenticated_data",
          title: "GraphQL Unauthenticated Data Access",
          description: "Sensitive query (users{...}) returned data without an Authorization header.",
          severity: "high",
          confidence: 80,
          owasp: "A01",
          mitre: ["T1190"],
          cwe: "CWE-862",
          payload: probe,
          evidence: { sample: txt.slice(0, 600) },
          vulnerable_parameter: "users",
        });
        break;
      }
    } catch { /* ignore */ }
  }

  return findings;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const body = await req.json();
    const { scanId, target, passNumber = 7, passName = "graphql_scan" } = body;
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

    const findings = await runGraphQLScan(target, scanId, admin);

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
