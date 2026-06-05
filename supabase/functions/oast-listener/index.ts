// OmniSec™ © HARSH MALIK
// oast-listener — public callback endpoint for blind/async vulnerability detection.
// Captures any inbound request (DNS-only resolution is captured upstream via separate
// DNS log; this handles HTTP/HTTPS callbacks). Correlates by ?t=<token> matched to
// scan_canaries.canary_token. Anyone on the internet can hit this — that's the point.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const u = new URL(req.url);
    const token = u.searchParams.get("t") || u.pathname.split("/").pop() || "unknown";
    const sourceIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    const ua = req.headers.get("user-agent") || "";
    let body = "";
    try { body = (await req.text()).slice(0, 2000); } catch {}

    // Look up the canary
    const { data: canary } = await supabase
      .from("scan_canaries")
      .select("scan_id, target, injected_into")
      .eq("canary_token", token)
      .maybeSingle();

    if (canary) {
      const evidence = {
        method: req.method, sourceIp, userAgent: ua, token,
        headers: Object.fromEntries(req.headers.entries()),
        body: body.slice(0, 500),
        receivedAt: new Date().toISOString(),
      };
      const hashSrc = `${canary.scan_id}:${token}:${sourceIp}`;
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(hashSrc));
      const hash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");

      await supabase.from("recon_findings").upsert({
        scan_id: canary.scan_id,
        target_host: canary.target,
        url_path: canary.injected_into || "oast",
        finding_type: "oast_callback",
        title: `🔥 OAST callback received from ${sourceIp}`,
        description: `Out-of-band callback confirms blind injection (SSRF / blind SQLi / async command injection / deserialization). Source IP ${sourceIp} resolved/fetched the canary URL, proving server-side execution.`,
        severity: "critical",
        confidence_score: 1.0,
        verification_status: "verified",
        source_module: "oast-listener",
        hash_signature: hash,
        evidence,
        raw_data: { scan_id: canary.scan_id, owasp: "A10:2021", mitre: "T1090.003", cwe: "CWE-918", cvss: 9.8 },
      }, { onConflict: "hash_signature" });
    }

    return new Response(JSON.stringify({ ack: true, token }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
