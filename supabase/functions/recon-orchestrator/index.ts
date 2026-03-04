import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// Generate a unique hash for deduplication
function generateFindingHash(host: string, path: string, param: string, type: string): string {
  const raw = `${host}|${path || ""}|${param || ""}|${type}`.toLowerCase();
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    const char = raw.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(36) + "-" + raw.length.toString(36);
}

// DNS resolution via Google DoH
async function resolveDNS(subdomain: string): Promise<{ alive: boolean; ip?: string }> {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`, {
      signal: AbortSignal.timeout(5000),
    });
    const data = await r.json();
    const ip = data?.Answer?.find((a: any) => a.type === 1)?.data;
    return { alive: !!ip, ip };
  } catch {
    return { alive: false };
  }
}

// Secondary verification: actually probe the host
async function verifyFinding(url: string, findingType: string): Promise<{ verified: boolean; evidence: any }> {
  try {
    const resp = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
      headers: { "User-Agent": "OmniSec-Verifier/1.0" },
    });

    const status = resp.status;
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headers[k] = v; });
    const bodySnippet = (await resp.text()).slice(0, 2000);

    // Verification logic per finding type
    if (findingType === "sensitive_file") {
      // A real sensitive file won't be a generic 404/error page
      const isFalsePositive = status === 404 || status === 403 ||
        bodySnippet.includes("Page Not Found") ||
        bodySnippet.includes("Access Denied") ||
        bodySnippet.length < 50;
      return {
        verified: !isFalsePositive && status === 200,
        evidence: { status, bodyLength: bodySnippet.length, headers },
      };
    }

    if (findingType === "open_port" || findingType === "service_detected") {
      return { verified: status < 500, evidence: { status, headers } };
    }

    if (findingType === "subdomain_takeover") {
      const takeoverIndicators = [
        "There isn't a GitHub Pages site here",
        "NoSuchBucket",
        "NXDOMAIN",
        "404 Not Found",
        "This domain is not configured",
      ];
      const vuln = takeoverIndicators.some(i => bodySnippet.includes(i));
      return { verified: vuln, evidence: { status, matchedIndicator: vuln } };
    }

    // Default: trust 200 with non-trivial body
    return { verified: status === 200 && bodySnippet.length > 100, evidence: { status } };
  } catch (e: any) {
    return { verified: false, evidence: { error: e.message } };
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );

    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { action, domain, finding } = await req.json();

    // ---- ACTION: enumerate ----
    if (action === "enumerate") {
      if (!domain) throw new Error("Missing domain");
      const cleanDomain = domain.trim().replace(/^https?:\/\//, "").split("/")[0];

      // Common subdomain prefixes
      const prefixes = [
        "www","mail","ftp","webmail","smtp","pop","ns1","ns2","admin","blog",
        "dev","staging","test","api","app","m","cdn","static","assets","img",
        "shop","store","secure","portal","login","auth","sso","vpn","db",
        "mysql","postgres","redis","jenkins","gitlab","jira","wiki","docs",
        "support","status","monitor","metrics","analytics","crm","search",
        "demo","sandbox","beta","prod","backup","old","v1","v2","web",
        "email","marketing","forum","community","chat","calendar","cloud",
        "s3","storage","media","files","download","upload","gateway","proxy",
      ];

      // Phase 1: Bruteforce + DNS resolve in batches
      const visited = new Set<string>();
      const alive: Array<{ subdomain: string; ip: string }> = [];

      const batchSize = 15;
      for (let i = 0; i < prefixes.length; i += batchSize) {
        const batch = prefixes.slice(i, i + batchSize);
        const results = await Promise.all(
          batch.map(async (p) => {
            const sub = `${p}.${cleanDomain}`;
            if (visited.has(sub)) return null;
            visited.add(sub);
            const dns = await resolveDNS(sub);
            return dns.alive ? { subdomain: sub, ip: dns.ip! } : null;
          })
        );
        alive.push(...results.filter(Boolean) as any);
      }

      // Phase 2: crt.sh certificate transparency
      try {
        const crtResp = await fetch(`https://crt.sh/?q=%.${cleanDomain}&output=json`, {
          signal: AbortSignal.timeout(10000),
        });
        if (crtResp.ok) {
          const crtData = await crtResp.json();
          const ctSubs = new Set<string>();
          for (const cert of crtData.slice(0, 150)) {
            for (const name of (cert.name_value?.split("\n") || [])) {
              const clean = name.replace(/^\*\./, "").toLowerCase().trim();
              if (clean.endsWith(cleanDomain) && !clean.includes("*") && !visited.has(clean)) {
                ctSubs.add(clean);
                visited.add(clean);
              }
            }
          }
          const ctBatch = Array.from(ctSubs).slice(0, 50);
          for (let i = 0; i < ctBatch.length; i += batchSize) {
            const batch = ctBatch.slice(i, i + batchSize);
            const results = await Promise.all(
              batch.map(async (sub) => {
                const dns = await resolveDNS(sub);
                return dns.alive ? { subdomain: sub, ip: dns.ip! } : null;
              })
            );
            alive.push(...results.filter(Boolean) as any);
          }
        }
      } catch { /* crt.sh timeout is non-fatal */ }

      // Check root domain
      if (!visited.has(cleanDomain)) {
        const rootDns = await resolveDNS(cleanDomain);
        if (rootDns.alive) alive.unshift({ subdomain: cleanDomain, ip: rootDns.ip! });
      }

      // Deduplicate by subdomain
      const unique = Array.from(new Map(alive.map(a => [a.subdomain, a])).values());

      // Insert into recon_queue (upsert to avoid dupes)
      for (const sub of unique) {
        await supabaseClient.from("recon_queue").upsert({
          domain: cleanDomain,
          subdomain: sub.subdomain,
          ip_address: sub.ip,
          status: "pending",
          scan_phase: "dns_verified",
          parent_domain: cleanDomain,
        }, { onConflict: "subdomain" });
      }

      return new Response(JSON.stringify({
        success: true,
        domain: cleanDomain,
        subdomains: unique,
        total: unique.length,
        queuedForScanning: unique.length,
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ---- ACTION: verify ----
    if (action === "verify" && finding) {
      const url = finding.url || `https://${finding.target_host}${finding.url_path || ""}`;
      const result = await verifyFinding(url, finding.finding_type);

      // Update finding verification status
      if (finding.id) {
        await supabaseClient.from("recon_findings").update({
          verification_status: result.verified ? "verified" : "false_positive",
          evidence: result.evidence,
          confidence_score: result.verified ? 85 : 15,
        }).eq("id", finding.id);
      }

      return new Response(JSON.stringify({
        success: true,
        verified: result.verified,
        evidence: result.evidence,
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ---- ACTION: normalize (dedup + insert finding) ----
    if (action === "normalize" && finding) {
      const hash = generateFindingHash(
        finding.target_host,
        finding.url_path || "",
        finding.vulnerable_parameter || "",
        finding.finding_type,
      );

      // Check if hash exists
      const { data: existing } = await supabaseClient
        .from("recon_findings")
        .select("id, seen_count")
        .eq("hash_signature", hash)
        .maybeSingle();

      if (existing) {
        // Update last_seen and increment count
        await supabaseClient.from("recon_findings").update({
          last_seen: new Date().toISOString(),
          seen_count: (existing.seen_count || 1) + 1,
        }).eq("id", existing.id);

        return new Response(JSON.stringify({
          success: true,
          deduplicated: true,
          existingId: existing.id,
          hash,
        }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      // Insert new finding
      const { data: newFinding, error: insertError } = await supabaseClient
        .from("recon_findings")
        .insert({
          hash_signature: hash,
          target_host: finding.target_host,
          url_path: finding.url_path || null,
          vulnerable_parameter: finding.vulnerable_parameter || null,
          finding_type: finding.finding_type,
          title: finding.title,
          description: finding.description || null,
          severity: finding.severity || "info",
          verification_status: "pending",
          source_module: finding.source_module || "recon",
          raw_data: finding.raw_data || null,
        })
        .select()
        .single();

      if (insertError) throw insertError;

      return new Response(JSON.stringify({
        success: true,
        deduplicated: false,
        finding: newFinding,
        hash,
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ---- ACTION: queue-status ----
    if (action === "queue-status") {
      const { data: queueItems } = await supabaseClient
        .from("recon_queue")
        .select("status, count")
        .then(({ data }) => {
          const counts: Record<string, number> = {};
          (data || []).forEach((item: any) => {
            counts[item.status] = (counts[item.status] || 0) + 1;
          });
          return { data: counts };
        });

      return new Response(JSON.stringify({
        success: true,
        queue: queueItems,
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    throw new Error(`Unknown action: ${action}`);
  } catch (e: any) {
    console.error("Recon orchestrator error:", e);
    return new Response(JSON.stringify({ error: e.message, success: false }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
