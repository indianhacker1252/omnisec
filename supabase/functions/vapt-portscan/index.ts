// OmniSec™ © HARSH MALIK — Port + Service Discovery via Shodan, CVE mapping via NVD
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface PortFinding {
  port: number;
  transport: string;
  service: string;
  product?: string;
  version?: string;
  banner?: string;
  cves: Array<{ id: string; cvss?: number; summary?: string }>;
}

async function resolveHost(target: string): Promise<string> {
  let host = target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  // Block private/loopback
  if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0|localhost)/i.test(host)) {
    throw new Error("Private/loopback host blocked (SSRF protection)");
  }
  return host;
}

async function shodanLookup(host: string, apiKey: string): Promise<any> {
  // Resolve to IP first
  const dns = await fetch(`https://api.shodan.io/dns/resolve?hostnames=${host}&key=${apiKey}`);
  if (!dns.ok) throw new Error(`Shodan DNS failed: ${dns.status}`);
  const dnsData = await dns.json();
  const ip = dnsData[host];
  if (!ip) throw new Error(`Could not resolve ${host}`);

  // Block private resolved IP
  if (/^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(ip)) {
    throw new Error(`Resolved IP ${ip} is private — blocked`);
  }

  const r = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
  if (r.status === 404) return { ip, data: [] };
  if (!r.ok) throw new Error(`Shodan host failed: ${r.status}`);
  return { ip, ...(await r.json()) };
}

async function nvdCveLookup(product: string, version?: string): Promise<any[]> {
  if (!product) return [];
  const kw = version ? `${product} ${version}` : product;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(kw)}&resultsPerPage=5`;
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!r.ok) return [];
    const j = await r.json();
    return (j.vulnerabilities || []).map((v: any) => {
      const c = v.cve;
      const metrics = c.metrics?.cvssMetricV31?.[0]?.cvssData
        || c.metrics?.cvssMetricV30?.[0]?.cvssData
        || c.metrics?.cvssMetricV2?.[0]?.cvssData;
      return {
        id: c.id,
        cvss: metrics?.baseScore,
        summary: c.descriptions?.[0]?.value?.slice(0, 300),
      };
    });
  } catch {
    return [];
  }
}

function severityFromCvss(cvss?: number): string {
  if (!cvss) return "info";
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
}

async function streamFinding(supabase: any, scanId: string, host: string, f: PortFinding) {
  for (const cve of f.cves.length ? f.cves : [{ id: "no-cve" }]) {
    const isCve = cve.id !== "no-cve";
    const title = isCve
      ? `${cve.id} — ${f.service}/${f.product || "?"} ${f.version || ""} on port ${f.port}`
      : `Open port ${f.port}/${f.transport} (${f.service}) on ${host}`;
    const sev = isCve ? severityFromCvss((cve as any).cvss) : "info";
    const hashSrc = `${host}:${f.port}:${cve.id}`;
    const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(hashSrc));
    const hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");

    await supabase.from("recon_findings").upsert({
      scan_id: scanId,
      target_host: host,
      url_path: `port:${f.port}`,
      finding_type: isCve ? "cve" : "open_port",
      title,
      description: isCve ? (cve as any).summary : `${f.service} ${f.product || ""} ${f.version || ""} ${f.banner?.slice(0, 200) || ""}`.trim(),
      severity: sev,
      vulnerable_parameter: `port_${f.port}`,
      confidence_score: isCve ? 0.7 : 0.95,
      verification_status: "passive",
      source_module: "vapt-portscan",
      hash_signature: hash,
      evidence: { port: f.port, service: f.service, product: f.product, version: f.version, banner: f.banner?.slice(0, 500) },
      raw_data: {
        scan_id: scanId,
        owasp: isCve ? "A06:2021" : "A05:2021",
        mitre: "T1046",
        cwe: isCve ? "CWE-1104" : "CWE-200",
        cvss: (cve as any).cvss,
        category: "infrastructure",
        cve: isCve ? cve.id : undefined,
      },
    }, { onConflict: "hash_signature" });
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );
    const body = await req.json();
    const { scanId, target, passNumber = 10, passName = "port_service_scan" } = body;
    if (!scanId || !target) return new Response(JSON.stringify({ error: "scanId and target required" }), { status: 400, headers: corsHeaders });

    const shodanKey = Deno.env.get("SHODAN_API_KEY");
    if (!shodanKey) return new Response(JSON.stringify({ error: "SHODAN_API_KEY missing" }), { status: 500, headers: corsHeaders });

    const host = await resolveHost(target);

    await supabase.from("scan_passes").update({ status: "running", started_at: new Date().toISOString() })
      .eq("scan_id", scanId).eq("pass_number", passNumber);

    const shodan = await shodanLookup(host, shodanKey);
    const services = shodan.data || [];
    const findings: PortFinding[] = [];

    for (const svc of services.slice(0, 30)) {
      const product = svc.product || svc._shodan?.module;
      const cves = await nvdCveLookup(product, svc.version);
      const f: PortFinding = {
        port: svc.port,
        transport: svc.transport || "tcp",
        service: svc._shodan?.module || svc.product || "unknown",
        product,
        version: svc.version,
        banner: svc.data,
        cves,
      };
      findings.push(f);
      await streamFinding(supabase, scanId, host, f);
    }

    await supabase.from("scan_passes").update({
      status: "completed",
      completed_at: new Date().toISOString(),
      payload: { ports: findings.length, cves: findings.reduce((s, f) => s + f.cves.length, 0), ip: shodan.ip },
    }).eq("scan_id", scanId).eq("pass_number", passNumber);

    return new Response(JSON.stringify({ ok: true, host, ip: shodan.ip, findings: findings.length, cves: findings.reduce((s, f) => s + f.cves.length, 0) }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
