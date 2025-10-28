import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { query } = await req.json();
    if (!query || typeof query !== "string") {
      return new Response(JSON.stringify({ error: "Missing query" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const NVD_API_KEY = Deno.env.get("NVD_API_KEY");
    const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    url.searchParams.set("keywordSearch", query);
    url.searchParams.set("resultsPerPage", "20");

    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (NVD_API_KEY) headers["apiKey"] = NVD_API_KEY;

    const r = await fetch(url.toString(), { headers });
    if (!r.ok) {
      const t = await r.text();
      console.error("NVD error", r.status, t);
      return new Response(JSON.stringify({ error: "NVD API error", details: t }), { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const data = await r.json();

    const vulns = (data.vulnerabilities || []).map((v: any) => {
      const cve = v.cve;
      const id = cve.id;
      const desc = cve.descriptions?.[0]?.value || "";
      const metrics = cve.metrics || {};
      const cvss = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore
        ?? metrics.cvssMetricV30?.[0]?.cvssData?.baseScore
        ?? metrics.cvssMetricV2?.[0]?.cvssData?.baseScore
        ?? null;
      const severity = metrics.cvssMetricV31?.[0]?.cvssData?.baseSeverity
        ?? metrics.cvssMetricV30?.[0]?.cvssData?.baseSeverity
        ?? metrics.cvssMetricV2?.[0]?.baseSeverity
        ?? null;

      return {
        id,
        cve: id,
        title: cve?.sourceIdentifier || id,
        description: desc,
        cvss: cvss,
        severity: (severity || "unknown").toLowerCase(),
        timestamp: cve.published || cve.lastModified || new Date().toISOString(),
      };
    });

    return new Response(JSON.stringify({ count: vulns.length, vulnerabilities: vulns }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("vulnintel error", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});