import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * Threat Intelligence Learning Engine
 * Fetches latest CVEs from NVD, GitHub advisories, and security research
 * to enrich the autonomous scanner's knowledge base.
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const authClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );
    const { data: { user }, error: authError } = await authClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const body = await req.json();
    const { technologies = [], action = "learn" } = body;

    const results: any = { nvdCVEs: [], githubAdvisories: [], hacktivityPatterns: [], timestamp: new Date().toISOString() };

    // 1. Fetch latest CVEs from NVD for detected technologies
    const techQueries = technologies.length > 0 ? technologies.slice(0, 5) : ["web application", "sql injection", "xss"];
    
    for (const tech of techQueries) {
      try {
        const nvdUrl = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
        nvdUrl.searchParams.set("keywordSearch", tech);
        nvdUrl.searchParams.set("resultsPerPage", "10");
        
        const NVD_API_KEY = Deno.env.get("NVD_API_KEY");
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (NVD_API_KEY) headers["apiKey"] = NVD_API_KEY;

        const resp = await fetch(nvdUrl.toString(), { headers });
        if (resp.ok) {
          const data = await resp.json();
          const cves = (data.vulnerabilities || []).slice(0, 5).map((v: any) => {
            const cve = v.cve;
            const metrics = cve.metrics || {};
            const cvss = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore
              ?? metrics.cvssMetricV30?.[0]?.cvssData?.baseScore ?? null;
            const severity = metrics.cvssMetricV31?.[0]?.cvssData?.baseSeverity
              ?? metrics.cvssMetricV30?.[0]?.cvssData?.baseSeverity ?? "unknown";
            return {
              id: cve.id,
              description: cve.descriptions?.[0]?.value?.slice(0, 200) || "",
              cvss,
              severity: severity.toLowerCase(),
              published: cve.published,
              technology: tech,
              exploitAvailable: cve.references?.some((r: any) => r.tags?.includes("Exploit")) || false,
            };
          });
          results.nvdCVEs.push(...cves);
        }
      } catch (e) {
        console.log(`NVD fetch error for ${tech}:`, e);
      }
    }

    // 2. Fetch GitHub Security Advisories
    try {
      const ghResp = await fetch("https://api.github.com/advisories?per_page=15&type=reviewed", {
        headers: { "Accept": "application/vnd.github+json", "User-Agent": "OmniSec-ThreatIntel/1.0" },
      });
      if (ghResp.ok) {
        const advisories = await ghResp.json();
        results.githubAdvisories = advisories.slice(0, 10).map((a: any) => ({
          id: a.ghsa_id,
          summary: a.summary?.slice(0, 200) || "",
          severity: a.severity || "unknown",
          cvss: a.cvss?.score || null,
          cve_id: a.cve_id,
          published: a.published_at,
          ecosystem: a.vulnerabilities?.[0]?.package?.ecosystem || "unknown",
          package: a.vulnerabilities?.[0]?.package?.name || "unknown",
          patchedVersions: a.vulnerabilities?.[0]?.patched_versions || "",
        }));
      }
    } catch (e) {
      console.log("GitHub advisories error:", e);
    }

    // 3. Common HackerOne hacktivity patterns (curated knowledge)
    results.hacktivityPatterns = [
      { type: "sqli", pattern: "Error-based SQLi via search params", bountyRange: "$500-$5000", frequency: "high", testPayloads: ["' OR '1'='1", "1' AND SLEEP(5)--", "' UNION SELECT NULL,NULL--"] },
      { type: "xss", pattern: "Reflected XSS in error messages", bountyRange: "$200-$2000", frequency: "high", testPayloads: ["<img src=x onerror=alert(1)>", "'\"><svg/onload=alert(1)>", "javascript:alert(document.cookie)"] },
      { type: "idor", pattern: "IDOR in API endpoints via sequential IDs", bountyRange: "$500-$10000", frequency: "medium", testPayloads: ["/api/v1/user/1 vs /api/v1/user/2", "/api/orders/100 vs /api/orders/101"] },
      { type: "ssrf", pattern: "SSRF via URL parameters (redirect, callback, url)", bountyRange: "$1000-$15000", frequency: "medium", testPayloads: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:6379/", "http://[::1]:80/"] },
      { type: "rce", pattern: "Command injection via file processing", bountyRange: "$5000-$50000", frequency: "low", testPayloads: ["; id", "| whoami", "`cat /etc/passwd`", "$(id)"] },
      { type: "auth_bypass", pattern: "JWT none algorithm / weak secret", bountyRange: "$1000-$5000", frequency: "medium", testPayloads: ["eyJ...alg:none", "Header manipulation: X-Forwarded-For: 127.0.0.1"] },
      { type: "cors", pattern: "Wildcard CORS with credentials", bountyRange: "$200-$2000", frequency: "high", testPayloads: ["Origin: https://evil.com", "Origin: null"] },
      { type: "open_redirect", pattern: "Open redirect in login/logout flows", bountyRange: "$100-$1000", frequency: "high", testPayloads: ["/login?redirect=https://evil.com", "/logout?next=//evil.com"] },
      { type: "info_disclosure", pattern: "Source code/config exposure via .git/.env", bountyRange: "$200-$3000", frequency: "medium", testPayloads: ["/.git/config", "/.env", "/debug", "/phpinfo.php", "/.svn/entries"] },
      { type: "race_condition", pattern: "TOCTOU in coupon/balance operations", bountyRange: "$500-$5000", frequency: "low", testPayloads: ["Send 50 concurrent requests to /api/redeem"] },
    ];

    // 4. Generate test recommendations based on findings
    const testRecommendations = results.nvdCVEs
      .filter((c: any) => c.exploitAvailable && c.severity !== "low")
      .map((c: any) => ({
        cveId: c.id,
        technology: c.technology,
        action: `Test for ${c.id}: ${c.description.slice(0, 100)}`,
        priority: c.severity === "critical" ? 1 : c.severity === "high" ? 2 : 3,
      }));

    results.testRecommendations = testRecommendations;
    results.totalCVEs = results.nvdCVEs.length;
    results.totalAdvisories = results.githubAdvisories.length;
    results.totalPatterns = results.hacktivityPatterns.length;

    console.log(`Threat intel: ${results.totalCVEs} CVEs, ${results.totalAdvisories} advisories, ${results.totalPatterns} patterns`);

    return new Response(JSON.stringify(results), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("threat-intel-learn error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
