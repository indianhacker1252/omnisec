import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { target } = await req.json();
    console.log("Starting web app scan for:", target);

    if (!target) {
      throw new Error("Target URL is required");
    }

    const findings = [];
    const startTime = Date.now();

    // Parse target URL
    let url: URL;
    try {
      url = new URL(target.startsWith('http') ? target : `https://${target}`);
    } catch {
      throw new Error("Invalid URL format");
    }

    console.log("Scanning:", url.toString());

    // 1. Check for common security headers
    try {
      const response = await fetch(url.toString(), { method: "HEAD" });
      const headers = response.headers;

      if (!headers.get("X-Frame-Options")) {
        findings.push({
          severity: "high",
          title: "Missing X-Frame-Options Header",
          description: "The application is vulnerable to clickjacking attacks",
          url: url.toString(),
          cwe: "CWE-1021"
        });
      }

      if (!headers.get("Content-Security-Policy")) {
        findings.push({
          severity: "medium",
          title: "Missing Content-Security-Policy",
          description: "No CSP header found, vulnerable to XSS attacks",
          url: url.toString(),
          cwe: "CWE-79"
        });
      }

      if (!headers.get("Strict-Transport-Security")) {
        findings.push({
          severity: "medium",
          title: "Missing HSTS Header",
          description: "Application vulnerable to protocol downgrade attacks",
          url: url.toString(),
          cwe: "CWE-319"
        });
      }

      const xssProtection = headers.get("X-XSS-Protection");
      if (!xssProtection || xssProtection === "0") {
        findings.push({
          severity: "high",
          title: "XSS Protection Disabled",
          description: "Browser XSS filter is disabled or not configured",
          url: url.toString(),
          cwe: "CWE-79"
        });
      }

      const server = headers.get("Server");
      if (server) {
        findings.push({
          severity: "low",
          title: "Server Version Disclosure",
          description: `Server header reveals: ${server}`,
          url: url.toString(),
          cwe: "CWE-200"
        });
      }

      const xPoweredBy = headers.get("X-Powered-By");
      if (xPoweredBy) {
        findings.push({
          severity: "low",
          title: "Technology Stack Disclosure",
          description: `X-Powered-By header reveals: ${xPoweredBy}`,
          url: url.toString(),
          cwe: "CWE-200"
        });
      }
    } catch (e) {
      console.error("Error checking headers:", e);
    }

    // 2. Test for common vulnerabilities
    const testPaths = [
      "/.git/config",
      "/.env",
      "/admin",
      "/phpinfo.php",
      "/server-status",
      "/.well-known/security.txt",
      "/robots.txt",
      "/sitemap.xml"
    ];

    for (const path of testPaths) {
      try {
        const testUrl = new URL(path, url.origin).toString();
        const response = await fetch(testUrl, { 
          method: "GET",
          redirect: "manual"
        });
        
        if (response.status === 200) {
          findings.push({
            severity: path.includes(".git") || path.includes(".env") ? "critical" : "info",
            title: `Exposed Path: ${path}`,
            description: `Sensitive path is publicly accessible (Status: ${response.status})`,
            url: testUrl,
            method: "GET"
          });
        }
      } catch (e: any) {
        console.log(`Path ${path} not accessible:`, e?.message || "Unknown error");
      }
    }

    // 3. Check SSL/TLS configuration
    if (url.protocol === "https:") {
      findings.push({
        severity: "info",
        title: "HTTPS Enabled",
        description: "Site uses HTTPS encryption",
        url: url.toString()
      });
    } else {
      findings.push({
        severity: "critical",
        title: "No HTTPS",
        description: "Site does not use HTTPS encryption - all traffic is in plaintext",
        url: url.toString(),
        cwe: "CWE-319"
      });
    }

    const scanTime = Date.now() - startTime;
    console.log(`Scan completed in ${scanTime}ms, found ${findings.length} issues`);

    return new Response(
      JSON.stringify({
        success: true,
        target: url.toString(),
        findings,
        scanTime,
        timestamp: new Date().toISOString()
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error: any) {
    console.error("Scan error:", error);
    return new Response(
      JSON.stringify({ 
        error: error?.message || "Unknown error",
        success: false 
      }),
      { 
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      }
    );
  }
});
