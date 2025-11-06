import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

function validateTarget(url: string): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    
    const blockedPatterns = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^192\.168\./,
      /^127\./,
      /^169\.254\./,
      /^0\./,
      /localhost/i,
      /metadata/i,
      /internal/i,
    ];
    
    return !blockedPatterns.some(p => p.test(hostname));
  } catch {
    return false;
  }
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    // Initialize Supabase client
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );

    // Authenticate user
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Check admin or analyst role
    const { data: roles } = await supabaseClient
      .from("user_roles")
      .select("role")
      .eq("user_id", user.id);

    const hasAccess = roles?.some((r: any) => ["admin", "analyst"].includes(r.role));
    if (!hasAccess) {
      return new Response(JSON.stringify({ 
        error: "Analyst or Admin role required for web application scanning" 
      }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { target } = await req.json();
    
    if (!target) {
      return new Response(
        JSON.stringify({ error: "Invalid request" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!validateTarget(target)) {
      return new Response(
        JSON.stringify({ error: "Invalid target URL" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const findings = [];
    const startTime = Date.now();

    // Parse target URL
    let url: URL;
    try {
      url = new URL(target.startsWith('http') ? target : `https://${target}`);
    } catch {
      return new Response(
        JSON.stringify({ error: "Invalid URL format" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
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

    // Audit log
    await supabaseClient.from("security_audit_log").insert({
      user_id: user.id,
      action: "webapp_scan_completed",
      resource_type: "web_application",
      resource_id: url.toString(),
      details: {
        target: url.toString(),
        findings_count: findings.length,
        critical_count: findings.filter((f: any) => f.severity === "critical").length,
        high_count: findings.filter((f: any) => f.severity === "high").length,
        scan_time_ms: scanTime,
        timestamp: new Date().toISOString()
      },
      ip_address: req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || "unknown"
    });

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
