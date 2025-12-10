import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

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
    const { target } = await req.json();
    
    if (!target) {
      return new Response(
        JSON.stringify({ error: "Missing target URL", success: false }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Parse target URL
    let url: URL;
    try {
      url = new URL(target.startsWith('http') ? target : `https://${target}`);
    } catch {
      return new Response(
        JSON.stringify({ error: "Invalid URL format", success: false }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    if (!validateTarget(url.toString())) {
      return new Response(
        JSON.stringify({ error: "Invalid target URL - internal/private addresses not allowed", success: false }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const findings: any[] = [];
    const startTime = Date.now();

    console.log("Starting security scan for:", url.toString());

    // 1. Check for common security headers
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      
      const response = await fetch(url.toString(), { 
        method: "GET",
        signal: controller.signal,
        headers: {
          "User-Agent": "OmniSec Security Scanner/1.0"
        }
      });
      clearTimeout(timeoutId);
      
      const headers = response.headers;

      console.log("Response status:", response.status);

      // Security header checks
      if (!headers.get("X-Frame-Options")) {
        findings.push({
          severity: "high",
          title: "Missing X-Frame-Options Header",
          description: "The application is vulnerable to clickjacking attacks. An attacker could embed this page in an iframe and trick users into clicking hidden elements.",
          url: url.toString(),
          cwe: "CWE-1021",
          remediation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header"
        });
      }

      if (!headers.get("Content-Security-Policy")) {
        findings.push({
          severity: "medium",
          title: "Missing Content-Security-Policy",
          description: "No CSP header found. The application may be vulnerable to XSS attacks as browsers cannot restrict resource loading.",
          url: url.toString(),
          cwe: "CWE-79",
          remediation: "Implement a strict Content-Security-Policy header"
        });
      }

      if (!headers.get("Strict-Transport-Security")) {
        findings.push({
          severity: "medium",
          title: "Missing HSTS Header",
          description: "Application is vulnerable to protocol downgrade attacks and cookie hijacking. Users could be redirected to HTTP.",
          url: url.toString(),
          cwe: "CWE-319",
          remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
        });
      }

      if (!headers.get("X-Content-Type-Options")) {
        findings.push({
          severity: "low",
          title: "Missing X-Content-Type-Options Header",
          description: "Browser may MIME-sniff responses away from declared content-type, enabling attacks.",
          url: url.toString(),
          cwe: "CWE-430",
          remediation: "Add 'X-Content-Type-Options: nosniff' header"
        });
      }

      const server = headers.get("Server");
      if (server) {
        findings.push({
          severity: "low",
          title: "Server Version Disclosure",
          description: `Server header reveals: "${server}". This information helps attackers identify known vulnerabilities.`,
          url: url.toString(),
          cwe: "CWE-200",
          remediation: "Remove or obfuscate the Server header"
        });
      }

      const xPoweredBy = headers.get("X-Powered-By");
      if (xPoweredBy) {
        findings.push({
          severity: "low",
          title: "Technology Stack Disclosure",
          description: `X-Powered-By header reveals: "${xPoweredBy}". This helps attackers identify framework-specific vulnerabilities.`,
          url: url.toString(),
          cwe: "CWE-200",
          remediation: "Remove the X-Powered-By header"
        });
      }

      // Check cookies
      const setCookie = headers.get("Set-Cookie");
      if (setCookie) {
        if (!setCookie.toLowerCase().includes("httponly")) {
          findings.push({
            severity: "medium",
            title: "Cookie Missing HttpOnly Flag",
            description: "Cookies can be accessed via JavaScript, making them vulnerable to XSS theft.",
            url: url.toString(),
            cwe: "CWE-1004",
            remediation: "Add HttpOnly flag to sensitive cookies"
          });
        }
        if (!setCookie.toLowerCase().includes("secure")) {
          findings.push({
            severity: "medium",
            title: "Cookie Missing Secure Flag",
            description: "Cookies may be transmitted over unencrypted connections.",
            url: url.toString(),
            cwe: "CWE-614",
            remediation: "Add Secure flag to all cookies"
          });
        }
      }

    } catch (e: any) {
      console.error("Error checking headers:", e?.message);
      if (e?.name === 'AbortError') {
        findings.push({
          severity: "info",
          title: "Connection Timeout",
          description: "The target took too long to respond (>10s). This may indicate server issues or rate limiting.",
          url: url.toString()
        });
      }
    }

    // 2. Test for sensitive paths
    const sensitivePaths = [
      { path: "/.git/config", severity: "critical", desc: "Git configuration exposed - may contain credentials and repo info" },
      { path: "/.env", severity: "critical", desc: "Environment file exposed - may contain secrets and API keys" },
      { path: "/.git/HEAD", severity: "critical", desc: "Git HEAD file exposed - confirms git repository" },
      { path: "/wp-config.php", severity: "critical", desc: "WordPress config exposed - database credentials" },
      { path: "/config.php", severity: "high", desc: "PHP config file may be accessible" },
      { path: "/phpinfo.php", severity: "high", desc: "PHP info page exposes server configuration" },
      { path: "/server-status", severity: "medium", desc: "Apache server status page accessible" },
      { path: "/elmah.axd", severity: "high", desc: ".NET error log accessible" },
      { path: "/.well-known/security.txt", severity: "info", desc: "Security contact information" },
      { path: "/robots.txt", severity: "info", desc: "Robots.txt may reveal hidden paths" },
      { path: "/sitemap.xml", severity: "info", desc: "Sitemap available" },
      { path: "/crossdomain.xml", severity: "low", desc: "Flash cross-domain policy" },
      { path: "/admin", severity: "info", desc: "Admin path accessible" },
      { path: "/api", severity: "info", desc: "API endpoint accessible" },
      { path: "/swagger", severity: "medium", desc: "API documentation may expose endpoints" },
      { path: "/graphql", severity: "info", desc: "GraphQL endpoint found" },
    ];

    for (const { path, severity, desc } of sensitivePaths) {
      try {
        const testUrl = new URL(path, url.origin).toString();
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        
        const response = await fetch(testUrl, { 
          method: "GET",
          redirect: "manual",
          signal: controller.signal,
          headers: {
            "User-Agent": "OmniSec Security Scanner/1.0"
          }
        });
        clearTimeout(timeoutId);
        
        if (response.status === 200) {
          const contentType = response.headers.get("content-type") || "";
          const contentLength = response.headers.get("content-length");
          
          // Check if it's actually content (not a redirect page)
          if (contentLength && parseInt(contentLength) > 0) {
            findings.push({
              severity: severity as any,
              title: `Exposed Path: ${path}`,
              description: desc,
              url: testUrl,
              method: "GET",
              details: `Status: ${response.status}, Content-Type: ${contentType}`
            });
            console.log(`Found accessible path: ${path}`);
          }
        }
      } catch (e: any) {
        // Timeout or connection error - path not accessible
      }
    }

    // 3. SSL/TLS check
    if (url.protocol === "https:") {
      findings.push({
        severity: "info",
        title: "HTTPS Enabled",
        description: "Site uses HTTPS encryption for secure communication.",
        url: url.toString()
      });
    } else {
      findings.push({
        severity: "critical",
        title: "No HTTPS Encryption",
        description: "Site does not use HTTPS - all traffic including credentials transmitted in plaintext. Vulnerable to man-in-the-middle attacks.",
        url: url.toString(),
        cwe: "CWE-319",
        remediation: "Implement HTTPS with a valid SSL/TLS certificate"
      });
    }

    const scanTime = Date.now() - startTime;
    console.log(`Scan completed in ${scanTime}ms, found ${findings.length} issues`);

    // Sort findings by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => (severityOrder[a.severity as keyof typeof severityOrder] || 5) - (severityOrder[b.severity as keyof typeof severityOrder] || 5));

    return new Response(
      JSON.stringify({
        success: true,
        target: url.toString(),
        findings,
        scanTime,
        summary: {
          critical: findings.filter(f => f.severity === "critical").length,
          high: findings.filter(f => f.severity === "high").length,
          medium: findings.filter(f => f.severity === "medium").length,
          low: findings.filter(f => f.severity === "low").length,
          info: findings.filter(f => f.severity === "info").length,
        },
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
