import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

function validateTarget(url: string): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;
    const blockedPatterns = [
      /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./, /^127\./,
      /^169\.254\./, /^0\./, /localhost/i, /metadata/i, /internal/i,
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

async function fetchWithTimeout(url: string, opts: RequestInit & { timeout?: number } = {}) {
  const { timeout = 8000, ...fetchOpts } = opts;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(url, { ...fetchOpts, signal: controller.signal });
    clearTimeout(timeoutId);
    return resp;
  } catch (e) {
    clearTimeout(timeoutId);
    throw e;
  }
}

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
        JSON.stringify({ error: "Invalid target - internal addresses not allowed", success: false }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const findings: any[] = [];
    const startTime = Date.now();

    console.log("Starting security scan for:", url.toString());

    // 1. Check main page and security headers
    try {
      const response = await fetchWithTimeout(url.toString(), {
        timeout: 15000,
        headers: { "User-Agent": "OmniSec Security Scanner/1.0" }
      });
      
      const headers = response.headers;
      const bodyText = await response.text();

      console.log("Response status:", response.status);

      // Security header checks
      if (!headers.get("X-Frame-Options")) {
        findings.push({
          severity: "high", title: "Missing X-Frame-Options Header",
          description: "Vulnerable to clickjacking attacks. An attacker could embed this page in an iframe.",
          url: url.toString(), cwe: "CWE-1021",
          remediation: "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header",
          poc: `<iframe src="${url}" width="500" height="400"></iframe>`
        });
      }

      if (!headers.get("Content-Security-Policy")) {
        findings.push({
          severity: "medium", title: "Missing Content-Security-Policy",
          description: "No CSP header found. The application may be vulnerable to XSS attacks.",
          url: url.toString(), cwe: "CWE-79",
          remediation: "Implement a strict Content-Security-Policy header"
        });
      }

      if (!headers.get("Strict-Transport-Security")) {
        findings.push({
          severity: "medium", title: "Missing HSTS Header",
          description: "Vulnerable to protocol downgrade attacks and cookie hijacking.",
          url: url.toString(), cwe: "CWE-319",
          remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
        });
      }

      if (!headers.get("X-Content-Type-Options")) {
        findings.push({
          severity: "low", title: "Missing X-Content-Type-Options",
          description: "Browser may MIME-sniff responses, enabling content-type attacks.",
          url: url.toString(), cwe: "CWE-430",
          remediation: "Add 'X-Content-Type-Options: nosniff' header"
        });
      }

      const server = headers.get("Server");
      if (server) {
        findings.push({
          severity: "low", title: "Server Version Disclosure",
          description: `Server header reveals: "${server}". Helps attackers identify known vulnerabilities.`,
          url: url.toString(), cwe: "CWE-200",
          remediation: "Remove or obfuscate the Server header",
          poc: `curl -sI "${url}" | grep -i server`
        });
      }

      const xPoweredBy = headers.get("X-Powered-By");
      if (xPoweredBy) {
        findings.push({
          severity: "low", title: "Technology Stack Disclosure",
          description: `X-Powered-By reveals: "${xPoweredBy}". Helps identify framework-specific vulnerabilities.`,
          url: url.toString(), cwe: "CWE-200",
          remediation: "Remove the X-Powered-By header",
          poc: `curl -sI "${url}" | grep -i x-powered-by`
        });
      }

      // Cookie checks
      const setCookie = headers.get("Set-Cookie");
      if (setCookie) {
        if (!setCookie.toLowerCase().includes("httponly")) {
          findings.push({
            severity: "medium", title: "Cookie Missing HttpOnly Flag",
            description: "Cookies accessible via JavaScript, vulnerable to XSS theft.",
            url: url.toString(), cwe: "CWE-1004",
            remediation: "Add HttpOnly flag to sensitive cookies"
          });
        }
        if (!setCookie.toLowerCase().includes("secure")) {
          findings.push({
            severity: "medium", title: "Cookie Missing Secure Flag",
            description: "Cookies may be transmitted over unencrypted connections.",
            url: url.toString(), cwe: "CWE-614",
            remediation: "Add Secure flag to all cookies"
          });
        }
      }

      // Check for forms and input fields (potential XSS/injection points)
      const formCount = (bodyText.match(/<form/gi) || []).length;
      const inputCount = (bodyText.match(/<input/gi) || []).length;
      if (formCount > 0 && !headers.get("Content-Security-Policy")) {
        findings.push({
          severity: "medium", title: `${formCount} Form(s) Without CSP Protection`,
          description: `Found ${formCount} form(s) with ${inputCount} input field(s) but no CSP header. Forms are potential XSS injection points.`,
          url: url.toString(), cwe: "CWE-79",
          remediation: "Implement CSP header and input validation on all form fields"
        });
      }

      // Check for inline scripts (XSS risk indicator)
      const inlineScripts = (bodyText.match(/<script[^>]*>[^<]+/gi) || []);
      if (inlineScripts.length > 0 && !headers.get("Content-Security-Policy")) {
        findings.push({
          severity: "medium", title: `${inlineScripts.length} Inline Script(s) Detected`,
          description: "Inline scripts without CSP make XSS exploitation trivial if an injection point is found.",
          url: url.toString(), cwe: "CWE-79",
          remediation: "Move scripts to external files and implement CSP with script-src directive"
        });
      }

      // Check for error disclosure
      if (bodyText.match(/(?:stack\s*trace|exception|error\s*in|fatal\s*error|warning:|notice:|parse\s*error)/i)) {
        findings.push({
          severity: "medium", title: "Error/Debug Information Disclosure",
          description: "The application exposes error messages, stack traces, or debug info that reveals internal implementation details.",
          url: url.toString(), cwe: "CWE-209",
          remediation: "Disable verbose error messages in production. Use custom error pages.",
          poc: `curl -s "${url}" | grep -iE "error|exception|warning|stack.trace"`
        });
      }

    } catch (e: any) {
      console.error("Error checking main page:", e?.message);
      if (e?.name === 'AbortError') {
        findings.push({ severity: "info", title: "Connection Timeout", description: "Target took too long to respond (>15s).", url: url.toString() });
      }
    }

    // 2. Test sensitive paths - parallel with short timeouts
    const sensitivePaths = [
      { path: "/.git/config", severity: "critical", desc: "Git config exposed - may contain credentials" },
      { path: "/.env", severity: "critical", desc: "Environment file exposed - may contain secrets" },
      { path: "/.git/HEAD", severity: "critical", desc: "Git HEAD exposed - confirms repo" },
      { path: "/phpinfo.php", severity: "high", desc: "PHP info page exposes server configuration" },
      { path: "/server-status", severity: "medium", desc: "Apache server status accessible" },
      { path: "/robots.txt", severity: "info", desc: "Robots.txt may reveal hidden paths" },
      { path: "/admin", severity: "info", desc: "Admin path accessible" },
      { path: "/swagger", severity: "medium", desc: "API documentation may expose endpoints" },
    ];

    const pathPromises = sensitivePaths.map(async ({ path, severity, desc }) => {
      try {
        const testUrl = new URL(path, url.origin).toString();
        const response = await fetchWithTimeout(testUrl, {
          timeout: 5000,
          headers: { "User-Agent": "OmniSec Security Scanner/1.0" },
          redirect: "manual"
        });

        const bodyText = await response.text();
        
        if (response.status === 200 && bodyText.length > 0) {
          // Verify it's actual content, not a generic 200 page
          const isGeneric = bodyText.includes("<!DOCTYPE") && !path.includes("robots") && !path.includes("admin");
          if (!isGeneric || path.includes(".git") || path.includes(".env") || path.includes("phpinfo")) {
            findings.push({
              severity: severity as any,
              title: `Exposed Path: ${path}`,
              description: desc,
              url: testUrl,
              method: "GET",
              details: `Status: ${response.status}, Size: ${bodyText.length} bytes`,
              poc: `curl -s "${testUrl}" | head -20`
            });
          }
        }
      } catch { /* timeout or error */ }
    });

    await Promise.all(pathPromises);

    // 3. SSL/TLS check
    if (url.protocol !== "https:") {
      findings.push({
        severity: "critical", title: "No HTTPS Encryption",
        description: "All traffic including credentials transmitted in plaintext. Vulnerable to MITM attacks.",
        url: url.toString(), cwe: "CWE-319",
        remediation: "Implement HTTPS with a valid SSL/TLS certificate",
        poc: `curl -sI "http://${url.hostname}" | head -5`
      });
    }

    const scanTime = Date.now() - startTime;
    console.log(`Scan completed in ${scanTime}ms, found ${findings.length} issues`);

    // Sort by severity
    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

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
      JSON.stringify({ error: error?.message || "Unknown error", success: false }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
