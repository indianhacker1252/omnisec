import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface IAMFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  mitreAttack?: string;
  owasp?: string;
  remediation: string;
  affectedEndpoint?: string;
  poc?: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body = await req.json();
    const target = body.target;
    // Support both testType and scanType params
    const testType = body.testType || body.scanType || "full";
    
    if (!target) {
      return new Response(JSON.stringify({ error: "Target is required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      return new Response(JSON.stringify({ error: "AI service not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    console.log(`Starting ${testType} IAM security test on: ${target}`);

    // Real probing for auth/IAM issues
    const realFindings: IAMFinding[] = [];
    let targetUrl: URL;
    try {
      targetUrl = new URL(target.startsWith("http") ? target : `https://${target}`);
    } catch {
      targetUrl = new URL(`https://${target}`);
    }

    // Probe auth endpoints
    const authPaths = [
      "/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
      "/admin/login", "/wp-login.php", "/user/login",
      "/oauth/authorize", "/oauth/token", "/.well-known/openid-configuration",
      "/api/auth/register", "/register", "/signup", "/api/signup",
      "/forgot-password", "/reset-password", "/api/password/reset"
    ];

    const probeResults: Array<{path: string; status: number; hasForm: boolean; headers: Record<string,string>}> = [];

    const probePromises = authPaths.map(async (path) => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        const probeUrl = new URL(path, targetUrl.origin).toString();
        const resp = await fetch(probeUrl, {
          method: "GET",
          signal: controller.signal,
          headers: { "User-Agent": "OmniSec-IAM-Scanner/1.0" },
          redirect: "manual"
        });
        clearTimeout(timeoutId);
        const bodyText = await resp.text();
        
        if (resp.status !== 404) {
          const hasForm = bodyText.includes("<form") || bodyText.includes("password") || bodyText.includes("login");
          probeResults.push({
            path,
            status: resp.status,
            hasForm,
            headers: Object.fromEntries(resp.headers.entries())
          });

          // Login page without HTTPS
          if (hasForm && targetUrl.protocol === "http:") {
            realFindings.push({
              id: `IAM-REAL-${realFindings.length + 1}`,
              category: "Authentication",
              severity: "critical",
              title: `Login Form Over HTTP: ${path}`,
              description: "Login form transmits credentials over unencrypted HTTP, allowing interception via man-in-the-middle attacks.",
              affectedEndpoint: probeUrl,
              owasp: "A07:2021 - Identification and Authentication Failures",
              mitreAttack: "T1557 - Adversary-in-the-Middle",
              remediation: "Enforce HTTPS on all authentication endpoints.",
              poc: `curl -s "${probeUrl}" | grep -i "form\\|password\\|login"`
            });
          }

          // Check for missing security headers on auth pages
          if (hasForm && resp.status === 200) {
            if (!resp.headers.get("x-frame-options") && !resp.headers.get("content-security-policy")) {
              realFindings.push({
                id: `IAM-REAL-${realFindings.length + 1}`,
                category: "Session Management",
                severity: "high",
                title: `Login Page Vulnerable to Clickjacking: ${path}`,
                description: "The login page can be embedded in an iframe, enabling clickjacking attacks to steal credentials.",
                affectedEndpoint: probeUrl,
                owasp: "A07:2021 - Identification and Authentication Failures",
                mitreAttack: "T1185 - Browser Session Hijacking",
                remediation: "Add X-Frame-Options: DENY and Content-Security-Policy frame-ancestors 'none' headers.",
                poc: `<iframe src="${probeUrl}" width="500" height="400"></iframe>`
              });
            }
          }

          // Username enumeration check
          if (hasForm && resp.status === 200 && (path.includes("login") || path.includes("signin"))) {
            try {
              const postResp = await fetch(probeUrl, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: "username=nonexistent_user_test&password=wrongpassword123",
                redirect: "manual"
              });
              const postBody = await postResp.text();
              if (postBody.toLowerCase().includes("user not found") || 
                  postBody.toLowerCase().includes("no such user") ||
                  postBody.toLowerCase().includes("account does not exist")) {
                realFindings.push({
                  id: `IAM-REAL-${realFindings.length + 1}`,
                  category: "Authentication",
                  severity: "medium",
                  title: `Username Enumeration via ${path}`,
                  description: "The login form reveals whether a username exists, enabling attackers to enumerate valid accounts.",
                  affectedEndpoint: probeUrl,
                  owasp: "A07:2021 - Identification and Authentication Failures",
                  remediation: "Use generic error messages like 'Invalid credentials' for both wrong username and password.",
                  poc: `curl -X POST "${probeUrl}" -d "username=nonexistent_user_test&password=wrong"`
                });
              }
            } catch { /* ignore */ }
          }
        }
      } catch { /* timeout */ }
    });

    await Promise.all(probePromises);

    // Check for OpenID configuration exposure
    const oidcResult = probeResults.find(p => p.path.includes("openid-configuration") && p.status === 200);
    if (oidcResult) {
      realFindings.push({
        id: `IAM-REAL-${realFindings.length + 1}`,
        category: "OAuth/OIDC",
        severity: "info",
        title: "OpenID Connect Configuration Exposed",
        description: "OpenID Connect discovery document is accessible. While standard, verify all listed endpoints are properly secured.",
        affectedEndpoint: new URL(oidcResult.path, targetUrl.origin).toString(),
        remediation: "Ensure all listed OIDC endpoints enforce proper authentication and authorization.",
        poc: `curl -s "${new URL(oidcResult.path, targetUrl.origin)}"`
      });
    }

    // Use AI to analyze probe data
    let aiFindings: IAMFinding[] = [];
    try {
      const systemPrompt = `You are an expert IAM security analyst. Based on these REAL probe results, identify genuine IAM/auth security issues.

Target: ${target}
Test Type: ${testType}

Real probe results (auth endpoints found):
${JSON.stringify(probeResults.slice(0, 10), null, 2)}

Already found ${realFindings.length} real issues. Add ONLY additional findings backed by the probe evidence.

Return JSON: { "findings": [{ "id": "IAM-AI-N", "category": "string", "severity": "critical|high|medium|low|info", "title": "string", "description": "string", "affectedEndpoint": "string", "owasp": "string", "mitreAttack": "string", "remediation": "string", "poc": "string" }] }

CRITICAL: Only return findings supported by evidence. No fabricated vulnerabilities.`;

      const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${LOVABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: `Analyze probe results for ${target} and return evidence-backed IAM findings.` }
          ],
          response_format: { type: "json_object" }
        }),
      });

      if (response.ok) {
        const aiResponse = await response.json();
        const content = aiResponse.choices?.[0]?.message?.content || "{}";
        const parsed = JSON.parse(content);
        aiFindings = (parsed.findings || []).map((f: any, idx: number) => ({
          id: f.id || `IAM-AI-${idx + 1}`,
          category: f.category || "IAM Security",
          severity: f.severity || "medium",
          title: f.title || "Unknown",
          description: f.description || "",
          affectedEndpoint: f.affectedEndpoint || f.endpoint || target,
          owasp: f.owasp,
          mitreAttack: f.mitreAttack || f.mitre_attack,
          remediation: f.remediation || "Review IAM configuration",
          poc: f.poc
        }));
      }
    } catch (e) {
      console.error("AI analysis error:", e);
    }

    const allFindings = [...realFindings, ...aiFindings];
    console.log(`IAM security test complete: ${allFindings.length} findings (${realFindings.length} real, ${aiFindings.length} AI)`);

    const summary = {
      critical: allFindings.filter(f => f.severity === "critical").length,
      high: allFindings.filter(f => f.severity === "high").length,
      medium: allFindings.filter(f => f.severity === "medium").length,
      low: allFindings.filter(f => f.severity === "low").length,
      info: allFindings.filter(f => f.severity === "info").length,
    };

    return new Response(JSON.stringify({
      success: true,
      testType,
      target,
      findings: allFindings,
      summary,
      scanTime: Date.now(),
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("IAM security test error:", error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : "Unknown error",
      success: false 
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
