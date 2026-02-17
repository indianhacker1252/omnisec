import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface APIFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  endpoint: string;
  method: string;
  mitreAttack?: string;
  owasp?: string;
  remediation: string;
  poc?: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body = await req.json();
    const target = body.target;
    // Support both apiType and scanType params
    const apiType = body.apiType || body.scanType || "rest";
    
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

    console.log(`Starting ${apiType} API security scan on: ${target}`);

    // First do real HTTP probing
    const realFindings: APIFinding[] = [];
    let targetUrl: URL;
    try {
      targetUrl = new URL(target.startsWith("http") ? target : `https://${target}`);
    } catch {
      targetUrl = new URL(`https://${target}`);
    }

    // Probe common API paths
    const apiPaths = [
      "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger.json",
      "/openapi.json", "/api-docs", "/api/docs", "/.well-known/openid-configuration",
      "/oauth/token", "/auth/login", "/api/users", "/api/admin",
      "/wp-json/wp/v2/users", "/rest/api/2/serverInfo"
    ];

    const probeResults: Array<{path: string; status: number; headers: Record<string, string>; bodySnippet: string}> = [];

    // Parallel probe with timeout
    const probePromises = apiPaths.map(async (path) => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        const probeUrl = new URL(path, targetUrl.origin).toString();
        const resp = await fetch(probeUrl, {
          method: "GET",
          signal: controller.signal,
          headers: { "User-Agent": "OmniSec-API-Scanner/1.0" },
          redirect: "manual"
        });
        clearTimeout(timeoutId);
        
        const bodyText = await resp.text();
        const snippet = bodyText.substring(0, 500);
        
        if (resp.status !== 404 && resp.status !== 403) {
          probeResults.push({
            path,
            status: resp.status,
            headers: Object.fromEntries(resp.headers.entries()),
            bodySnippet: snippet
          });
        }

        // Check for exposed API docs
        if (resp.status === 200 && (path.includes("swagger") || path.includes("openapi") || path.includes("api-docs"))) {
          realFindings.push({
            id: `API-REAL-${realFindings.length + 1}`,
            category: "API Documentation",
            severity: "medium",
            title: `API Documentation Exposed: ${path}`,
            description: `API documentation is publicly accessible at ${path}. This reveals endpoint structure, parameters, and data models to attackers.`,
            endpoint: probeUrl,
            method: "GET",
            owasp: "API9:2023 - Improper Inventory Management",
            remediation: "Restrict API documentation access to authenticated users or internal networks only.",
            poc: `curl -s "${probeUrl}" | head -50`
          });
        }

        // Check for user enumeration
        if (resp.status === 200 && path.includes("users") && snippet.includes("{")) {
          realFindings.push({
            id: `API-REAL-${realFindings.length + 1}`,
            category: "Information Disclosure",
            severity: "high",
            title: `User Enumeration via ${path}`,
            description: `The ${path} endpoint returns user data without authentication. Attackers can enumerate users.`,
            endpoint: probeUrl,
            method: "GET",
            owasp: "API1:2023 - Broken Object Level Authorization",
            remediation: "Require authentication for user listing endpoints. Implement proper access controls.",
            poc: `curl -s "${probeUrl}"`
          });
        }

        // Check for GraphQL introspection
        if (resp.status === 200 && path === "/graphql") {
          try {
            const introspectionResp = await fetch(probeUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ query: "{ __schema { types { name } } }" })
            });
            const intrBody = await introspectionResp.text();
            if (intrBody.includes("__schema") || intrBody.includes("types")) {
              realFindings.push({
                id: `API-REAL-${realFindings.length + 1}`,
                category: "GraphQL Security",
                severity: "medium",
                title: "GraphQL Introspection Enabled",
                description: "GraphQL introspection is enabled, allowing attackers to discover the entire API schema.",
                endpoint: probeUrl,
                method: "POST",
                remediation: "Disable introspection in production. Use schema whitelisting.",
                poc: `curl -X POST "${probeUrl}" -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name } } }"}'`
              });
            }
          } catch { /* ignore */ }
        }

        // Check CORS misconfiguration
        if (resp.status === 200) {
          const acaoHeader = resp.headers.get("access-control-allow-origin");
          if (acaoHeader === "*") {
            realFindings.push({
              id: `API-REAL-${realFindings.length + 1}`,
              category: "CORS",
              severity: "medium",
              title: `Permissive CORS on ${path}`,
              description: `The endpoint at ${path} allows requests from any origin (Access-Control-Allow-Origin: *). This could enable cross-origin data theft.`,
              endpoint: probeUrl,
              method: "GET",
              owasp: "API8:2023 - Security Misconfiguration",
              remediation: "Restrict CORS to trusted origins only.",
              poc: `curl -s -I "${probeUrl}" | grep -i "access-control"`
            });
          }
        }
      } catch { /* timeout or error - path not accessible */ }
    });

    await Promise.all(probePromises);

    // Test for missing rate limiting
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      const responses: number[] = [];
      
      for (let i = 0; i < 5; i++) {
        const resp = await fetch(targetUrl.toString(), {
          signal: controller.signal,
          headers: { "User-Agent": "OmniSec-API-Scanner/1.0" }
        });
        responses.push(resp.status);
        await resp.text(); // consume body
      }
      clearTimeout(timeoutId);

      if (responses.every(s => s === 200)) {
        realFindings.push({
          id: `API-REAL-${realFindings.length + 1}`,
          category: "Rate Limiting",
          severity: "medium",
          title: "No Rate Limiting Detected",
          description: "5 rapid requests all returned 200. No rate limiting or throttling detected, making the API vulnerable to brute-force and abuse.",
          endpoint: targetUrl.toString(),
          method: "GET",
          owasp: "API4:2023 - Unrestricted Resource Consumption",
          remediation: "Implement rate limiting (e.g., 100 requests/minute per IP). Use API keys for tracking.",
          poc: `for i in {1..10}; do curl -s -o /dev/null -w "%{http_code}" "${targetUrl}"; done`
        });
      }
    } catch { /* ignore */ }

    // Use AI to analyze the probed data for deeper findings
    const systemPrompt = `You are an expert API security analyst. Based on the real probe results below, identify ONLY genuine security issues. Do NOT fabricate findings.

Target: ${target}
API Type: ${apiType}

Real probe results:
${JSON.stringify(probeResults.slice(0, 10), null, 2)}

Already found ${realFindings.length} real issues. Add ONLY additional findings that are supported by the probe data above.

Return JSON: { "findings": [{ "id": "API-AI-N", "category": "string", "severity": "critical|high|medium|low|info", "title": "string", "description": "string", "endpoint": "string", "method": "GET|POST|PUT|DELETE", "owasp": "string", "remediation": "string", "poc": "curl command or step-by-step" }] }

IMPORTANT: Only return findings backed by evidence from the probe results. No guessing.`;

    let aiFindings: APIFinding[] = [];
    try {
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
            { role: "user", content: `Analyze the probe results and return only evidence-backed findings as JSON.` }
          ],
          response_format: { type: "json_object" }
        }),
      });

      if (response.ok) {
        const aiResponse = await response.json();
        const content = aiResponse.choices?.[0]?.message?.content || "{}";
        const parsed = JSON.parse(content);
        aiFindings = (parsed.findings || []).map((f: any, idx: number) => ({
          id: f.id || `API-AI-${idx + 1}`,
          category: f.category || "API Security",
          severity: f.severity || "medium",
          title: f.title || "Unknown",
          description: f.description || "",
          endpoint: f.endpoint || target,
          method: f.method || "GET",
          owasp: f.owasp,
          remediation: f.remediation || "Review and fix",
          poc: f.poc
        }));
      }
    } catch (e) {
      console.error("AI analysis error:", e);
    }

    const allFindings = [...realFindings, ...aiFindings];
    console.log(`API security scan complete: ${allFindings.length} findings (${realFindings.length} real, ${aiFindings.length} AI-analyzed)`);

    const summary = {
      critical: allFindings.filter(f => f.severity === "critical").length,
      high: allFindings.filter(f => f.severity === "high").length,
      medium: allFindings.filter(f => f.severity === "medium").length,
      low: allFindings.filter(f => f.severity === "low").length,
      info: allFindings.filter(f => f.severity === "info").length,
    };

    return new Response(JSON.stringify({
      success: true,
      apiType,
      target,
      findings: allFindings,
      summary,
      probeResults: probeResults.map(p => ({ path: p.path, status: p.status })),
      scanTime: Date.now(),
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("API security scan error:", error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : "Unknown error",
      success: false 
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
