import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

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

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    const body = await req.json();
    const { action, finding, script, verificationResult } = body;

    if (action === "generate_script") {
      const generatedScript = await generateVerificationScript(finding, LOVABLE_API_KEY);
      return new Response(JSON.stringify({ script: generatedScript }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "run_verification") {
      const result = await runVerification(finding, script);
      return new Response(JSON.stringify(result), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "generate_poc") {
      const report = await generatePOCReport(finding, verificationResult, LOVABLE_API_KEY);
      return new Response(JSON.stringify({ report }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    return new Response(JSON.stringify({ error: "Invalid action" }), {
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    console.error("verify-finding error:", e);
    return new Response(JSON.stringify({ error: e.message || "Internal error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});

async function generateVerificationScript(finding: any, apiKey: string | undefined): Promise<string> {
  if (!apiKey) return generateLocalScript(finding);

  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          {
            role: "system",
            content: `You are an expert penetration tester generating verification scripts. Output ONLY the script content — no markdown fences, no explanations. The script should be a series of curl commands with comments explaining each test. Include:
1. The exact reproduction steps using curl
2. Multiple test variations to confirm the finding
3. Expected vs actual response comparison logic
4. Clear comments marking what confirms the vulnerability
Be specific to the vulnerability type and endpoint.`
          },
          {
            role: "user",
            content: `Generate a verification test script for this finding:
Title: ${finding.title}
Endpoint: ${finding.endpoint}
Method: ${finding.method || "GET"}
Payload: ${finding.payload || "N/A"}
Evidence: ${finding.evidence || "N/A"}
CWE: ${finding.cwe || "N/A"}
Category: ${finding.category || "N/A"}
Severity: ${finding.severity}`
          }
        ],
        max_tokens: 2000,
      }),
    });

    if (!resp.ok) return generateLocalScript(finding);

    const data = await resp.json();
    return data.choices?.[0]?.message?.content || generateLocalScript(finding);
  } catch {
    return generateLocalScript(finding);
  }
}

function generateLocalScript(finding: any): string {
  const url = finding.endpoint || "";
  const method = finding.method || "GET";
  const payload = finding.payload || "";
  const cwe = finding.cwe || "";

  if (cwe.includes("89") || finding.category === "sqli") {
    return `# SQL Injection Verification
# Target: ${url}

# Test 1: Error-based detection
curl -v "${url}${url.includes("?") ? "&" : "?"}id=1'"

# Test 2: Boolean-based blind
curl -s -o /dev/null -w "%{http_code}" "${url}${url.includes("?") ? "&" : "?"}id=1 AND 1=1"
curl -s -o /dev/null -w "%{http_code}" "${url}${url.includes("?") ? "&" : "?"}id=1 AND 1=2"

# Test 3: Original payload
curl -v "${url}${url.includes("?") ? "&" : "?"}${payload}"

# Confirm: Different responses = SQLi confirmed`;
  }

  if (cwe.includes("79") || finding.category === "xss") {
    return `# XSS Verification
# Target: ${url}

# Test 1: Reflected XSS check
curl -v "${url}${url.includes("?") ? "&" : "?"}q=${encodeURIComponent(payload || "<script>alert(1)</script>")}"

# Test 2: Event handler bypass
curl -v "${url}${url.includes("?") ? "&" : "?"}q=${encodeURIComponent("<img src=x onerror=alert(1)>")}"

# Confirm: Unescaped payload in response body = XSS confirmed`;
  }

  return `# Vulnerability Verification
# Finding: ${finding.title}
# Target: ${url}

curl -v -X ${method} "${url}" ${payload ? `-d "${payload}"` : ""}

# Review response for: ${finding.evidence || "vulnerability indicators"}`;
}

async function runVerification(finding: any, script: string): Promise<any> {
  const endpoint = finding.endpoint || "";
  const method = finding.method || "GET";
  const payload = finding.payload || "";

  // Extract the primary test URL from the script or use the finding endpoint
  let testUrl = endpoint;
  if (payload && !testUrl.includes(payload)) {
    const sep = testUrl.includes("?") ? "&" : "?";
    testUrl = `${testUrl}${sep}${payload}`;
  }

  try {
    const startTime = Date.now();
    const resp = await fetch(testUrl, {
      method,
      headers: { "User-Agent": "OmniSec-Verifier/1.0" },
      redirect: "follow",
    });
    const responseTime = Date.now() - startTime;
    const statusCode = resp.status;
    const responseBody = await resp.text().catch(() => "");
    const responseHeaders = Object.fromEntries(resp.headers.entries());

    // Build request description
    const requestDesc = `${method} ${testUrl}\nUser-Agent: OmniSec-Verifier/1.0`;

    // Build response description
    const headerStr = Object.entries(responseHeaders).map(([k, v]) => `${k}: ${v}`).join("\n");
    const truncatedBody = responseBody.length > 3000 ? responseBody.slice(0, 3000) + "\n... [truncated]" : responseBody;
    const responseDesc = `HTTP/${statusCode}\n${headerStr}\n\n${truncatedBody}`;

    // Analyze for vulnerability confirmation
    const confirmed = analyzeResponse(finding, responseBody, statusCode, responseHeaders, responseTime);

    return {
      confirmed: confirmed.isVulnerable,
      request: requestDesc,
      response: responseDesc,
      statusCode,
      responseTime,
      analysis: confirmed.analysis,
    };
  } catch (e) {
    return {
      confirmed: false,
      request: `${method} ${testUrl}`,
      response: `Error: ${e.message}`,
      analysis: `Failed to reach endpoint: ${e.message}`,
    };
  }
}

function analyzeResponse(finding: any, body: string, status: number, headers: any, responseTime: number): { isVulnerable: boolean; analysis: string } {
  const cwe = finding.cwe || "";
  const payload = finding.payload || "";
  const bodyLower = body.toLowerCase();
  const reasons: string[] = [];
  let isVulnerable = false;

  // SQL Injection indicators
  if (cwe.includes("89") || finding.category === "sqli") {
    const sqlErrors = ["sql syntax", "mysql", "postgresql", "sqlite", "ora-", "you have an error", "unclosed quotation", "unterminated", "syntax error", "warning: mysql", "sqlstate"];
    for (const err of sqlErrors) {
      if (bodyLower.includes(err)) {
        isVulnerable = true;
        reasons.push(`SQL error string detected: "${err}"`);
      }
    }
    if (payload && body.includes(payload)) {
      reasons.push("Payload reflected in response");
    }
  }

  // XSS indicators
  if (cwe.includes("79") || finding.category === "xss") {
    if (payload && body.includes(payload)) {
      isVulnerable = true;
      reasons.push("Payload reflected unescaped in response body");
    }
    const xssPatterns = ["<script", "onerror=", "onload=", "javascript:", "alert("];
    for (const p of xssPatterns) {
      if (body.includes(p) && payload.toLowerCase().includes(p)) {
        isVulnerable = true;
        reasons.push(`XSS pattern "${p}" found unfiltered`);
      }
    }
  }

  // CORS
  if (cwe.includes("346") || finding.category === "cors") {
    const acao = headers["access-control-allow-origin"];
    if (acao === "*" || (acao && acao !== "null")) {
      isVulnerable = true;
      reasons.push(`Permissive CORS: Access-Control-Allow-Origin: ${acao}`);
    }
  }

  // Directory Traversal
  if (cwe.includes("22") || finding.category === "traversal") {
    if (bodyLower.includes("root:") || bodyLower.includes("[boot loader]") || bodyLower.includes("/etc/passwd")) {
      isVulnerable = true;
      reasons.push("System file content detected in response");
    }
  }

  // Open Redirect
  if (cwe.includes("601") || finding.category === "redirect") {
    if (status >= 300 && status < 400) {
      const location = headers["location"] || "";
      if (location.includes("evil.com") || location.includes("attacker")) {
        isVulnerable = true;
        reasons.push(`Redirect to external domain: ${location}`);
      }
    }
  }

  // Cookie issues
  if (finding.category === "cookie") {
    const setCookie = headers["set-cookie"] || "";
    if (setCookie && !setCookie.toLowerCase().includes("httponly")) {
      isVulnerable = true;
      reasons.push("Cookie missing HttpOnly flag");
    }
    if (setCookie && !setCookie.toLowerCase().includes("secure")) {
      isVulnerable = true;
      reasons.push("Cookie missing Secure flag");
    }
  }

  // Generic: if the original evidence string appears in response
  if (!isVulnerable && finding.evidence) {
    const evidenceKey = finding.evidence.slice(0, 100).toLowerCase();
    if (bodyLower.includes(evidenceKey)) {
      isVulnerable = true;
      reasons.push("Original evidence pattern found in response");
    }
  }

  const analysis = isVulnerable
    ? `CONFIRMED: ${reasons.join(". ")}`
    : reasons.length > 0
      ? `Partial indicators found but not conclusive: ${reasons.join(". ")}. Manual review recommended.`
      : `No vulnerability indicators detected in response (HTTP ${status}, ${responseTime}ms). The finding may require different test conditions or authentication context.`;

  return { isVulnerable, analysis };
}

async function generatePOCReport(finding: any, verificationResult: any, apiKey: string | undefined): Promise<string> {
  if (!apiKey) return generateLocalPOC(finding, verificationResult);

  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          {
            role: "system",
            content: `You are a professional bug bounty hunter writing a POC report. Write in Markdown format. Include:
1. Title and severity summary table
2. Detailed description of the vulnerability
3. Step-by-step reproduction with exact curl commands
4. Request/Response evidence
5. Impact analysis (what an attacker can achieve)
6. CVSS scoring justification
7. Remediation recommendations
8. References (CWE, OWASP, relevant resources)
Be professional, detailed, and ready for HackerOne/Bugcrowd submission.`
          },
          {
            role: "user",
            content: `Generate a bug bounty POC report:
Title: ${finding.title}
Severity: ${finding.severity}
CWE: ${finding.cwe || "N/A"}
CVSS: ${finding.cvss || "N/A"}
Endpoint: ${finding.endpoint}
Method: ${finding.method || "GET"}
Payload: ${finding.payload || "N/A"}
Description: ${finding.description}
Evidence: ${finding.evidence || "N/A"}
Secondary Evidence: ${finding.evidence2 || "N/A"}
Remediation: ${finding.remediation}
Category: ${finding.category || "N/A"}
${verificationResult ? `\nVerification Request:\n${verificationResult.request}\n\nVerification Response:\n${verificationResult.response?.slice(0, 2000)}\n\nVerification Analysis: ${verificationResult.analysis}` : ""}`
          }
        ],
        max_tokens: 4000,
      }),
    });

    if (!resp.ok) return generateLocalPOC(finding, verificationResult);

    const data = await resp.json();
    return data.choices?.[0]?.message?.content || generateLocalPOC(finding, verificationResult);
  } catch {
    return generateLocalPOC(finding, verificationResult);
  }
}

function generateLocalPOC(finding: any, verificationResult: any): string {
  return `# Bug Bounty Report — ${finding.title}

## Summary
| Field | Value |
|-------|-------|
| **Vulnerability** | ${finding.title} |
| **Severity** | ${(finding.severity || "medium").toUpperCase()} |
| **CWE** | ${finding.cwe || "N/A"} |
| **CVSS** | ${finding.cvss || "N/A"} |
| **Endpoint** | \`${finding.endpoint}\` |
| **Method** | ${finding.method || "GET"} |

## Description
${finding.description || "N/A"}

## Steps to Reproduce
1. Open a terminal
2. Run the following curl command:
\`\`\`bash
curl -v -X ${finding.method || "GET"} "${finding.endpoint}" ${finding.payload ? `-d "${finding.payload}"` : ""}
\`\`\`
3. Observe the response for vulnerability indicators

## Evidence

### Request
\`\`\`
${verificationResult?.request || `${finding.method || "GET"} ${finding.endpoint}`}
\`\`\`

### Response
\`\`\`
${verificationResult?.response?.slice(0, 2000) || finding.evidence || "See description"}
\`\`\`

${finding.evidence2 ? `### Secondary Verification\n${finding.evidence2}` : ""}

## Impact
${finding.severity === "critical" || finding.severity === "high"
    ? "This vulnerability poses a significant risk and could lead to unauthorized data access, system compromise, or service disruption."
    : "This vulnerability should be remediated to prevent potential security issues."}

## Remediation
${finding.remediation || "Apply appropriate security controls."}

## References
- CWE: ${finding.cwe || "N/A"}
- OWASP: https://owasp.org/www-project-top-ten/
`;
}
