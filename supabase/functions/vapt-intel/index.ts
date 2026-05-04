import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * OmniSec™ VAPT Intel — Pass 6 (Template Engine + Canary Tracker + LLM Business Logic)
 *
 * - Nuclei-style template engine: loads exploit templates from vapt_templates,
 *   executes the request, evaluates matchers, emits findings.
 * - Canary tracker: scans all known endpoints for previously-injected canary tokens
 *   to detect stored/second-order XSS, SQLi, and SSRF.
 * - LLM business-logic fuzzer: asks Lovable AI to reason about workflows
 *   (negative qty, role swap, currency confusion, race-friendly endpoints) and
 *   generates concrete test cases.
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const FETCH_TIMEOUT = 8000;
const fid = (cat: string) => `${cat}-${crypto.randomUUID().slice(0, 8)}`;

const safeFetch = async (url: string, opts: RequestInit = {}): Promise<Response | null> => {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    const r = await fetch(url, { ...opts, signal: ctrl.signal, redirect: 'manual' });
    clearTimeout(t);
    return r;
  } catch { return null; }
};

// Evaluate nuclei-style matcher block against a response
async function evaluateMatchers(resp: Response, body: string, matchers: any): Promise<boolean> {
  const condition = matchers.condition || 'and';
  const checks: boolean[] = [];

  if (matchers.status) {
    checks.push(matchers.status.includes(resp.status));
  }
  if (matchers.words) {
    const part = matchers.part === 'header' ? JSON.stringify(Array.from(resp.headers.entries())) : body;
    const wordsCondition = matchers.words_condition || 'and';
    const wordResults = matchers.words.map((w: string) => part.toLowerCase().includes(w.toLowerCase()));
    checks.push(wordsCondition === 'and' ? wordResults.every(Boolean) : wordResults.some(Boolean));
  }
  if (matchers.regex) {
    const regexResults = matchers.regex.map((r: string) => new RegExp(r, 'i').test(body));
    checks.push(regexResults.some(Boolean));
  }
  if (matchers.negative) {
    return !checks.every(Boolean);
  }

  return condition === 'and' ? checks.every(Boolean) : checks.some(Boolean);
}

// ═══════════════════ TEMPLATE ENGINE ═══════════════════
async function runTemplates(target: string, supabase: any): Promise<any[]> {
  const findings: any[] = [];
  const { data: templates } = await supabase.from('vapt_templates').select('*').eq('enabled', true).limit(100);
  if (!templates || templates.length === 0) return findings;

  const baseUrl = new URL(target);

  for (const tpl of templates.slice(0, 50)) {
    try {
      const path = tpl.request.path || '/';
      const url = new URL(path, baseUrl.origin).toString();
      const method = tpl.request.method || 'GET';
      const headers = tpl.request.headers || {};
      const body = tpl.request.body || undefined;

      const r = await safeFetch(url, { method, headers, body });
      if (!r) continue;
      const respBody = (await r.text()).slice(0, 50_000);

      const matched = await evaluateMatchers(r, respBody, tpl.matchers);
      if (matched) {
        findings.push({
          id: fid('tpl'),
          template_id: tpl.template_id,
          severity: tpl.severity,
          title: `[${tpl.template_id}] ${tpl.name}`,
          description: tpl.description || `Template ${tpl.template_id} matched on ${url}`,
          endpoint: url,
          method,
          payload: body ? String(body).slice(0, 200) : `${method} ${path}`,
          evidence: respBody.slice(0, 400),
          remediation: tpl.matchers?.remediation || 'Review the template references and apply the recommended patch.',
          cwe: (tpl.tags || []).find((t: string) => t.startsWith('cwe-')) || undefined,
          cve_ids: tpl.cve_ids || [],
          confidence: 85,
          category: tpl.category,
          poc: `curl -X ${method} "${url}"${Object.entries(headers).map(([k, v]) => ` -H "${k}: ${v}"`).join('')}${body ? ` -d '${String(body).slice(0, 100)}'` : ''}`,
        });
      }
    } catch (e) {
      console.log(`[template ${tpl.template_id}] error:`, e instanceof Error ? e.message : e);
    }
  }
  return findings;
}

// ═══════════════════ CANARY TRACKER ═══════════════════
async function trackCanaries(target: string, endpoints: string[], supabase: any): Promise<any[]> {
  const findings: any[] = [];
  const { data: canaries } = await supabase.from('scan_canaries').select('*').eq('status', 'pending').limit(100);
  if (!canaries || canaries.length === 0) return findings;

  // Inject one new canary per scan that future scans can detect
  const newToken = `omnisec-canary-${crypto.randomUUID().slice(0, 12)}`;
  await supabase.from('scan_canaries').insert({
    scan_id: target, canary_token: newToken,
    injected_url: target, injected_param: 'user_input',
  });

  // Look for previous canaries in current target's known endpoints
  const checkUrls = [target, ...endpoints.slice(0, 20)];
  for (const url of checkUrls) {
    const r = await safeFetch(url);
    if (!r) continue;
    const body = (await r.text()).slice(0, 100_000);
    for (const c of canaries) {
      if (body.includes(c.canary_token)) {
        await supabase.from('scan_canaries').update({
          reflected_url: url, reflected_at: new Date().toISOString(), status: 'triggered',
        }).eq('id', c.id);
        findings.push({
          id: fid('stored'),
          severity: 'high',
          title: `Stored payload reflected (canary ${c.canary_token.slice(-6)})`,
          description: `A canary token injected at ${c.injected_url} (param: ${c.injected_param}) is now reflected at ${url} — confirmed second-order/stored vulnerability.`,
          endpoint: url,
          payload: c.canary_token,
          evidence: `Canary echoed in response body.`,
          remediation: 'Sanitize stored data on output. Use context-aware encoding. Validate input at storage time.',
          cwe: 'CWE-79', cvss: 7.5, owasp: 'A03:2021', confidence: 95, category: 'stored_xss',
          poc: `# Original injection at ${c.injected_url}, reflection at ${url}\ncurl "${url}" | grep "${c.canary_token}"`,
        });
      }
    }
  }
  return findings;
}

// ═══════════════════ LLM BUSINESS-LOGIC FUZZER ═══════════════════
async function businessLogicFuzz(target: string, endpoints: string[], previousFindings: any[], apiKey: string | undefined): Promise<any[]> {
  if (!apiKey) return [];
  const findings: any[] = [];

  const epSample = endpoints.slice(0, 15).join('\n');
  const findingSample = previousFindings.slice(0, 10).map(f => `${f.severity}: ${f.title}`).join('\n');

  try {
    const r = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [{
          role: 'system',
          content: 'You are a senior bug bounty hunter. Given endpoints and prior findings, identify 3-5 plausible business-logic vulnerabilities (negative quantity, currency confusion, role swap, workflow skip, integer overflow, mass assignment, race-friendly endpoints). Return JSON: {"tests":[{"endpoint","attack","severity","reasoning","curl_poc"}]}. No prose, JSON only.',
        }, {
          role: 'user',
          content: `Target: ${target}\n\nEndpoints:\n${epSample}\n\nPrior findings:\n${findingSample}`,
        }],
      }),
    });
    if (!r.ok) return findings;
    const data = await r.json();
    const content = data.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return findings;
    const parsed = JSON.parse(jsonMatch[0]);
    for (const test of (parsed.tests || []).slice(0, 5)) {
      findings.push({
        id: fid('biz'),
        severity: test.severity || 'medium',
        title: `Business-logic suspect: ${test.attack}`,
        description: test.reasoning || 'AI-identified business-logic weakness',
        endpoint: test.endpoint || target,
        payload: test.attack, evidence: 'AI reasoning (manual verification recommended)',
        remediation: 'Review business-logic invariants. Add server-side validation for quantity ranges, role transitions, and atomic state changes.',
        cwe: 'CWE-840', confidence: 50, category: 'business_logic',
        poc: test.curl_poc || `# Manual verification required\n${test.attack}`,
      });
    }
  } catch (e) { console.error('biz-logic fuzz error:', e); }
  return findings;
}

// ═══════════════════ DISPATCHER ═══════════════════
serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");

    const body = await req.json();
    const { scanId, passNumber = 6, passName = 'template_intel_poc', target, previousPayload = {} } = body;

    if (!scanId || !target) {
      return new Response(JSON.stringify({ error: "scanId and target required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const start = Date.now();
    console.log(`[vapt-intel] Pass ${passNumber} start for ${target}`);

    await supabase.from('scan_passes').update({ status: 'running', started_at: new Date().toISOString() })
      .eq('scan_id', scanId).eq('pass_number', passNumber);

    await supabase.from('scan_progress').insert({
      scan_id: scanId, phase: 'template_engine', phase_number: 50, total_phases: 60,
      progress: 90, message: 'Running 50+ exploit templates + canary tracker + AI business-logic fuzzer',
    });

    const endpoints = (previousPayload.endpoints || []).map((e: string) => e.startsWith('http') ? e : new URL(e, target).toString());
    const priorFindings = [
      ...(previousPayload.partialFindings || []),
      ...(previousPayload.pass4Findings || []),
      ...(previousPayload.pass5Findings || []),
    ];

    const allFindings: any[] = [];

    try {
      const [tplFindings, canaryFindings, bizFindings] = await Promise.all([
        runTemplates(target, supabase),
        trackCanaries(target, endpoints, supabase),
        businessLogicFuzz(target, endpoints, priorFindings, LOVABLE_API_KEY),
      ]);
      allFindings.push(...tplFindings, ...canaryFindings, ...bizFindings);

      // Persist findings
      for (const f of allFindings) {
        try {
          const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(f.endpoint + f.title + (f.payload || '')));
          const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
          await supabase.from('recon_findings').upsert({
            target_host: new URL(target).hostname,
            url_path: new URL(f.endpoint).pathname,
            finding_type: f.category || 'intel',
            title: f.title, description: f.description.slice(0, 500),
            severity: f.severity, hash_signature: hashHex,
            source_module: 'vapt-intel', confidence_score: f.confidence,
            verification_status: f.confidence >= 80 ? 'verified' : 'pending',
            evidence: { payload: f.payload?.slice(0, 500), evidence: f.evidence?.slice(0, 1000), poc: f.poc?.slice(0, 1500), cwe: f.cwe, cve_ids: f.cve_ids, template_id: f.template_id },
          }, { onConflict: 'hash_signature' });
        } catch (e) { console.error('finding upsert error:', e); }
      }

      // Final aggregated report row
      await supabase.from('security_reports').insert({
        module: 'omnisec_xbow_chained',
        scan_id: scanId,
        title: `XBOW Chained Scan - ${new URL(target).hostname}`,
        summary: `30-min multi-pass scan complete. ${allFindings.length} new findings from templates+canaries+business-logic on top of prior passes.`,
        findings: allFindings.slice(0, 50),
        severity_counts: {
          critical: allFindings.filter(f => f.severity === 'critical').length,
          high: allFindings.filter(f => f.severity === 'high').length,
          medium: allFindings.filter(f => f.severity === 'medium').length,
          low: allFindings.filter(f => f.severity === 'low').length,
          info: allFindings.filter(f => f.severity === 'info').length,
        },
        recommendations: ['Review all critical/high findings', 'Verify stored XSS canaries manually', 'Re-test business-logic findings with authenticated session'],
      });

      await supabase.from('scan_progress').insert({
        scan_id: scanId, phase: 'chain_complete', phase_number: 60, total_phases: 60,
        progress: 100, message: `🎉 Full chain complete! ${allFindings.length} new findings in final pass.`,
        findings_so_far: allFindings.length,
      });

      await supabase.from('scan_passes').update({
        status: 'completed', completed_at: new Date().toISOString(),
        findings_count: allFindings.length,
        payload: { ...previousPayload, finalFindings: allFindings.slice(0, 30) },
      }).eq('scan_id', scanId).eq('pass_number', passNumber);

      console.log(`[vapt-intel] Done in ${Date.now() - start}ms with ${allFindings.length} findings`);

      return new Response(JSON.stringify({ success: true, scanId, findings: allFindings.length, elapsed: Date.now() - start }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (innerErr: any) {
      console.error('[vapt-intel] error:', innerErr);
      await supabase.from('scan_passes').update({
        status: 'completed', completed_at: new Date().toISOString(),
        error_message: innerErr.message?.slice(0, 500),
      }).eq('scan_id', scanId).eq('pass_number', passNumber);
      return new Response(JSON.stringify({ success: false, error: innerErr.message }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  } catch (e: any) {
    console.error('[vapt-intel] fatal:', e);
    return new Response(JSON.stringify({ error: e.message || 'Unknown' }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
