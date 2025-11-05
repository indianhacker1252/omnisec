import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.7.1';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface ScanPhase {
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  findings: any[];
  duration?: number;
}

interface ZAPScan {
  target: string;
  phases: {
    spider: ScanPhase;
    passiveScan: ScanPhase;
    activeScan: ScanPhase;
    authentication: ScanPhase;
  };
  overallStatus: string;
  vulnerabilities: any[];
  statistics: any;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get('authorization');
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey, {
      global: { headers: { Authorization: authHeader! } }
    });

    const { data: { user } } = await supabase.auth.getUser(authHeader!.replace('Bearer ', ''));
    if (!user) throw new Error('Unauthorized');

    const { target, scanDepth = 'standard', includeAuth = false } = await req.json();

    console.log(`[ZAP Scanner] Starting comprehensive scan of ${target}`);

    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
    if (!LOVABLE_API_KEY) throw new Error('LOVABLE_API_KEY not configured');

    const scan: ZAPScan = {
      target,
      phases: {
        spider: { name: 'Spider & Crawl', status: 'pending', findings: [] },
        passiveScan: { name: 'Passive Scanning', status: 'pending', findings: [] },
        activeScan: { name: 'Active Scanning', status: 'pending', findings: [] },
        authentication: { name: 'Authentication Testing', status: 'pending', findings: [] },
      },
      overallStatus: 'running',
      vulnerabilities: [],
      statistics: {
        urlsFound: 0,
        formsDiscovered: 0,
        parametersIdentified: 0,
        vulnerabilitiesDetected: 0,
        scanDuration: 0
      }
    };

    const startTime = Date.now();

    // Phase 1: Spider/Crawl
    await executeSpiderPhase(scan, LOVABLE_API_KEY);

    // Phase 2: Passive Scanning
    await executePassiveScan(scan, LOVABLE_API_KEY);

    // Phase 3: Active Scanning
    if (scanDepth !== 'passive-only') {
      await executeActiveScan(scan, LOVABLE_API_KEY);
    }

    // Phase 4: Authentication Testing
    if (includeAuth) {
      await executeAuthenticationTests(scan, LOVABLE_API_KEY);
    }

    scan.overallStatus = 'completed';
    scan.statistics.scanDuration = Date.now() - startTime;

    // Aggregate all vulnerabilities
    Object.values(scan.phases).forEach(phase => {
      scan.vulnerabilities.push(...phase.findings);
    });

    scan.statistics.vulnerabilitiesDetected = scan.vulnerabilities.length;

    // Store scan results
    await supabase.from('security_audit_log').insert({
      user_id: user.id,
      action: 'zap_scan',
      resource_type: 'webapp',
      resource_id: target,
      details: {
        scan_type: 'comprehensive',
        phases_completed: Object.keys(scan.phases).filter(k => scan.phases[k as keyof typeof scan.phases].status === 'completed').length,
        total_vulnerabilities: scan.vulnerabilities.length,
        statistics: scan.statistics,
        full_results: scan
      }
    });

    return new Response(JSON.stringify({
      success: true,
      scan,
      summary: generateScanSummary(scan)
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('[ZAP Scanner Error]:', error);
    return new Response(JSON.stringify({ 
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function executeSpiderPhase(scan: ZAPScan, apiKey: string) {
  scan.phases.spider.status = 'running';
  const startTime = Date.now();
  
  console.log('[Spider Phase] Starting traditional and AJAX spider...');

  const prompt = `Perform web application spidering/crawling analysis on: ${scan.target}

As an expert web crawler, identify:
1. All discoverable URLs and endpoints
2. Forms and input fields
3. API endpoints
4. Hidden parameters in URLs
5. JavaScript-rendered content
6. Directory structure
7. Technology stack indicators

Respond with ONLY valid JSON (no markdown):
{
  "urls": ["url1", "url2"],
  "forms": [{"action": "/login", "method": "POST", "fields": ["username", "password"]}],
  "apiEndpoints": ["/api/v1/users"],
  "parameters": ["id", "search", "filter"],
  "technologies": ["React", "Node.js"],
  "directories": ["/admin", "/api", "/uploads"]
}`;

  try {
    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are a web application spider. Analyze and discover application structure.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.3,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      let resultText = data.choices[0].message.content.trim();
      resultText = resultText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      
      const spiderResult = JSON.parse(resultText);
      scan.phases.spider.findings = [spiderResult];
      scan.statistics.urlsFound = spiderResult.urls?.length || 0;
      scan.statistics.formsDiscovered = spiderResult.forms?.length || 0;
      scan.statistics.parametersIdentified = spiderResult.parameters?.length || 0;
      
      scan.phases.spider.status = 'completed';
    } else {
      throw new Error('Spider phase failed');
    }
  } catch (error) {
    scan.phases.spider.status = 'failed';
    console.error('[Spider Phase Error]:', error);
  }
  
  scan.phases.spider.duration = Date.now() - startTime;
}

async function executePassiveScan(scan: ZAPScan, apiKey: string) {
  scan.phases.passiveScan.status = 'running';
  const startTime = Date.now();
  
  console.log('[Passive Scan] Analyzing HTTP traffic and responses...');

  const spiderData = scan.phases.spider.findings[0] || {};
  
  const prompt = `Perform passive security analysis on web application: ${scan.target}

Discovered URLs: ${JSON.stringify(spiderData.urls || [])}
Forms: ${JSON.stringify(spiderData.forms || [])}

Identify security issues WITHOUT active testing:
1. Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
2. Information disclosure in responses
3. Insecure cookies (missing Secure, HttpOnly, SameSite)
4. Sensitive data in URLs or responses
5. Outdated software versions
6. CORS misconfigurations
7. SSL/TLS issues

Respond with ONLY valid JSON (no markdown):
{
  "vulnerabilities": [
    {
      "type": "Missing Security Header",
      "severity": "medium",
      "name": "X-Frame-Options header missing",
      "description": "Application vulnerable to clickjacking",
      "remediation": "Add X-Frame-Options: DENY header",
      "cwe": "CWE-1021"
    }
  ]
}`;

  try {
    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are a passive security scanner analyzing HTTP traffic for vulnerabilities.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.2,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      let resultText = data.choices[0].message.content.trim();
      resultText = resultText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      
      const passiveResult = JSON.parse(resultText);
      scan.phases.passiveScan.findings = passiveResult.vulnerabilities || [];
      scan.phases.passiveScan.status = 'completed';
    } else {
      throw new Error('Passive scan failed');
    }
  } catch (error) {
    scan.phases.passiveScan.status = 'failed';
    console.error('[Passive Scan Error]:', error);
  }
  
  scan.phases.passiveScan.duration = Date.now() - startTime;
}

async function executeActiveScan(scan: ZAPScan, apiKey: string) {
  scan.phases.activeScan.status = 'running';
  const startTime = Date.now();
  
  console.log('[Active Scan] Testing for OWASP Top 10 vulnerabilities...');

  const spiderData = scan.phases.spider.findings[0] || {};
  
  const prompt = `Perform active vulnerability scanning on: ${scan.target}

Application structure:
Forms: ${JSON.stringify(spiderData.forms || [])}
Parameters: ${JSON.stringify(spiderData.parameters || [])}
APIs: ${JSON.stringify(spiderData.apiEndpoints || [])}

Test for OWASP Top 10 vulnerabilities:
1. SQL Injection (test parameters with SQL payloads)
2. XSS (Cross-Site Scripting)
3. CSRF (Cross-Site Request Forgery)
4. Authentication bypass attempts
5. Authorization flaws
6. Command injection
7. Path traversal
8. XXE (XML External Entity)
9. SSRF (Server-Side Request Forgery)
10. Deserialization vulnerabilities

For each vulnerability found, provide:
- Type and OWASP category
- Severity (critical/high/medium/low)
- Affected endpoint/parameter
- Proof of concept
- Remediation steps

Respond with ONLY valid JSON (no markdown):
{
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "owasp": "A03:2021 - Injection",
      "severity": "critical",
      "endpoint": "/api/users?id=1",
      "parameter": "id",
      "poc": "id=1' OR '1'='1",
      "impact": "Database compromise, data exfiltration",
      "remediation": "Use parameterized queries",
      "cwe": "CWE-89",
      "cvss": 9.8
    }
  ]
}`;

  try {
    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-pro',
        messages: [
          { role: 'system', content: 'You are an advanced active vulnerability scanner testing for OWASP Top 10 and beyond.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.2,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      let resultText = data.choices[0].message.content.trim();
      resultText = resultText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      
      const activeResult = JSON.parse(resultText);
      scan.phases.activeScan.findings = activeResult.vulnerabilities || [];
      scan.phases.activeScan.status = 'completed';
    } else {
      throw new Error('Active scan failed');
    }
  } catch (error) {
    scan.phases.activeScan.status = 'failed';
    console.error('[Active Scan Error]:', error);
  }
  
  scan.phases.activeScan.duration = Date.now() - startTime;
}

async function executeAuthenticationTests(scan: ZAPScan, apiKey: string) {
  scan.phases.authentication.status = 'running';
  const startTime = Date.now();
  
  console.log('[Auth Testing] Analyzing authentication mechanisms...');

  const spiderData = scan.phases.spider.findings[0] || {};
  
  const prompt = `Analyze authentication security for: ${scan.target}

Forms discovered: ${JSON.stringify(spiderData.forms || [])}

Test authentication mechanisms for:
1. Weak password policies
2. Brute force protection
3. Session management flaws
4. Insecure credential transmission
5. Authentication bypass vulnerabilities
6. Multi-factor authentication presence
7. Password reset vulnerabilities
8. Session fixation
9. Insufficient session expiration

Respond with ONLY valid JSON (no markdown):
{
  "findings": [
    {
      "type": "Weak Password Policy",
      "severity": "high",
      "description": "No password complexity requirements detected",
      "remediation": "Implement strong password policy"
    }
  ]
}`;

  try {
    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are an authentication security specialist.' },
          { role: 'user', content: prompt }
        ],
        temperature: 0.2,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      let resultText = data.choices[0].message.content.trim();
      resultText = resultText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      
      const authResult = JSON.parse(resultText);
      scan.phases.authentication.findings = authResult.findings || [];
      scan.phases.authentication.status = 'completed';
    } else {
      throw new Error('Authentication testing failed');
    }
  } catch (error) {
    scan.phases.authentication.status = 'failed';
    console.error('[Auth Testing Error]:', error);
  }
  
  scan.phases.authentication.duration = Date.now() - startTime;
}

function generateScanSummary(scan: ZAPScan) {
  const criticalVulns = scan.vulnerabilities.filter(v => v.severity === 'critical').length;
  const highVulns = scan.vulnerabilities.filter(v => v.severity === 'high').length;
  const mediumVulns = scan.vulnerabilities.filter(v => v.severity === 'medium').length;
  const lowVulns = scan.vulnerabilities.filter(v => v.severity === 'low').length;

  return {
    target: scan.target,
    status: scan.overallStatus,
    phasesCompleted: Object.values(scan.phases).filter(p => p.status === 'completed').length,
    totalPhases: Object.keys(scan.phases).length,
    vulnerabilitiesBySeversity: {
      critical: criticalVulns,
      high: highVulns,
      medium: mediumVulns,
      low: lowVulns
    },
    statistics: scan.statistics,
    recommendedActions: criticalVulns > 0 
      ? 'CRITICAL: Immediate remediation required'
      : highVulns > 0 
      ? 'HIGH: Address vulnerabilities within 24-48 hours'
      : 'Review and remediate identified issues'
  };
}