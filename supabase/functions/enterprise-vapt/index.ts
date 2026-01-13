import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * OmniSec™ Enterprise VAPT Scanner
 * Real-data vulnerability assessment with AI-powered analysis and learning
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface ScanRequest {
  target: string;
  modules: string[];
  deep?: boolean;
  retryWithNewPayloads?: boolean;
  previousFindings?: any[];
}

interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  endpoint: string;
  method?: string;
  evidence?: string;
  remediation: string;
  cwe?: string;
  cvss?: number;
  mitre?: string[];
  payload?: string;
  response?: string;
  confidence: number;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const body: ScanRequest = await req.json();
    const { target, modules, deep = true, retryWithNewPayloads = false, previousFindings = [] } = body;

    if (!target) {
      return new Response(
        JSON.stringify({ error: "Target is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Normalize target URL
    let targetUrl: URL;
    try {
      targetUrl = new URL(target.startsWith('http') ? target : `https://${target}`);
    } catch {
      return new Response(
        JSON.stringify({ error: "Invalid target URL" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    console.log(`Starting Enterprise VAPT on ${targetUrl.toString()} with modules: ${modules.join(', ')}`);

    const allFindings: Finding[] = [];
    const scanResults: Record<string, any> = {};
    const startTime = Date.now();

    // Phase 1: Real HTTP reconnaissance
    const reconData = await performReconnaissance(targetUrl);
    scanResults.recon = reconData;

    // Phase 2: Module-specific scanning with real requests
    for (const module of modules) {
      try {
        const moduleFindings = await scanModule(module, targetUrl, reconData, LOVABLE_API_KEY, previousFindings, retryWithNewPayloads);
        scanResults[module] = moduleFindings;
        allFindings.push(...moduleFindings.findings);
      } catch (e: any) {
        console.error(`Module ${module} error:`, e);
        scanResults[module] = { error: e?.message || 'Unknown error', findings: [] };
      }
    }

    // Phase 3: AI-powered correlation and attack path analysis
    const correlationResult = await analyzeWithAI(allFindings, reconData, targetUrl.toString(), LOVABLE_API_KEY);

    // Save to database for learning
    await supabase.from('scan_history').insert({
      module: 'enterprise_vapt',
      scan_type: 'Enterprise VAPT - Full Assessment',
      target: targetUrl.toString(),
      status: 'completed',
      findings_count: allFindings.length,
      duration_ms: Date.now() - startTime,
      report: {
        recon: reconData,
        modules: scanResults,
        correlation: correlationResult,
        allFindings
      }
    });

    // Save report
    const severityCounts = {
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      info: allFindings.filter(f => f.severity === 'info').length
    };

    await supabase.from('security_reports').insert({
      module: 'enterprise_vapt',
      title: `Enterprise VAPT - ${targetUrl.hostname}`,
      summary: `Real-data scan found ${allFindings.length} vulnerabilities: ${severityCounts.critical} critical, ${severityCounts.high} high, ${severityCounts.medium} medium`,
      findings: allFindings,
      severity_counts: severityCounts,
      recommendations: correlationResult.recommendations
    });

    return new Response(
      JSON.stringify({
        success: true,
        target: targetUrl.toString(),
        scanTime: Date.now() - startTime,
        recon: reconData,
        modules: scanResults,
        findings: allFindings,
        attackPaths: correlationResult.attackPaths,
        correlations: correlationResult.correlations,
        summary: severityCounts,
        recommendations: correlationResult.recommendations
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error: any) {
    console.error("Enterprise VAPT error:", error);
    return new Response(
      JSON.stringify({ error: error.message || "Scan failed", success: false }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

async function performReconnaissance(target: URL): Promise<any> {
  const results: any = {
    target: target.toString(),
    hostname: target.hostname,
    headers: {},
    technologies: [],
    endpoints: [],
    securityHeaders: {},
    cookies: [],
    forms: [],
    scripts: [],
    serverInfo: null
  };

  try {
    // Fetch main page with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    
    const response = await fetch(target.toString(), {
      method: "GET",
      signal: controller.signal,
      headers: {
        "User-Agent": "OmniSec Enterprise VAPT Scanner/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    });
    clearTimeout(timeoutId);

    // Extract headers
    response.headers.forEach((value, key) => {
      results.headers[key] = value;
      
      // Security headers analysis
      if (['x-frame-options', 'content-security-policy', 'strict-transport-security', 
           'x-content-type-options', 'x-xss-protection', 'referrer-policy'].includes(key.toLowerCase())) {
        results.securityHeaders[key] = value;
      }
      
      if (key.toLowerCase() === 'server') {
        results.serverInfo = value;
      }
      
      if (key.toLowerCase() === 'set-cookie') {
        results.cookies.push(value);
      }

      if (key.toLowerCase() === 'x-powered-by') {
        results.technologies.push(value);
      }
    });

    // Parse HTML for endpoints and forms
    const html = await response.text();
    
    // Extract links/endpoints
    const linkMatches = html.match(/href=["']([^"']+)["']/gi) || [];
    const actionMatches = html.match(/action=["']([^"']+)["']/gi) || [];
    const srcMatches = html.match(/src=["']([^"']+)["']/gi) || [];
    
    const endpoints = new Set<string>();
    [...linkMatches, ...actionMatches].forEach(match => {
      const url = match.replace(/^(href|action)=["']/i, '').replace(/["']$/, '');
      if (url && !url.startsWith('#') && !url.startsWith('javascript:')) {
        endpoints.add(url);
      }
    });
    results.endpoints = Array.from(endpoints).slice(0, 50);

    // Extract form details
    const formMatches = html.match(/<form[^>]*>[\s\S]*?<\/form>/gi) || [];
    results.forms = formMatches.slice(0, 10).map((form, i) => {
      const action = form.match(/action=["']([^"']+)["']/i)?.[1] || '';
      const method = form.match(/method=["']([^"']+)["']/i)?.[1] || 'GET';
      const inputs = (form.match(/<input[^>]+>/gi) || []).map(inp => {
        const name = inp.match(/name=["']([^"']+)["']/i)?.[1];
        const type = inp.match(/type=["']([^"']+)["']/i)?.[1] || 'text';
        return { name, type };
      }).filter(i => i.name);
      return { id: i, action, method: method.toUpperCase(), inputs };
    });

    // Detect technologies
    if (html.includes('wp-content') || html.includes('WordPress')) results.technologies.push('WordPress');
    if (html.includes('Joomla')) results.technologies.push('Joomla');
    if (html.includes('Drupal')) results.technologies.push('Drupal');
    if (html.includes('React') || html.includes('react')) results.technologies.push('React');
    if (html.includes('Angular') || html.includes('ng-')) results.technologies.push('Angular');
    if (html.includes('Vue') || html.includes('v-')) results.technologies.push('Vue.js');
    if (html.includes('jQuery') || html.includes('jquery')) results.technologies.push('jQuery');
    if (html.includes('php')) results.technologies.push('PHP');
    if (html.includes('.aspx') || html.includes('ASP.NET')) results.technologies.push('ASP.NET');

    // Extract script sources
    srcMatches.forEach(match => {
      const src = match.replace(/^src=["']/i, '').replace(/["']$/, '');
      if (src.endsWith('.js')) results.scripts.push(src);
    });
    results.scripts = results.scripts.slice(0, 20);

  } catch (e: any) {
    console.error("Recon error:", e.message);
    results.error = e.message;
  }

  return results;
}

async function scanModule(
  module: string, 
  target: URL, 
  reconData: any, 
  apiKey: string | undefined,
  previousFindings: any[],
  retryWithNewPayloads: boolean
): Promise<{ findings: Finding[], metadata: any }> {
  
  const findings: Finding[] = [];
  const metadata: any = { module, scannedAt: new Date().toISOString() };

  switch (module) {
    case 'web':
      return await scanWebApplication(target, reconData, apiKey, previousFindings, retryWithNewPayloads);
    case 'api':
      return await scanAPIEndpoints(target, reconData, apiKey);
    case 'network':
      return await scanNetworkServices(target, reconData);
    case 'cloud':
      return await scanCloudMisconfig(target, reconData, apiKey);
    case 'iam':
      return await scanIAMVulns(target, reconData, apiKey);
    case 'container':
      return await scanContainerSecurity(target, reconData, apiKey);
    default:
      return { findings: [], metadata: { module, note: 'Module not implemented' } };
  }
}

async function scanWebApplication(
  target: URL, 
  recon: any, 
  apiKey: string | undefined,
  previousFindings: any[],
  retryWithNewPayloads: boolean
): Promise<{ findings: Finding[], metadata: any }> {
  
  const findings: Finding[] = [];
  const testedEndpoints: string[] = [];

  // Test security headers
  const missingHeaders = ['x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options'];
  for (const header of missingHeaders) {
    if (!recon.securityHeaders[header]) {
      findings.push({
        id: `WEB-HDR-${header}`,
        severity: header === 'content-security-policy' ? 'medium' : 'low',
        title: `Missing ${header.toUpperCase()} Header`,
        description: `The security header ${header} is not present on the response.`,
        endpoint: target.toString(),
        evidence: `Headers: ${JSON.stringify(recon.headers, null, 2).slice(0, 500)}`,
        remediation: `Add ${header} header to all responses`,
        cwe: header === 'x-frame-options' ? 'CWE-1021' : 'CWE-16',
        confidence: 95
      });
    }
  }

  // Test forms for injection vulnerabilities with real payloads
  const xssPayloads = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg/onload=alert(1)>'
  ];
  
  const sqlPayloads = [
    "' OR '1'='1",
    "1' AND '1'='1",
    "'; DROP TABLE--",
    "1 UNION SELECT NULL--"
  ];

  // If retrying with new payloads, generate AI-enhanced payloads
  let enhancedPayloads = { xss: xssPayloads, sql: sqlPayloads };
  if (retryWithNewPayloads && apiKey && previousFindings.length > 0) {
    enhancedPayloads = await generateAIPayloads(target.toString(), previousFindings, apiKey);
  }

  for (const form of recon.forms.slice(0, 5)) {
    const formUrl = form.action ? new URL(form.action, target).toString() : target.toString();
    testedEndpoints.push(formUrl);

    for (const input of form.inputs) {
      // Test XSS
      for (const payload of enhancedPayloads.xss.slice(0, 2)) {
        try {
          const formData = new URLSearchParams();
          formData.set(input.name, payload);
          
          const response = await fetch(formUrl, {
            method: form.method,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString(),
            redirect: 'follow'
          });
          
          const responseText = await response.text();
          
          // Check if payload is reflected
          if (responseText.includes(payload) || responseText.includes(payload.replace(/</g, '&lt;'))) {
            findings.push({
              id: `WEB-XSS-${Date.now()}`,
              severity: responseText.includes(payload) ? 'high' : 'medium',
              title: 'Cross-Site Scripting (XSS) Vulnerability',
              description: `Input field "${input.name}" reflects user input without proper sanitization.`,
              endpoint: formUrl,
              method: form.method,
              payload: payload,
              evidence: `Input: ${input.name}, Payload reflected in response`,
              response: responseText.slice(0, 500),
              remediation: 'Implement proper output encoding and Content-Security-Policy',
              cwe: 'CWE-79',
              cvss: 6.1,
              mitre: ['T1059.007'],
              confidence: 85
            });
            break; // Found XSS, move to next input
          }
        } catch (e) {
          // Request failed, continue
        }
      }

      // Test SQL Injection
      for (const payload of enhancedPayloads.sql.slice(0, 2)) {
        try {
          const formData = new URLSearchParams();
          formData.set(input.name, payload);
          
          const response = await fetch(formUrl, {
            method: form.method,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString()
          });
          
          const responseText = await response.text();
          
          // Check for SQL error indicators
          const sqlErrors = ['sql syntax', 'mysql', 'postgresql', 'sqlite', 'oracle', 'sql error', 'odbc', 'jdbc'];
          const hasError = sqlErrors.some(err => responseText.toLowerCase().includes(err));
          
          if (hasError) {
            findings.push({
              id: `WEB-SQLI-${Date.now()}`,
              severity: 'critical',
              title: 'SQL Injection Vulnerability',
              description: `Database error exposed when injecting SQL payload into "${input.name}".`,
              endpoint: formUrl,
              method: form.method,
              payload: payload,
              evidence: 'SQL error message detected in response',
              response: responseText.slice(0, 500),
              remediation: 'Use parameterized queries and prepared statements',
              cwe: 'CWE-89',
              cvss: 9.8,
              mitre: ['T1190', 'T1505'],
              confidence: 90
            });
            break;
          }
        } catch (e) {
          // Request failed
        }
      }
    }
  }

  // Test common vulnerable paths
  const sensitivePaths = [
    { path: '/.git/config', severity: 'critical' as const, desc: 'Git configuration exposed' },
    { path: '/.env', severity: 'critical' as const, desc: 'Environment file exposed' },
    { path: '/phpinfo.php', severity: 'high' as const, desc: 'PHP info page accessible' },
    { path: '/admin', severity: 'medium' as const, desc: 'Admin panel accessible' },
    { path: '/backup', severity: 'high' as const, desc: 'Backup directory accessible' },
    { path: '/debug', severity: 'high' as const, desc: 'Debug endpoint accessible' },
    { path: '/.htaccess', severity: 'medium' as const, desc: 'Apache config exposed' },
    { path: '/web.config', severity: 'medium' as const, desc: 'IIS config exposed' },
  ];

  for (const { path, severity, desc } of sensitivePaths) {
    try {
      const testUrl = new URL(path, target).toString();
      const response = await fetch(testUrl, { 
        method: 'GET',
        redirect: 'manual'
      });
      
      if (response.status === 200) {
        const contentLength = response.headers.get('content-length');
        if (contentLength && parseInt(contentLength) > 0) {
          findings.push({
            id: `WEB-PATH-${path.replace(/[^a-z]/gi, '')}`,
            severity,
            title: `Sensitive Path Exposed: ${path}`,
            description: desc,
            endpoint: testUrl,
            method: 'GET',
            evidence: `HTTP ${response.status}, Content-Length: ${contentLength}`,
            remediation: 'Restrict access to sensitive files and directories',
            cwe: 'CWE-200',
            confidence: 90
          });
        }
      }
    } catch (e) {
      // Path not accessible
    }
  }

  return {
    findings,
    metadata: {
      module: 'web',
      formsScanned: recon.forms.length,
      endpointsTested: testedEndpoints.length,
      payloadsUsed: retryWithNewPayloads ? 'AI-enhanced' : 'standard'
    }
  };
}

async function scanAPIEndpoints(target: URL, recon: any, apiKey: string | undefined): Promise<{ findings: Finding[], metadata: any }> {
  const findings: Finding[] = [];
  
  // Common API paths to test
  const apiPaths = [
    '/api', '/api/v1', '/api/v2', '/graphql', '/rest', '/swagger', '/swagger-ui',
    '/api-docs', '/openapi.json', '/swagger.json', '/api/users', '/api/admin'
  ];

  for (const path of apiPaths) {
    try {
      const testUrl = new URL(path, target).toString();
      const response = await fetch(testUrl, {
        method: 'GET',
        headers: { 'Accept': 'application/json' }
      });

      if (response.status === 200) {
        const contentType = response.headers.get('content-type') || '';
        const body = await response.text();
        
        if (contentType.includes('json') || body.startsWith('{') || body.startsWith('[')) {
          findings.push({
            id: `API-DISC-${path.replace(/[^a-z]/gi, '')}`,
            severity: path.includes('swagger') || path.includes('api-docs') ? 'medium' : 'info',
            title: `API Endpoint Discovered: ${path}`,
            description: `API endpoint accessible at ${path}`,
            endpoint: testUrl,
            method: 'GET',
            evidence: `Content-Type: ${contentType}, Response: ${body.slice(0, 200)}`,
            remediation: 'Ensure proper authentication on API endpoints',
            cwe: 'CWE-200',
            confidence: 95
          });

          // Test for BOLA/IDOR if it's a user endpoint
          if (path.includes('user') || path.includes('admin')) {
            try {
              const idorUrl = new URL(`${path}/1`, target).toString();
              const idorResponse = await fetch(idorUrl, { method: 'GET' });
              if (idorResponse.status === 200) {
                findings.push({
                  id: `API-IDOR-${Date.now()}`,
                  severity: 'high',
                  title: 'Potential IDOR/BOLA Vulnerability',
                  description: 'Direct object reference accessible without proper authorization check',
                  endpoint: idorUrl,
                  method: 'GET',
                  evidence: `Accessed ${idorUrl} successfully`,
                  remediation: 'Implement proper authorization checks for each request',
                  cwe: 'CWE-639',
                  cvss: 7.5,
                  mitre: ['T1078'],
                  confidence: 75
                });
              }
            } catch (e) {}
          }
        }
      }

      // Check for GraphQL introspection
      if (path === '/graphql') {
        try {
          const introspectionQuery = JSON.stringify({
            query: '{ __schema { types { name } } }'
          });
          const gqlResponse = await fetch(testUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: introspectionQuery
          });
          
          if (gqlResponse.status === 200) {
            const gqlBody = await gqlResponse.text();
            if (gqlBody.includes('__schema')) {
              findings.push({
                id: 'API-GQL-INTRO',
                severity: 'medium',
                title: 'GraphQL Introspection Enabled',
                description: 'GraphQL introspection is enabled, exposing full API schema',
                endpoint: testUrl,
                method: 'POST',
                evidence: 'Introspection query returned schema information',
                remediation: 'Disable GraphQL introspection in production',
                cwe: 'CWE-200',
                confidence: 95
              });
            }
          }
        } catch (e) {}
      }
    } catch (e) {
      // Endpoint not accessible
    }
  }

  // Test rate limiting
  try {
    const testUrl = new URL('/api', target).toString();
    let rateLimited = false;
    for (let i = 0; i < 20; i++) {
      const response = await fetch(testUrl, { method: 'GET' });
      if (response.status === 429) {
        rateLimited = true;
        break;
      }
    }
    if (!rateLimited) {
      findings.push({
        id: 'API-RATE-LIMIT',
        severity: 'medium',
        title: 'No Rate Limiting Detected',
        description: 'API does not appear to implement rate limiting',
        endpoint: testUrl,
        evidence: '20 rapid requests did not trigger rate limiting',
        remediation: 'Implement rate limiting on all API endpoints',
        cwe: 'CWE-770',
        confidence: 70
      });
    }
  } catch (e) {}

  return { findings, metadata: { module: 'api', pathsTested: apiPaths.length } };
}

async function scanNetworkServices(target: URL, recon: any): Promise<{ findings: Finding[], metadata: any }> {
  const findings: Finding[] = [];
  
  // Check for exposed services via common ports (simulated - real port scanning requires lower-level access)
  const commonServices = [
    { port: 21, name: 'FTP', severity: 'high' as const },
    { port: 22, name: 'SSH', severity: 'info' as const },
    { port: 23, name: 'Telnet', severity: 'critical' as const },
    { port: 3306, name: 'MySQL', severity: 'high' as const },
    { port: 5432, name: 'PostgreSQL', severity: 'high' as const },
    { port: 6379, name: 'Redis', severity: 'high' as const },
    { port: 27017, name: 'MongoDB', severity: 'high' as const },
  ];

  // Check via HTTP probing alternate ports
  for (const { port, name, severity } of commonServices) {
    try {
      const testUrl = `${target.protocol}//${target.hostname}:${port}/`;
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      const response = await fetch(testUrl, {
        method: 'GET',
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      
      findings.push({
        id: `NET-SVC-${name}`,
        severity,
        title: `${name} Service Detected on Port ${port}`,
        description: `${name} service appears to be accessible on port ${port}`,
        endpoint: testUrl,
        evidence: `HTTP probe returned status ${response.status}`,
        remediation: `Restrict access to ${name} service using firewall rules`,
        cwe: 'CWE-284',
        confidence: 60
      });
    } catch (e) {
      // Service not accessible via HTTP or timeout
    }
  }

  // Check SSL/TLS
  if (target.protocol === 'https:') {
    findings.push({
      id: 'NET-TLS-OK',
      severity: 'info',
      title: 'HTTPS Enabled',
      description: 'Site uses HTTPS encryption',
      endpoint: target.toString(),
      evidence: 'Connection established over HTTPS',
      remediation: 'Ensure TLS 1.2+ is enforced',
      confidence: 100
    });
  } else {
    findings.push({
      id: 'NET-NO-TLS',
      severity: 'critical',
      title: 'No HTTPS Encryption',
      description: 'Site does not use HTTPS - traffic is unencrypted',
      endpoint: target.toString(),
      evidence: 'Connection over HTTP',
      remediation: 'Implement HTTPS with valid TLS certificate',
      cwe: 'CWE-319',
      cvss: 7.5,
      confidence: 100
    });
  }

  return { findings, metadata: { module: 'network', servicesTested: commonServices.length } };
}

async function scanCloudMisconfig(target: URL, recon: any, apiKey: string | undefined): Promise<{ findings: Finding[], metadata: any }> {
  const findings: Finding[] = [];

  // Check for cloud-specific headers/indicators
  const cloudIndicators = {
    aws: ['x-amz', 'aws', 's3.amazonaws.com', 'cloudfront'],
    azure: ['x-ms', 'azure', 'blob.core.windows.net', 'azurewebsites'],
    gcp: ['x-goog', 'storage.googleapis.com', 'appspot.com']
  };

  let detectedCloud = null;
  for (const [provider, indicators] of Object.entries(cloudIndicators)) {
    const headerStr = JSON.stringify(recon.headers).toLowerCase();
    if (indicators.some(ind => headerStr.includes(ind))) {
      detectedCloud = provider;
      break;
    }
  }

  if (detectedCloud) {
    findings.push({
      id: `CLOUD-DETECT-${detectedCloud.toUpperCase()}`,
      severity: 'info',
      title: `${detectedCloud.toUpperCase()} Cloud Platform Detected`,
      description: `Application appears to be hosted on ${detectedCloud.toUpperCase()}`,
      endpoint: target.toString(),
      evidence: 'Cloud-specific headers detected',
      remediation: 'Review cloud security configuration',
      confidence: 80
    });
  }

  // Check for S3 bucket misconfigurations
  const s3Patterns = recon.endpoints.filter((e: string) => 
    e.includes('s3.amazonaws.com') || e.includes('.s3.') || e.match(/s3[.-]/i)
  );

  for (const s3Url of s3Patterns.slice(0, 5)) {
    try {
      const response = await fetch(s3Url, { method: 'GET' });
      if (response.status === 200) {
        findings.push({
          id: `CLOUD-S3-PUBLIC-${Date.now()}`,
          severity: 'high',
          title: 'Publicly Accessible S3 Bucket',
          description: 'S3 bucket is publicly accessible without authentication',
          endpoint: s3Url,
          evidence: `HTTP ${response.status}`,
          remediation: 'Configure S3 bucket policy to restrict public access',
          cwe: 'CWE-732',
          mitre: ['T1530'],
          confidence: 90
        });
      }
    } catch (e) {}
  }

  // Check for cloud metadata endpoint exposure (SSRF indicator)
  const metadataEndpoints = [
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/',
  ];

  // Note: We can't directly test these from edge function, but check if app might be vulnerable
  if (recon.endpoints.some((e: string) => e.includes('url=') || e.includes('redirect='))) {
    findings.push({
      id: 'CLOUD-SSRF-RISK',
      severity: 'medium',
      title: 'Potential SSRF Risk',
      description: 'URL parameters detected that could be vulnerable to SSRF targeting cloud metadata',
      endpoint: target.toString(),
      evidence: 'URL/redirect parameters found in application',
      remediation: 'Validate and sanitize all URL inputs, block internal IP ranges',
      cwe: 'CWE-918',
      mitre: ['T1552.005'],
      confidence: 60
    });
  }

  return { findings, metadata: { module: 'cloud', detectedCloud } };
}

async function scanIAMVulns(target: URL, recon: any, apiKey: string | undefined): Promise<{ findings: Finding[], metadata: any }> {
  const findings: Finding[] = [];

  // Check for common auth endpoints
  const authPaths = ['/login', '/signin', '/auth', '/oauth', '/saml', '/api/auth', '/api/login'];
  
  for (const path of authPaths) {
    try {
      const testUrl = new URL(path, target).toString();
      const response = await fetch(testUrl, { method: 'GET', redirect: 'manual' });
      
      if (response.status === 200 || response.status === 302) {
        findings.push({
          id: `IAM-AUTH-${path.replace(/[^a-z]/gi, '')}`,
          severity: 'info',
          title: `Authentication Endpoint: ${path}`,
          description: 'Authentication endpoint discovered',
          endpoint: testUrl,
          evidence: `HTTP ${response.status}`,
          remediation: 'Ensure strong authentication mechanisms',
          confidence: 90
        });

        // Test for user enumeration
        try {
          const enumTest = await fetch(testUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'username=admin&password=wrongpassword123'
          });
          const enumBody = await enumTest.text();
          
          if (enumBody.toLowerCase().includes('user not found') || 
              enumBody.toLowerCase().includes('invalid username')) {
            findings.push({
              id: `IAM-ENUM-${Date.now()}`,
              severity: 'medium',
              title: 'User Enumeration Possible',
              description: 'Application reveals whether username exists',
              endpoint: testUrl,
              method: 'POST',
              evidence: 'Different error messages for valid/invalid users',
              remediation: 'Use generic error messages for authentication failures',
              cwe: 'CWE-204',
              confidence: 80
            });
          }
        } catch (e) {}

        // Test for brute force protection
        let blockedAfter = 0;
        for (let i = 0; i < 10; i++) {
          try {
            const bruteTest = await fetch(testUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: 'username=admin&password=test' + i
            });
            if (bruteTest.status === 429 || bruteTest.status === 423) {
              blockedAfter = i + 1;
              break;
            }
          } catch (e) { break; }
        }
        
        if (blockedAfter === 0) {
          findings.push({
            id: 'IAM-BRUTE-NO-PROTECT',
            severity: 'high',
            title: 'No Brute Force Protection',
            description: 'No account lockout or rate limiting after failed login attempts',
            endpoint: testUrl,
            evidence: '10 failed attempts without lockout',
            remediation: 'Implement account lockout and rate limiting',
            cwe: 'CWE-307',
            cvss: 7.5,
            mitre: ['T1110'],
            confidence: 85
          });
        }
      }
    } catch (e) {}
  }

  // Check for JWT in cookies without secure flags
  for (const cookie of recon.cookies) {
    const cookieLower = cookie.toLowerCase();
    if (cookie.includes('jwt') || cookie.includes('token') || cookie.includes('session')) {
      if (!cookieLower.includes('httponly')) {
        findings.push({
          id: 'IAM-COOKIE-HTTPONLY',
          severity: 'medium',
          title: 'Session Cookie Missing HttpOnly',
          description: 'Authentication cookie accessible via JavaScript',
          endpoint: target.toString(),
          evidence: `Cookie: ${cookie.slice(0, 100)}`,
          remediation: 'Add HttpOnly flag to session cookies',
          cwe: 'CWE-1004',
          confidence: 95
        });
      }
      if (!cookieLower.includes('secure')) {
        findings.push({
          id: 'IAM-COOKIE-SECURE',
          severity: 'medium',
          title: 'Session Cookie Missing Secure Flag',
          description: 'Authentication cookie may be sent over unencrypted connection',
          endpoint: target.toString(),
          evidence: `Cookie: ${cookie.slice(0, 100)}`,
          remediation: 'Add Secure flag to session cookies',
          cwe: 'CWE-614',
          confidence: 95
        });
      }
    }
  }

  return { findings, metadata: { module: 'iam', authEndpointsFound: authPaths.length } };
}

async function scanContainerSecurity(target: URL, recon: any, apiKey: string | undefined): Promise<{ findings: Finding[], metadata: any }> {
  const findings: Finding[] = [];

  // Check for Docker/Kubernetes indicators
  const k8sIndicators = [
    '/healthz', '/readyz', '/livez', '/metrics', '/debug/pprof',
    '/.kube/config', '/var/run/secrets/kubernetes.io'
  ];

  for (const path of k8sIndicators) {
    try {
      const testUrl = new URL(path, target).toString();
      const response = await fetch(testUrl, { method: 'GET' });
      
      if (response.status === 200) {
        const body = await response.text();
        findings.push({
          id: `K8S-${path.replace(/[^a-z]/gi, '')}`,
          severity: path.includes('secrets') || path.includes('kube') ? 'critical' : 'medium',
          title: `Kubernetes Endpoint Exposed: ${path}`,
          description: 'Kubernetes internal endpoint accessible externally',
          endpoint: testUrl,
          evidence: `Response: ${body.slice(0, 200)}`,
          remediation: 'Restrict access to internal Kubernetes endpoints',
          cwe: 'CWE-200',
          mitre: ['T1552'],
          confidence: 90
        });
      }
    } catch (e) {}
  }

  // Check for Docker registry exposure
  try {
    const registryUrl = new URL('/v2/', target).toString();
    const response = await fetch(registryUrl, { method: 'GET' });
    if (response.status === 200 || response.status === 401) {
      findings.push({
        id: 'DOCKER-REGISTRY',
        severity: response.status === 200 ? 'critical' : 'medium',
        title: 'Docker Registry Detected',
        description: `Docker registry endpoint found${response.status === 200 ? ' and accessible without auth' : ''}`,
        endpoint: registryUrl,
        evidence: `HTTP ${response.status}`,
        remediation: 'Secure Docker registry with authentication',
        cwe: 'CWE-306',
        confidence: 85
      });
    }
  } catch (e) {}

  return { findings, metadata: { module: 'container', indicatorsTested: k8sIndicators.length } };
}

async function generateAIPayloads(target: string, previousFindings: any[], apiKey: string): Promise<{ xss: string[], sql: string[] }> {
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
            content: `You are a security researcher generating bypass payloads based on failed attempts. Generate NEW payloads that might bypass WAF or input filters.`
          },
          {
            role: "user",
            content: `Target: ${target}\nPrevious failed payloads: ${JSON.stringify(previousFindings.slice(0, 5).map(f => f.payload))}\n\nGenerate 3 NEW XSS and 3 NEW SQL injection payloads that use different encoding/obfuscation techniques. Return as JSON: { "xss": [...], "sql": [...] }`
          }
        ],
        response_format: { type: "json_object" }
      }),
    });

    if (response.ok) {
      const data = await response.json();
      const content = JSON.parse(data.choices?.[0]?.message?.content || '{}');
      return {
        xss: content.xss || [],
        sql: content.sql || []
      };
    }
  } catch (e) {
    console.error("AI payload generation failed:", e);
  }

  return { xss: [], sql: [] };
}

async function analyzeWithAI(findings: Finding[], recon: any, target: string, apiKey: string | undefined): Promise<any> {
  if (!apiKey || findings.length === 0) {
    return { attackPaths: [], correlations: [], recommendations: [] };
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
            content: `You are an expert penetration tester analyzing real vulnerability findings. Identify attack paths by correlating vulnerabilities. Map to MITRE ATT&CK.`
          },
          {
            role: "user",
            content: `Target: ${target}
Technologies: ${recon.technologies?.join(', ') || 'Unknown'}
Server: ${recon.serverInfo || 'Unknown'}

Findings (${findings.length} total):
${findings.map(f => `- ${f.severity.toUpperCase()}: ${f.title} at ${f.endpoint}`).join('\n')}

Analyze these REAL findings and identify:
1. Attack paths (chain of vulnerabilities leading to compromise)
2. Correlations between findings
3. Prioritized remediation recommendations

Return JSON: { "attackPaths": [{ "name": "", "severity": "", "steps": [], "mitre": [] }], "correlations": [], "recommendations": [] }`
          }
        ],
        response_format: { type: "json_object" }
      }),
    });

    if (response.ok) {
      const data = await response.json();
      return JSON.parse(data.choices?.[0]?.message?.content || '{}');
    }
  } catch (e) {
    console.error("AI analysis failed:", e);
  }

  return { attackPaths: [], correlations: [], recommendations: [] };
}
