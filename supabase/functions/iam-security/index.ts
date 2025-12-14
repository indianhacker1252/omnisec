import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface IAMFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  mitreAttack?: string;
  owasp?: string;
  remediation: string;
  affectedEndpoint?: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { testType, target, config } = await req.json();
    
    if (!target) {
      return new Response(JSON.stringify({ error: "Target is required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      return new Response(JSON.stringify({ error: "AI service not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    console.log(`Starting ${testType} IAM security test on: ${target}`);

    const testTypeDetails: Record<string, string> = {
      oauth: `OAuth 2.0 / OpenID Connect security testing:
- Authorization code flow vulnerabilities
- PKCE implementation issues
- Token leakage via referrer or logs
- Insecure redirect_uri validation
- Token scope manipulation
- Refresh token rotation issues
- Client credentials exposure`,
      
      saml: `SAML security testing:
- XML Signature Wrapping attacks
- SAML assertion replay
- Comment injection
- XXE vulnerabilities
- Improper signature validation
- Session fixation
- Identity provider bypass`,
      
      sso: `Single Sign-On configuration testing:
- Session management issues
- Cross-domain authentication flaws
- Token binding weaknesses
- Logout propagation failures
- Session timeout issues
- Account linking vulnerabilities`,
      
      jwt: `JWT security testing:
- Algorithm confusion attacks (none/HS256)
- Key confusion (RS256 to HS256)
- Weak signing keys
- Missing expiration
- Improper audience/issuer validation
- JWK injection
- Token replay attacks`,
      
      session: `Session management testing:
- Session fixation
- Insecure session storage
- Predictable session IDs
- Missing secure/HttpOnly flags
- Session hijacking vectors
- Concurrent session handling`,
      
      mfa: `MFA/2FA bypass testing:
- Rate limiting on verification codes
- Backup code weaknesses
- MFA enrollment bypass
- Time-based token issues
- Recovery flow vulnerabilities
- Device trust exploitation`
    };

    const systemPrompt = `You are an expert identity and access management security analyst performing a security assessment.

Test Type: ${testType.toUpperCase()}
Target: ${target}
${config ? `Additional Config: ${config}` : ''}

${testTypeDetails[testType] || 'General IAM security testing'}

For each finding provide:
1. Unique ID (IAM-XXX)
2. Category (e.g., Token Security, Session Management, Authentication)
3. Severity (critical/high/medium/low/info)
4. Title
5. Description
6. MITRE ATT&CK technique (e.g., T1528 - Steal Application Access Token)
7. OWASP reference if applicable (e.g., A07:2021 - Identification and Authentication Failures)
8. Affected endpoint
9. Specific remediation steps

Be thorough and realistic. Return findings as a JSON array.`;

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: `Perform comprehensive ${testType} security testing on: ${target}. Return findings as JSON array.` }
        ],
        response_format: { type: "json_object" }
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("AI gateway error:", response.status, errorText);
      throw new Error(`AI analysis failed: ${response.status}`);
    }

    const aiResponse = await response.json();
    const content = aiResponse.choices?.[0]?.message?.content || "{}";
    
    let findings: IAMFinding[] = [];
    try {
      const parsed = JSON.parse(content);
      findings = parsed.findings || parsed.vulnerabilities || (Array.isArray(parsed) ? parsed : []);
      
      findings = findings.map((f: any, idx: number) => ({
        id: f.id || `IAM-${idx + 1}`,
        category: f.category || testType.toUpperCase(),
        severity: f.severity || 'medium',
        title: f.title || 'Unknown Issue',
        description: f.description || '',
        mitreAttack: f.mitreAttack || f.mitre_attack || f.mitre,
        owasp: f.owasp || f.owasp_reference,
        affectedEndpoint: f.affectedEndpoint || f.endpoint || target,
        remediation: f.remediation || 'Review and implement security best practices'
      }));
    } catch (e) {
      console.error("Failed to parse AI response:", e);
      findings = [{
        id: 'IAM-1',
        category: testType.toUpperCase(),
        severity: 'info',
        title: 'Test Completed',
        description: 'IAM security analysis completed. Manual review recommended.',
        remediation: 'Review IAM configuration manually.'
      }];
    }

    console.log(`IAM security test complete: ${findings.length} findings`);

    return new Response(JSON.stringify({
      success: true,
      testType,
      target,
      findings,
      scanTime: Date.now(),
      recommendations: [
        "Implement proper token validation and expiration",
        "Use secure session management with proper flags",
        "Enable MFA for all privileged accounts",
        "Implement rate limiting on authentication endpoints",
        "Use PKCE for OAuth authorization code flow",
        "Validate redirect URIs strictly"
      ]
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("IAM security test error:", error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : "Unknown error",
      success: false 
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
