import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface CloudFinding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  resource: string;
  provider: string;
  mitreAttack?: string;
  remediation: string;
  poc?: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body = await req.json();
    const target = body.target;
    const provider = body.provider || "auto";
    
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

    console.log(`Starting cloud security scan on: ${target} (provider: ${provider})`);

    // Real cloud infrastructure probing
    const realFindings: CloudFinding[] = [];
    let targetUrl: URL;
    try {
      targetUrl = new URL(target.startsWith("http") ? target : `https://${target}`);
    } catch {
      targetUrl = new URL(`https://${target}`);
    }

    // Detect cloud provider from headers and DNS
    let detectedProvider = provider;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      const resp = await fetch(targetUrl.toString(), {
        signal: controller.signal,
        headers: { "User-Agent": "OmniSec-Cloud-Scanner/1.0" }
      });
      clearTimeout(timeoutId);
      const respHeaders = Object.fromEntries(resp.headers.entries());
      const bodyText = await resp.text();

      // Detect provider
      const serverHeader = resp.headers.get("server") || "";
      const via = resp.headers.get("via") || "";
      if (serverHeader.includes("AmazonS3") || serverHeader.includes("CloudFront") || respHeaders["x-amz-request-id"]) {
        detectedProvider = "aws";
      } else if (serverHeader.includes("Microsoft") || respHeaders["x-ms-request-id"]) {
        detectedProvider = "azure";
      } else if (serverHeader.includes("GSE") || serverHeader.includes("gws") || via.includes("google")) {
        detectedProvider = "gcp";
      } else if (serverHeader.includes("cloudflare")) {
        detectedProvider = "cloudflare";
      }

      // Check for cloud metadata exposure
      const metadataPaths = [
        "/.env", "/config.json", "/configuration.json",
        "/aws-exports.js", "/amplify-config.json"
      ];

      for (const path of metadataPaths) {
        try {
          const ctrl = new AbortController();
          const tid = setTimeout(() => ctrl.abort(), 3000);
          const metaResp = await fetch(new URL(path, targetUrl.origin).toString(), {
            signal: ctrl.signal,
            redirect: "manual"
          });
          clearTimeout(tid);
          
          if (metaResp.status === 200) {
            const content = await metaResp.text();
            if (content.includes("aws") || content.includes("region") || content.includes("key") || content.includes("secret")) {
              realFindings.push({
                id: `CLOUD-REAL-${realFindings.length + 1}`,
                severity: "critical",
                title: `Cloud Configuration Exposed: ${path}`,
                description: `Cloud configuration file at ${path} is publicly accessible and may contain API keys, region info, or service credentials.`,
                resource: new URL(path, targetUrl.origin).toString(),
                provider: detectedProvider,
                mitreAttack: "T1552.001 - Unsecured Credentials: Credentials In Files",
                remediation: "Remove or restrict access to configuration files. Rotate any exposed credentials immediately.",
                poc: `curl -s "${new URL(path, targetUrl.origin)}"`
              });
            } else {
              await metaResp.text(); // consume body
            }
          } else {
            await metaResp.text();
          }
        } catch { /* ignore */ }
      }

      // Check S3-like bucket patterns
      const s3Patterns = [
        `${target.replace(/\./g, "-")}.s3.amazonaws.com`,
        `s3.amazonaws.com/${target.replace(/\./g, "-")}`,
      ];

      for (const bucket of s3Patterns) {
        try {
          const ctrl = new AbortController();
          const tid = setTimeout(() => ctrl.abort(), 5000);
          const bucketResp = await fetch(`https://${bucket}`, { 
            signal: ctrl.signal,
            redirect: "manual" 
          });
          clearTimeout(tid);
          const bucketBody = await bucketResp.text();

          if (bucketResp.status === 200 && bucketBody.includes("ListBucketResult")) {
            realFindings.push({
              id: `CLOUD-REAL-${realFindings.length + 1}`,
              severity: "critical",
              title: `S3 Bucket Publicly Listable: ${bucket}`,
              description: "An S3 bucket associated with this target allows public listing of objects, potentially exposing sensitive files.",
              resource: `https://${bucket}`,
              provider: "aws",
              mitreAttack: "T1530 - Data from Cloud Storage",
              remediation: "Disable public access on the S3 bucket. Enable S3 Block Public Access settings.",
              poc: `curl -s "https://${bucket}" | head -50`
            });
          }
        } catch { /* ignore */ }
      }

      // Check for server version disclosure (cloud-related)
      if (serverHeader && !serverHeader.match(/^(cloudflare|nginx|apache)$/i)) {
        realFindings.push({
          id: `CLOUD-REAL-${realFindings.length + 1}`,
          severity: "low",
          title: `Cloud Infrastructure Disclosure: Server="${serverHeader}"`,
          description: `The Server header reveals cloud infrastructure details: "${serverHeader}". This helps attackers identify the hosting platform.`,
          resource: targetUrl.toString(),
          provider: detectedProvider,
          remediation: "Remove or obfuscate the Server header to prevent infrastructure fingerprinting.",
          poc: `curl -sI "${targetUrl}" | grep -i server`
        });
      }

      // Check for HTTPS
      if (targetUrl.protocol === "http:") {
        realFindings.push({
          id: `CLOUD-REAL-${realFindings.length + 1}`,
          severity: "high",
          title: "Cloud Service Not Using HTTPS",
          description: "The cloud-hosted service is accessible over HTTP. Data in transit is unencrypted.",
          resource: targetUrl.toString(),
          provider: detectedProvider,
          remediation: "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
          poc: `curl -sI "http://${target}" | head -5`
        });
      }

    } catch (e) {
      console.error("Cloud probing error:", e);
    }

    // AI analysis of detected cloud config
    let aiFindings: CloudFinding[] = [];
    try {
      const systemPrompt = `You are a cloud security expert. Based on the real probe of ${target}, we detected provider: ${detectedProvider}.

We already found ${realFindings.length} real issues. Analyze the target for additional cloud-specific vulnerabilities.

IMPORTANT: Only report findings that are reasonable based on the detected cloud provider (${detectedProvider}) and the target domain. Do NOT fabricate S3 buckets, IAM policies, or specific resource names you haven't verified.

Focus on:
- Common misconfigurations for ${detectedProvider} hosting
- DNS/subdomain takeover risks
- Certificate transparency findings
- CDN/edge security issues

Return JSON: { "findings": [{ "id": "CLOUD-AI-N", "severity": "critical|high|medium|low|info", "title": "string", "description": "string", "resource": "string", "provider": "${detectedProvider}", "remediation": "string", "poc": "string" }] }

Return an EMPTY findings array if you cannot identify genuine issues.`;

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
            { role: "user", content: `Provide cloud security findings for ${target} hosted on ${detectedProvider}. Only evidence-based findings.` }
          ],
          response_format: { type: "json_object" }
        }),
      });

      if (response.ok) {
        const aiResponse = await response.json();
        const content = aiResponse.choices?.[0]?.message?.content || "{}";
        const parsed = JSON.parse(content);
        aiFindings = (parsed.findings || []).map((f: any, idx: number) => ({
          id: f.id || `CLOUD-AI-${idx + 1}`,
          severity: f.severity || "medium",
          title: f.title || "Unknown",
          description: f.description || "",
          resource: f.resource || target,
          provider: detectedProvider,
          mitreAttack: f.mitreAttack || f.mitre_attack,
          remediation: f.remediation || "Review cloud configuration",
          poc: f.poc
        }));
      }
    } catch (e) {
      console.error("AI analysis error:", e);
    }

    const allFindings = [...realFindings, ...aiFindings];
    console.log(`Cloud security scan complete: ${allFindings.length} findings (${realFindings.length} real, ${aiFindings.length} AI)`);

    const summary = {
      critical: allFindings.filter(f => f.severity === "critical").length,
      high: allFindings.filter(f => f.severity === "high").length,
      medium: allFindings.filter(f => f.severity === "medium").length,
      low: allFindings.filter(f => f.severity === "low").length,
      info: allFindings.filter(f => f.severity === "info").length,
    };

    return new Response(JSON.stringify({
      success: true,
      provider: detectedProvider,
      target,
      findings: allFindings,
      summary,
      scanTime: Date.now(),
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("Cloud security scan error:", error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : "Unknown error",
      success: false 
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
