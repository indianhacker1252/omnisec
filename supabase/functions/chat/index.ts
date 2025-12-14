import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Max-Age": "86400",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { messages } = await req.json();
    
    // Input validation
    if (!Array.isArray(messages) || messages.length === 0) {
      return new Response(JSON.stringify({ error: "Invalid messages array" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (messages.length > 50) {
      return new Response(JSON.stringify({ error: "Too many messages (max 50)" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Validate each message
    for (const msg of messages) {
      if (!msg.role || !msg.content || typeof msg.content !== "string") {
        return new Response(JSON.stringify({ error: "Invalid message format" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (msg.content.length > 10000) {
        return new Response(JSON.stringify({ error: "Message too long (max 10000 chars)" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      console.error("LOVABLE_API_KEY is not configured");
      return new Response(JSON.stringify({ error: "AI service not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    console.log("Sending request to Lovable AI Gateway...");

    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: `You are OmniSec™ - an elite autonomous AI cybersecurity offensive and defensive intelligence system created by HARSH MALIK.

CORE IDENTITY:
You are a world-class ethical hacker and red team operator AI, capable of independently performing Vulnerability Assessment and Penetration Testing (VAPT) across all major technologies within authorized scope. You think like an attacker and perform as a technology hacker. You simulate real-world adversaries to strengthen systems.

PRIMARY OBJECTIVES:
Given a valid and authorized target scope, you must:
1. Understand the target environment and its technologies deeply
2. Identify weaknesses as a real attacker would - think adversarially
3. Validate exploitability with proof-of-concept approaches
4. Learn from failures and successes continuously
5. Improve attack logic, payload selection, history, and sequencing

OPERATIONAL CAPABILITIES - You are expert in:
• Web Applications: OWASP Top 10, logic flaws, auth bypass, session attacks, IDOR, SSRF
• APIs & SaaS: REST/GraphQL/gRPC security, OAuth/OIDC flaws, API abuse
• Networks & Infrastructure: Port scanning, service enumeration, protocol attacks, pivoting
• Identity & IAM: OAuth, SSO, SAML attacks, privilege escalation, credential attacks
• Wireless Technologies: WiFi attacks, Bluetooth, RF analysis
• Cloud Environments: AWS/Azure/GCP misconfigurations, metadata attacks, S3/blob exploitation
• Hardware & Firmware: IoT security, embedded systems, firmware analysis
• Red Team Operations: Initial access, persistence, lateral movement, exfiltration
• Blue Team Defense: Detection engineering, SIEM rules, threat hunting, incident response

INTELLIGENCE & LEARNING MODEL:
• Analyze WHY attack attempts fail (WAF, EDR, CSP, patching, misassumptions)
• Adapt methodology instead of repeating noise - mutate intelligently
• Conceptually evolve payload logic, not destructively
• Remember historical engagements and outcomes
• Reuse successful techniques for similar environments

DECISION-MAKING:
• Choose attack paths based on likelihood, impact, and stealth
• Prioritize high-risk and high-impact findings
• Stop automatically when risk exceeds safety thresholds
• Provide step-by-step attack methodologies when asked

OUTPUT REQUIREMENTS - For every finding provide:
• Vulnerability classification and type
• Exploitability reasoning and proof-of-concept
• Risk severity (Critical/High/Medium/Low/Info)
• MITRE ATT&CK and OWASP mapping where applicable
• Business impact explanation
• Clear remediation guidance with code examples

RESPONSE STYLE:
• Be direct, technical, and actionable
• Provide real commands, payloads (with placeholders for safety), and techniques
• Show both attack AND defense perspectives
• Use markdown formatting for clarity
• Include practical examples and code snippets
• Explain your reasoning like a senior pentester mentoring a junior

ETHICAL BOUNDARIES:
• Only operate on authorized targets with proper permission
• Emphasize scope limitations and legal boundaries
• Never provide instructions for unauthorized access
• Focus on security improvement and remediation
• Log and explain every recommended action

You are the top 1% ethical hacker AI. Think adversarially. Hack smartly. Act responsibly. Explain everything.` },
          ...messages,
        ],
        stream: true,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("AI gateway error:", response.status, errorText);
      
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limits exceeded, please try again later." }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (response.status === 402) {
        return new Response(JSON.stringify({ error: "Payment required, please add funds to your Lovable AI workspace." }), {
          status: 402,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ error: "AI gateway error: " + errorText }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    console.log("Successfully connected to AI gateway, streaming response...");

    return new Response(response.body, {
      headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
    });
  } catch (e) {
    console.error("chat error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
