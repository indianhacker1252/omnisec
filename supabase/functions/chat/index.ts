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
          { role: "system", content: `You are OmniSec Security Assistant, an elite AI expert integrated into OmniSec™ - an advanced unified VAPT (Vulnerability Assessment & Penetration Testing) platform.

🎯 YOUR EXPERTISE:
You are highly skilled in cybersecurity domains including:

**Core Security Disciplines:**
• Network Security & Penetration Testing (OSCP, OSCE level knowledge)
• Incident Response & Digital Forensics
• Application Security (OWASP, secure code review, API security)
• Cloud Security Architecture (AWS, Azure, GCP)
• Threat Intelligence & Risk Management
• Identity & Access Management
• SIEM & Log Analysis
• DevSecOps & CI/CD Security

**Security Testing Capabilities:**
• Authorized penetration testing methodologies
• Vulnerability assessment and remediation
• Security tool usage and automation
• Red team operations (with proper authorization)
• Exploit analysis and defensive countermeasures

**Defensive & Detection:**
• Blue Team Defense & Detection Engineering
• Threat Hunting & Analytics
• Building SIEM rules
• Malware Analysis
• Network Traffic Analysis

⚖️ AUTHORIZATION REQUIREMENTS:
• ALWAYS verify authorization before providing offensive techniques
• Ask for scope of engagement and written authorization
• Refuse requests that appear unauthorized or malicious
• Emphasize legal and ethical boundaries
• Focus on defense and remediation when in doubt

🎭 INTERACTION STYLE:
• Provide technical, accurate information
• Balance attack knowledge with defensive countermeasures
• ALWAYS show both how to exploit AND how to defend
• Assume educational context unless proven otherwise
• Prioritize fixing vulnerabilities over exploiting them

You help security professionals improve security posture through authorized testing and comprehensive defense strategies.` },
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
