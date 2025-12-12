import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { text, action } = await req.json();
    
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      console.error("LOVABLE_API_KEY not configured");
      return new Response(JSON.stringify({ error: "AI service not configured" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    console.log(`Voice assistant request: action=${action}, text=${text?.substring(0, 50)}...`);

    // Call Lovable AI for response
    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { 
            role: "system", 
            content: `You are OmniSec Jarvis, an elite voice-activated cybersecurity AI assistant. You specialize in:

🔒 SECURITY DOMAINS:
- Network security and penetration testing (OSCP, OSCE level)
- Vulnerability assessment and exploitation guidance
- Security tool usage (Nmap, Metasploit, Burp Suite, ZAP)
- Threat analysis and incident response
- OWASP Top 10 vulnerabilities
- Web application security testing
- Wireless security (WiFi, Bluetooth)
- Forensics and malware analysis

🎯 VOICE INTERACTION STYLE:
- Keep responses concise (2-3 sentences for simple queries)
- Use technical but clear language
- Provide actionable steps when asked for procedures
- Always emphasize AUTHORIZED TESTING ONLY
- Be helpful but never provide illegal guidance

When the user asks to scan or analyze something, provide the methodology and tool recommendations.
When asked for commands, provide the actual syntax with explanations.

Remember: You're a voice assistant, so responses should be speakable - avoid excessive formatting.` 
          },
          { role: "user", content: text }
        ],
        max_tokens: 500,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("AI gateway error:", response.status, errorText);
      
      if (response.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limited. Please try again in a moment." }), {
          status: 429,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      
      return new Response(JSON.stringify({ error: "AI service temporarily unavailable" }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const data = await response.json();
    const assistantResponse = data.choices?.[0]?.message?.content || "I couldn't process that request.";

    console.log("Voice assistant response generated successfully");

    return new Response(JSON.stringify({ 
      response: assistantResponse,
      success: true 
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (e) {
    console.error("Voice assistant error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});