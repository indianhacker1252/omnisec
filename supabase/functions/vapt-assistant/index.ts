import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Max-Age': '86400',
};

interface VAPTRequest {
  prompt: string;
  mode?: 'security' | 'analysis' | 'recon' | 'exploit';
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Initialize Supabase client
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );

    // Authenticate user (VAPT assistant available to all authenticated users)
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { prompt, mode = 'security' }: VAPTRequest = await req.json();
    
    // Input validation
    if (!prompt || typeof prompt !== "string") {
      return new Response(JSON.stringify({ error: "Invalid prompt" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (prompt.length > 10000) {
      return new Response(JSON.stringify({ error: "Prompt too long (max 10000 chars)" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (mode && !['security', 'analysis', 'recon', 'exploit'].includes(mode)) {
      return new Response(JSON.stringify({ error: "Invalid mode" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    console.log(`[VAPT] Processing request - Mode: ${mode}, User: ${user.id}`);

    const lovableApiKey = Deno.env.get('LOVABLE_API_KEY');
    if (!lovableApiKey) {
      throw new Error('LOVABLE_API_KEY not configured');
    }

    // Enhanced system prompts based on the WormGPT logic
    const systemPrompts = {
      security: `You are OmniSec VAPT Assistant, an advanced penetration testing AI with deep knowledge of:
- Network reconnaissance and enumeration
- Vulnerability assessment and exploitation
- Web application security (OWASP Top 10)
- SQL injection, XSS, CSRF, and other attack vectors
- Metasploit, Nmap, SQLMap, Burp Suite, and other security tools
- Post-exploitation and privilege escalation
- Social engineering techniques
- Wireless security and network attacks

When given a command like "scan network [target]" or "find vulnerabilities in [target]":
1. Acknowledge the command
2. Explain what tools would be used (e.g., Nmap for port scanning, Nuclei for vulnerability detection)
3. Provide expected output format
4. Give security recommendations

IMPORTANT: You must respond with actionable intelligence and explain each step of the security assessment process.`,

      analysis: `You are an expert security analyst specializing in:
- CVE database analysis and threat intelligence
- Risk assessment and CVSS scoring
- Security incident investigation
- Malware analysis and reverse engineering
- Log analysis and forensic investigation
- Compliance frameworks (ISO 27001, GDPR, SOC 2, PCI DSS)

Analyze security data with precision and provide comprehensive reports.`,

      recon: `You are a reconnaissance specialist expert in:
- OSINT (Open Source Intelligence) gathering
- Domain and subdomain enumeration
- Port scanning and service detection
- DNS reconnaissance and zone transfers
- Social media and digital footprint analysis
- Shodan and Censys database queries
- Network mapping and topology discovery

Provide detailed reconnaissance reports with actionable intelligence.`,

      exploit: `You are a penetration testing expert specializing in:
- Exploit development and weaponization
- Buffer overflows and memory corruption
- Privilege escalation techniques
- Payload generation and obfuscation
- C2 (Command & Control) operations
- Active Directory exploitation
- Web shell deployment and persistence

CRITICAL: Only provide exploit guidance for authorized penetration testing. Always emphasize legal and ethical boundaries.`
    };

    const systemPrompt = systemPrompts[mode] || systemPrompts.security;

    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${lovableApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: prompt }
        ],
        temperature: 0.7,
        max_tokens: 4000,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('[VAPT] AI Gateway error:', response.status, errorText);
      
      if (response.status === 429) {
        return new Response(JSON.stringify({ 
          error: 'Rate limit exceeded. Please try again later.',
          type: 'rate_limit' 
        }), {
          status: 429,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      
      if (response.status === 402) {
        return new Response(JSON.stringify({ 
          error: 'AI credits exhausted. Please add funds to continue.',
          type: 'payment_required' 
        }), {
          status: 402,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      
      throw new Error(`AI Gateway error: ${response.status}`);
    }

    const data = await response.json();
    const answer = data.choices?.[0]?.message?.content || 'No response generated';

    console.log('[VAPT] Response generated successfully');

    // Audit log
    await supabaseClient.from("security_audit_log").insert({
      user_id: user.id,
      action: "vapt_assistant_query",
      resource_type: "ai_assistant",
      resource_id: mode,
      details: {
        mode: mode,
        prompt_preview: prompt.substring(0, 200),
        response_length: answer.length,
        timestamp: new Date().toISOString()
      },
      ip_address: req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || "unknown"
    });

    return new Response(JSON.stringify({ 
      answer,
      mode,
      timestamp: new Date().toISOString()
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('[VAPT] Error:', error);
    return new Response(JSON.stringify({ 
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      type: 'server_error'
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
