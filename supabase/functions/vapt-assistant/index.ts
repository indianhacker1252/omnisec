import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
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
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );

    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { prompt, mode = 'security' }: VAPTRequest = await req.json();
    
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

    console.log(`[VAPT] Processing request - Mode: ${mode}, User: ${user.id}`);

    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
    if (!LOVABLE_API_KEY) {
      return new Response(JSON.stringify({ 
        error: 'AI service not configured',
        answer: 'VAPT Assistant is not configured. Please contact support.'
      }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const systemPrompts: Record<string, string> = {
      security: `You are OmniSec VAPT Assistant, an advanced penetration testing AI. Provide detailed, actionable security assessments with:
- Specific vulnerability details and CVE references when applicable
- Proof-of-concept commands and tool usage (Nmap, Burp, SQLMap, etc.)
- Remediation recommendations with code examples
- CVSS scoring when applicable
- Step-by-step attack methodology

Always provide REAL, ACTIONABLE guidance for AUTHORIZED testing only.`,

      analysis: `You are an expert security analyst. Provide comprehensive threat analysis with:
- CVE database references and exploit availability
- Risk assessment with CVSS scoring  
- Detailed technical analysis
- Specific mitigation strategies
- MITRE ATT&CK framework mapping`,

      recon: `You are a reconnaissance specialist. Provide detailed OSINT and reconnaissance guidance including:
- Specific tool commands (nmap, amass, subfinder, theHarvester, etc.)
- Expected output analysis and interpretation
- Target profiling methodology
- Attack surface mapping techniques
- Passive vs active reconnaissance approaches`,

      exploit: `You are a penetration testing expert. Provide exploitation guidance for AUTHORIZED testing only:
- Exploit selection based on target vulnerabilities
- Payload generation and customization approaches
- Post-exploitation techniques and persistence
- Detailed technical procedures with commands
- Evasion techniques for security controls

CRITICAL: Only for authorized penetration testing with proper scope.`
    };

    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: systemPrompts[mode] || systemPrompts.security },
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
          error: 'Rate limit exceeded',
          answer: 'Too many requests. Please wait a moment and try again.'
        }), {
          status: 200,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
      
      return new Response(JSON.stringify({ 
        error: 'AI service error',
        answer: 'I encountered an error processing your request. Please try again.'
      }), {
        status: 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const data = await response.json();
    const answer = data.choices?.[0]?.message?.content || 'No response generated';

    console.log('[VAPT] Response generated successfully');

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
      error: error instanceof Error ? error.message : 'Unknown error',
      answer: "I encountered an error processing your request. Please try again."
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});