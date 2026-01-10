import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

async function callAI(systemPrompt: string, userMessage: string, apiKey: string): Promise<string> {
  const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "google/gemini-3-flash-preview",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userMessage },
      ],
      temperature: 0.3,
    }),
  });

  if (!response.ok) {
    throw new Error(`AI API error: ${response.status}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || "";
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      throw new Error("LOVABLE_API_KEY not configured");
    }

    const { action, fileData, fileName, fileType, hexDump, strings, imports } = await req.json();

    if (action === "analyze_binary") {
      // AI-powered binary analysis
      const systemPrompt = `You are an expert reverse engineer and malware analyst. Analyze binary data and provide security insights.

Your analysis should include:
1. File type identification and structure analysis
2. Suspicious patterns and behaviors
3. Potential malware indicators (IOCs)
4. Function purpose identification
5. Security recommendations

Format your response as JSON with the following structure:
{
  "file_type": "PE/ELF/Mach-O/etc",
  "architecture": "x86/x64/ARM/etc",
  "suspicious_indicators": [{"type": "string", "description": "string", "severity": "low/medium/high/critical"}],
  "functions": [{"name": "string", "purpose": "string", "risk_level": "safe/suspicious/malicious"}],
  "strings_analysis": [{"string": "string", "type": "url/ip/command/registry/file", "risk": "string"}],
  "imports_analysis": [{"dll": "string", "functions": ["string"], "purpose": "string", "risk_level": "string"}],
  "behavioral_indicators": ["string"],
  "recommendations": ["string"],
  "malware_family": "string or null",
  "confidence_score": 0-100,
  "summary": "string"
}`;

      const userMessage = `Analyze this binary data:
File Name: ${fileName || 'unknown'}
File Type: ${fileType || 'unknown'}
${hexDump ? `Hex Dump (first 1024 bytes):\n${hexDump}` : ''}
${strings ? `Extracted Strings:\n${JSON.stringify(strings)}` : ''}
${imports ? `Import Table:\n${JSON.stringify(imports)}` : ''}
${fileData ? `Base64 Data (first 4KB): ${fileData.substring(0, 5460)}` : ''}

Provide a comprehensive security analysis.`;

      const analysisText = await callAI(systemPrompt, userMessage, LOVABLE_API_KEY);
      
      // Parse the AI response
      let analysis;
      try {
        const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          analysis = JSON.parse(jsonMatch[0]);
        } else {
          throw new Error("No JSON found");
        }
      } catch {
        // Fallback structured response
        analysis = {
          file_type: fileType || "Unknown",
          architecture: "Unknown",
          suspicious_indicators: [],
          functions: [],
          strings_analysis: [],
          imports_analysis: [],
          behavioral_indicators: [],
          recommendations: ["Upload actual binary for detailed analysis"],
          malware_family: null,
          confidence_score: 0,
          summary: analysisText
        };
      }

      return new Response(JSON.stringify({
        success: true,
        analysis,
        timestamp: new Date().toISOString()
      }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "analyze_strings") {
      const systemPrompt = `You are an expert malware analyst specializing in string analysis. Analyze extracted strings from a binary and identify:
1. Command and control (C2) indicators
2. File paths and registry keys
3. Network indicators (URLs, IPs, domains)
4. Encryption/encoding patterns
5. Anti-analysis techniques
6. Suspicious commands or scripts

Provide JSON response:
{
  "categorized_strings": {
    "network": [{"value": "string", "type": "url/ip/domain", "risk": "low/medium/high"}],
    "commands": [{"value": "string", "purpose": "string", "risk": "low/medium/high"}],
    "registry": [{"value": "string", "purpose": "string", "risk": "low/medium/high"}],
    "files": [{"value": "string", "purpose": "string", "risk": "low/medium/high"}],
    "crypto": [{"value": "string", "type": "string"}],
    "other": [{"value": "string", "notes": "string"}]
  },
  "iocs": [{"type": "string", "value": "string", "confidence": "high/medium/low"}],
  "summary": "string",
  "threat_level": "low/medium/high/critical"
}`;

      const analysisText = await callAI(systemPrompt, `Analyze these strings extracted from a binary:\n${JSON.stringify(strings)}`, LOVABLE_API_KEY);
      
      let result;
      try {
        const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
        result = jsonMatch ? JSON.parse(jsonMatch[0]) : { summary: analysisText };
      } catch {
        result = { summary: analysisText };
      }

      return new Response(JSON.stringify({ success: true, ...result }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "analyze_imports") {
      const systemPrompt = `You are an expert Windows API analyst. Analyze the import table of a PE binary and identify:
1. Suspicious API combinations
2. Code injection techniques
3. Anti-debugging methods
4. Process manipulation
5. Network capabilities
6. Persistence mechanisms
7. Evasion techniques

Provide JSON response:
{
  "capabilities": [{"name": "string", "description": "string", "apis_used": ["string"], "risk_level": "low/medium/high/critical"}],
  "suspicious_patterns": [{"pattern": "string", "description": "string", "confidence": "high/medium/low"}],
  "behavior_prediction": ["string"],
  "risk_score": 0-100,
  "summary": "string"
}`;

      const analysisText = await callAI(systemPrompt, `Analyze this import table:\n${JSON.stringify(imports)}`, LOVABLE_API_KEY);
      
      let result;
      try {
        const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
        result = jsonMatch ? JSON.parse(jsonMatch[0]) : { summary: analysisText };
      } catch {
        result = { summary: analysisText };
      }

      return new Response(JSON.stringify({ success: true, ...result }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    if (action === "decompile_function") {
      const systemPrompt = `You are an expert reverse engineer. Analyze this disassembly and provide:
1. High-level pseudocode reconstruction
2. Function purpose identification
3. Security implications
4. Potential vulnerabilities
5. Behavioral analysis

Respond with JSON:
{
  "pseudocode": "string (C-like pseudocode)",
  "purpose": "string",
  "security_implications": ["string"],
  "vulnerabilities": [{"type": "string", "description": "string", "severity": "string"}],
  "behavior": ["string"],
  "calls_analysis": [{"function": "string", "purpose": "string"}],
  "summary": "string"
}`;

      const analysisText = await callAI(systemPrompt, `Analyze and decompile this assembly:\n${hexDump || fileData}`, LOVABLE_API_KEY);
      
      let result;
      try {
        const jsonMatch = analysisText.match(/\{[\s\S]*\}/);
        result = jsonMatch ? JSON.parse(jsonMatch[0]) : { summary: analysisText };
      } catch {
        result = { summary: analysisText };
      }

      return new Response(JSON.stringify({ success: true, ...result }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Default: return capabilities
    return new Response(JSON.stringify({
      success: true,
      actions: ["analyze_binary", "analyze_strings", "analyze_imports", "decompile_function"],
      description: "AI-powered reverse engineering analysis"
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (error) {
    console.error("Reverse engineering error:", error);
    return new Response(JSON.stringify({
      success: false,
      error: error instanceof Error ? error.message : "Unknown error"
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
