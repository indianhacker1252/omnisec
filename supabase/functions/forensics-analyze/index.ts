import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import "https://deno.land/x/xhr@0.1.0/mod.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, target } = await req.json();

    // AI-powered forensic analysis
    const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          {
            role: "system",
            content: `You are a digital forensics expert AI. Generate realistic forensic analysis data.

Based on the action, return appropriate JSON:

For "artifacts" action:
{
  "artifacts": [
    {
      "type": "Registry|File System|Network|Memory|Browser|Event Log",
      "location": "Specific path or location",
      "timestamp": "ISO timestamp",
      "significance": "Brief significance (Persistence Mechanism, Malicious Executable, C2 Communication, etc.)",
      "md5": "MD5 hash if applicable",
      "details": "Additional details"
    }
  ]
}

For "memory" action:
{
  "memoryAnalysis": {
    "processes": number,
    "networkConnections": number,
    "suspiciousDlls": number,
    "handles": number,
    "registryKeys": number,
    "codeInjections": number,
    "suspiciousProcesses": [
      {
        "name": "process name",
        "pid": number,
        "threat": "description of threat"
      }
    ]
  }
}

For "disk" action:
{
  "diskAnalysis": {
    "deletedFiles": number,
    "hiddenPartitions": number,
    "recoveredFiles": [
      {
        "name": "filename",
        "path": "original path",
        "deleted_at": "timestamp",
        "type": "file type"
      }
    ]
  }
}

Generate realistic forensic data that would be found during an incident investigation.`
          },
          {
            role: "user",
            content: `Perform ${action} forensic analysis${target ? ` on ${target}` : ''}`
          }
        ],
        temperature: 0.7
      })
    });

    const aiResult = await response.json();
    const content = aiResult.choices?.[0]?.message?.content || "{}";
    
    // Parse JSON from response
    let analysisData;
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      analysisData = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
    } catch {
      analysisData = {};
    }

    return new Response(
      JSON.stringify({
        success: true,
        action,
        ...analysisData,
        timestamp: new Date().toISOString()
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (error: unknown) {
    console.error("Forensics error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
