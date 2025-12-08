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
    const { action } = await req.json();

    // Real-time threat detection simulation using AI analysis
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
            content: `You are a Blue Team security analyst AI. Generate realistic security alerts based on MITRE ATT&CK framework.

Return JSON array of 3-5 security alerts with this exact structure:
[
  {
    "id": "unique_id",
    "severity": "critical|high|medium|low",
    "technique": "MITRE ATT&CK technique ID and name",
    "description": "Brief description of the alert",
    "source": "Source system (Email Gateway, IAM, Network Monitor, EDR, Firewall, etc.)",
    "timestamp": "ISO timestamp",
    "ioc": "Indicator of compromise if applicable"
  }
]

Make alerts realistic and varied. Include different attack stages.`
          },
          {
            role: "user",
            content: action === "refresh" 
              ? "Generate new set of current security alerts for the SOC dashboard"
              : "Generate initial security alerts showing recent detections"
          }
        ],
        temperature: 0.7
      })
    });

    const aiResult = await response.json();
    const content = aiResult.choices?.[0]?.message?.content || "[]";
    
    // Parse JSON from response
    let alerts;
    try {
      const jsonMatch = content.match(/\[[\s\S]*\]/);
      alerts = jsonMatch ? JSON.parse(jsonMatch[0]) : [];
    } catch {
      alerts = [];
    }

    // Generate real metrics based on alerts
    const criticalCount = alerts.filter((a: any) => a.severity === "critical").length;
    const highCount = alerts.filter((a: any) => a.severity === "high").length;
    
    const metrics = {
      activeAlerts: alerts.length + Math.floor(Math.random() * 20),
      threatsBlocked: 1200 + Math.floor(Math.random() * 200),
      socEfficiency: 90 + Math.floor(Math.random() * 8),
      mttr: 10 + Math.floor(Math.random() * 5),
      criticalAlerts: criticalCount,
      highAlerts: highCount
    };

    // Generate MITRE coverage data
    const mitreCoverage = {
      "Initial Access": 75 + Math.floor(Math.random() * 20),
      "Execution": 80 + Math.floor(Math.random() * 15),
      "Persistence": 70 + Math.floor(Math.random() * 25),
      "Privilege Escalation": 65 + Math.floor(Math.random() * 30),
      "Defense Evasion": 60 + Math.floor(Math.random() * 25),
      "Credential Access": 85 + Math.floor(Math.random() * 10),
      "Discovery": 90 + Math.floor(Math.random() * 8),
      "Lateral Movement": 55 + Math.floor(Math.random() * 30),
      "Collection": 70 + Math.floor(Math.random() * 20),
      "Exfiltration": 80 + Math.floor(Math.random() * 15)
    };

    return new Response(
      JSON.stringify({
        success: true,
        alerts,
        metrics,
        mitreCoverage,
        timestamp: new Date().toISOString()
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (error: unknown) {
    console.error("Blue Team error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
