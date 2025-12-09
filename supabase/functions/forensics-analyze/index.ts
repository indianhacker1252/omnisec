import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

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

    // Authenticate user
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { action, fileData, fileName, fileType } = await req.json();

    // Check if actual forensic data was provided
    if (fileData) {
      // Real forensic analysis of uploaded file
      const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
      if (!LOVABLE_API_KEY) {
        throw new Error("AI service not configured");
      }

      // Use AI to analyze the forensic data
      const response = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${LOVABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            {
              role: "system",
              content: `You are a digital forensics expert. Analyze the provided data and extract:
- Timestamps and chronology
- Indicators of Compromise (IOCs)
- Suspicious patterns
- File metadata analysis
- Network artifacts
- User activity traces

Return JSON with your findings:
{
  "artifacts": [...],
  "iocs": [...],
  "timeline": [...],
  "suspiciousFindings": [...],
  "recommendations": [...]
}`
            },
            {
              role: "user",
              content: `Analyze this ${fileType || "unknown"} file (${fileName || "unnamed"}):\n\n${fileData.substring(0, 50000)}`
            }
          ],
          temperature: 0.3
        })
      });

      if (!response.ok) {
        throw new Error("AI analysis failed");
      }

      const aiResult = await response.json();
      const content = aiResult.choices?.[0]?.message?.content || "{}";

      let analysisData;
      try {
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        analysisData = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
      } catch {
        analysisData = { rawAnalysis: content };
      }

      // Audit log
      await supabaseClient.from("security_audit_log").insert({
        user_id: user.id,
        action: "forensic_analysis_completed",
        module: "forensics",
        target: fileName || "uploaded_file",
        result: `Analyzed ${fileType || "unknown"} file`
      });

      return new Response(
        JSON.stringify({
          success: true,
          source: "uploaded_file",
          fileName,
          fileType,
          ...analysisData,
          timestamp: new Date().toISOString()
        }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // No file data provided - return instructions
    return new Response(
      JSON.stringify({
        success: false,
        error: "NO_DATA_PROVIDED",
        message: "Forensic analysis requires actual data to analyze",
        instructions: {
          title: "How to Perform Real Forensic Analysis",
          description: "Upload forensic evidence files for analysis",
          supportedFormats: [
            { format: "Memory Dump (.raw, .dmp, .mem)", tools: ["Volatility", "Rekall"] },
            { format: "Disk Image (.dd, .E01, .vmdk)", tools: ["Autopsy", "Sleuth Kit"] },
            { format: "Network Capture (.pcap, .pcapng)", tools: ["Wireshark", "NetworkMiner"] },
            { format: "Log Files (.evtx, .log, .json)", tools: ["LogParser", "ELK Stack"] },
            { format: "Registry Hive (SYSTEM, SAM, SOFTWARE)", tools: ["RegRipper", "Registry Explorer"] },
            { format: "Browser Data (places.sqlite, History)", tools: ["Browser History Viewer"] }
          ],
          steps: [
            "1. Collect forensic evidence using proper chain of custody",
            "2. Create forensic images using dd, FTK Imager, or similar tools",
            "3. Upload the evidence file to OmniSec for AI-powered analysis",
            "4. Review the automated findings and IOCs",
            "5. Export report for incident documentation"
          ],
          collectingEvidence: {
            memory: "Use winpmem, LiME, or DumpIt to capture RAM",
            disk: "Use dd, FTK Imager, or dcfldd for disk imaging",
            network: "Use tcpdump, Wireshark, or network TAP for packet capture",
            logs: "Collect Windows Event Logs, syslog, application logs"
          }
        },
        action,
        timestamp: new Date().toISOString()
      }),
      { 
        status: 400, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
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
