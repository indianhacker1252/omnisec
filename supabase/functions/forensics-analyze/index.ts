import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, fileData, fileName, fileType } = await req.json();

    console.log("Forensics request:", action, fileName);

    // Check if actual forensic data was provided
    if (fileData && fileData.length > 0) {
      // Real forensic analysis of uploaded file
      const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
      if (!LOVABLE_API_KEY) {
        throw new Error("AI service not configured");
      }

      console.log(`Analyzing file: ${fileName} (${fileType}), size: ${fileData.length} chars`);

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
- Timestamps and chronology of events
- Indicators of Compromise (IOCs) - IP addresses, domains, file hashes, etc.
- Suspicious patterns and anomalies
- File metadata and structure analysis
- Network artifacts and connections
- User activity traces and behavior patterns
- Potential attack vectors and techniques used

Return a detailed JSON analysis:
{
  "summary": "Brief summary of findings",
  "artifacts": [{"type": "...", "value": "...", "description": "...", "severity": "critical|high|medium|low|info"}],
  "iocs": [{"type": "ip|domain|hash|email|url", "value": "...", "confidence": "high|medium|low"}],
  "timeline": [{"timestamp": "...", "event": "...", "significance": "..."}],
  "suspiciousFindings": [{"title": "...", "description": "...", "severity": "critical|high|medium|low"}],
  "techniques": [{"mitre_id": "T####", "name": "...", "evidence": "..."}],
  "recommendations": ["..."]
}`
            },
            {
              role: "user",
              content: `Analyze this ${fileType || "unknown"} file named "${fileName || "unnamed"}":\n\n${fileData.substring(0, 100000)}`
            }
          ],
          temperature: 0.2
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error("AI analysis failed:", errorText);
        throw new Error("AI analysis failed");
      }

      const aiResult = await response.json();
      const content = aiResult.choices?.[0]?.message?.content || "{}";

      let analysisData;
      try {
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        analysisData = jsonMatch ? JSON.parse(jsonMatch[0]) : { rawAnalysis: content };
      } catch {
        analysisData = { rawAnalysis: content };
      }

      console.log("Analysis complete for:", fileName);

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

    // No file data provided - return instructions for real forensic analysis
    return new Response(
      JSON.stringify({
        success: false,
        error: "NO_DATA_PROVIDED",
        message: "Forensic analysis requires actual evidence data to analyze",
        instructions: {
          title: "Digital Forensics Evidence Collection Guide",
          description: "Upload forensic evidence files for AI-powered analysis. OmniSec can analyze various forensic artifacts.",
          supportedFormats: [
            { 
              format: "Memory Dump", 
              extensions: [".raw", ".dmp", ".mem", ".lime"],
              tools: ["Volatility 3", "Rekall", "WinPmem", "LiME"],
              command: "winpmem_mini_x64.exe memory.raw"
            },
            { 
              format: "Disk Image", 
              extensions: [".dd", ".E01", ".vmdk", ".raw"],
              tools: ["Autopsy", "Sleuth Kit", "FTK Imager"],
              command: "dd if=/dev/sda of=disk.dd bs=4M"
            },
            { 
              format: "Network Capture", 
              extensions: [".pcap", ".pcapng", ".cap"],
              tools: ["Wireshark", "tcpdump", "NetworkMiner"],
              command: "tcpdump -i eth0 -w capture.pcap"
            },
            { 
              format: "Windows Event Logs", 
              extensions: [".evtx"],
              tools: ["Event Viewer", "LogParser", "EvtxExplorer"],
              location: "C:\\Windows\\System32\\winevt\\Logs\\"
            },
            { 
              format: "Linux Logs", 
              extensions: [".log"],
              tools: ["journalctl", "cat", "less"],
              location: "/var/log/"
            },
            { 
              format: "Registry Hives", 
              extensions: ["SYSTEM", "SAM", "SOFTWARE", "NTUSER.DAT"],
              tools: ["RegRipper", "Registry Explorer", "RECmd"],
              location: "C:\\Windows\\System32\\config\\"
            },
            { 
              format: "Browser Artifacts", 
              extensions: [".sqlite", "History", "Cookies"],
              tools: ["Browser History Viewer", "Hindsight", "KAPE"],
              location: "Browser profile directories"
            },
            {
              format: "JSON/Text Logs",
              extensions: [".json", ".log", ".txt", ".csv"],
              tools: ["jq", "grep", "ELK Stack"],
              command: "cat application.log | jq '.'"
            }
          ],
          evidenceCollection: {
            memory: {
              windows: "winpmem_mini_x64.exe memory.raw",
              linux: "sudo ./lime.ko path=/tmp/memory.lime format=lime",
              macos: "sudo osxpmem -o memory.raw"
            },
            disk: {
              linux: "sudo dd if=/dev/sda of=/path/to/image.dd bs=4M status=progress",
              windows: "FTK Imager or dd for Windows",
              note: "Always use write-blockers for physical media"
            },
            network: {
              live: "tcpdump -i any -w capture.pcap",
              rotate: "tcpdump -i any -w capture_%Y%m%d_%H%M%S.pcap -G 3600"
            }
          },
          bestPractices: [
            "Maintain chain of custody documentation",
            "Create verified forensic images (hash verification)",
            "Work only on copies, never original evidence",
            "Document all actions and timestamps",
            "Use write-blockers when accessing storage media"
          ]
        },
        timestamp: new Date().toISOString()
      }),
      { 
        status: 200, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  } catch (error: unknown) {
    console.error("Forensics error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: errorMessage, success: false }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
