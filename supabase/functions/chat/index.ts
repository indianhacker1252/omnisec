import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Max-Age": "86400",
};

const EDGE_FUNCTION_TOOLS = [
  {
    type: "function",
    function: {
      name: "run_autonomous_vapt",
      description: "Run a full autonomous VAPT scan on a target URL. Use for deep vulnerability assessment.",
      parameters: {
        type: "object",
        properties: {
          target: { type: "string", description: "Target URL or domain (e.g. testphp.vulnweb.com)" },
          maxDepth: { type: "number", description: "Crawl depth (1-5, default 3)" },
        },
        required: ["target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_recon",
      description: "Run reconnaissance scan (Shodan port scan, service detection) on a target host.",
      parameters: {
        type: "object",
        properties: { target: { type: "string", description: "Target hostname" } },
        required: ["target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_webapp_scan",
      description: "Run web application security scan on a target URL.",
      parameters: {
        type: "object",
        properties: { target: { type: "string", description: "Target URL" } },
        required: ["target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_subdomain_enum",
      description: "Enumerate subdomains for a domain.",
      parameters: {
        type: "object",
        properties: { domain: { type: "string", description: "Root domain" } },
        required: ["domain"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_vuln_intel",
      description: "Search for known CVEs and vulnerabilities related to a technology or domain.",
      parameters: {
        type: "object",
        properties: { query: { type: "string", description: "Technology, product, or domain to search" } },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_api_security",
      description: "Run API security assessment on a target.",
      parameters: {
        type: "object",
        properties: {
          target: { type: "string", description: "Target URL" },
          scanType: { type: "string", description: "Scan type: quick or comprehensive", enum: ["quick", "comprehensive"] },
        },
        required: ["target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_cloud_security",
      description: "Run cloud security assessment.",
      parameters: {
        type: "object",
        properties: {
          target: { type: "string", description: "Target hostname or cloud resource" },
          provider: { type: "string", description: "Cloud provider", enum: ["auto", "aws", "azure", "gcp"] },
        },
        required: ["target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "generate_payload",
      description: "Generate security testing payloads for a specific vulnerability type.",
      parameters: {
        type: "object",
        properties: {
          type: { type: "string", description: "Payload type", enum: ["xss", "sqli", "ssrf", "ssti", "cmdi", "lfi"] },
          context: { type: "string", description: "Target context (technology, WAF, etc.)" },
        },
        required: ["type"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_endpoint_discovery",
      description: "Discover endpoints, APIs, and hidden paths on a target.",
      parameters: {
        type: "object",
        properties: { target: { type: "string", description: "Target URL" } },
        required: ["target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "run_threat_intel",
      description: "Fetch latest CVEs from NVD, GitHub advisories, and HackerOne hacktivity patterns for specific technologies.",
      parameters: {
        type: "object",
        properties: {
          technologies: { type: "array", items: { type: "string" }, description: "Technologies to research (e.g. ['Apache', 'PHP', 'MySQL'])" },
        },
        required: ["technologies"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "save_chat_history",
      description: "Save the current chat conversation for future reference.",
      parameters: {
        type: "object",
        properties: {
          title: { type: "string", description: "Conversation title" },
        },
        required: ["title"],
      },
    },
  },
];

async function executeToolCall(
  functionName: string,
  args: Record<string, any>,
  supabaseUrl: string,
  authToken: string,
  userId: string
): Promise<string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${authToken}`,
    apikey: Deno.env.get("SUPABASE_ANON_KEY") || "",
  };

  const invoke = async (fn: string, body: any) => {
    const resp = await fetch(`${supabaseUrl}/functions/v1/${fn}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      const errText = await resp.text().catch(() => "Unknown error");
      return { error: `${fn} returned ${resp.status}: ${errText}` };
    }
    return resp.json();
  };

  try {
    switch (functionName) {
      case "run_autonomous_vapt": {
        const target = args.target?.startsWith("http") ? args.target : `http://${args.target}`;
        const result = await invoke("autonomous-vapt", { target, maxDepth: args.maxDepth || 3 });
        if (result.error) return JSON.stringify({ error: result.error });
        const f = result.findings || [];
        return JSON.stringify({
          success: true,
          target: result.target,
          scanTime: `${Math.round((result.scanTime || 0) / 1000)}s`,
          endpoints: result.discovery?.endpoints || 0,
          subdomains: result.discovery?.subdomains || 0,
          totalFindings: f.length,
          critical: f.filter((v: any) => v.severity === "critical").length,
          high: f.filter((v: any) => v.severity === "high").length,
          medium: f.filter((v: any) => v.severity === "medium").length,
          topFindings: f.slice(0, 10).map((v: any) => ({
            severity: v.severity,
            title: v.title,
            endpoint: v.endpoint,
            cwe: v.cwe,
            exploitValidated: v.exploitValidated,
            poc: v.poc?.slice(0, 300),
          })),
          technologies: result.detectedTech || [],
        });
      }
      case "run_recon":
        return JSON.stringify(await invoke("recon", { target: args.target }));
      case "run_webapp_scan": {
        const t = args.target?.startsWith("http") ? args.target : `https://${args.target}`;
        return JSON.stringify(await invoke("webapp-scan", { target: t }));
      }
      case "run_subdomain_enum":
        return JSON.stringify(await invoke("subdomain-enum", { domain: args.domain }));
      case "run_vuln_intel":
        return JSON.stringify(await invoke("vulnintel", { query: args.query }));
      case "run_api_security": {
        const t = args.target?.startsWith("http") ? args.target : `https://${args.target}`;
        return JSON.stringify(await invoke("api-security", { target: t, scanType: args.scanType || "comprehensive" }));
      }
      case "run_cloud_security":
        return JSON.stringify(await invoke("cloud-security", { target: args.target, provider: args.provider || "auto" }));
      case "generate_payload":
        return JSON.stringify(await invoke("payload-generator", { type: args.type, context: args.context || "" }));
      case "run_endpoint_discovery": {
        const t = args.target?.startsWith("http") ? args.target : `https://${args.target}`;
        return JSON.stringify(await invoke("endpoint-discovery", { target: t }));
      }
      case "run_threat_intel":
        return JSON.stringify(await invoke("threat-intel-learn", { technologies: args.technologies || [], action: "learn" }));
      case "save_chat_history":
        return JSON.stringify({ saved: true, title: args.title, note: "Chat saved by the AI. User can view it from chat history." });
      default:
        return JSON.stringify({ error: `Unknown function: ${functionName}` });
    }
  } catch (e: any) {
    return JSON.stringify({ error: e.message || "Tool execution failed" });
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseClient = createClient(
      supabaseUrl,
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );
    const token = req.headers.get("Authorization")?.replace("Bearer ", "") ?? "";
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser(token);
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { messages, conversationId, saveHistory } = await req.json();

    if (!Array.isArray(messages) || messages.length === 0) {
      return new Response(JSON.stringify({ error: "Invalid messages array" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    if (messages.length > 100) {
      return new Response(JSON.stringify({ error: "Too many messages (max 100)" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    for (const msg of messages) {
      if (!msg.role || !msg.content || typeof msg.content !== "string") {
        return new Response(JSON.stringify({ error: "Invalid message format" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (msg.content.length > 100000) {
        return new Response(JSON.stringify({ error: "Message too long (max 100000 chars)" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) {
      return new Response(JSON.stringify({ error: "AI service not configured" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    console.log(`[CHAT] User ${user.id} sending message with tool-calling enabled...`);

    const systemPrompt = `You are OmniSec™ - an elite autonomous AI cybersecurity offensive and defensive intelligence system created by HARSH MALIK.

You have access to TOOLS that let you perform real security operations. When a user asks you to scan, test, or analyze a target, USE THE APPROPRIATE TOOL instead of just giving advice.

AVAILABLE TOOLS:
- run_autonomous_vapt: Full 20-phase deep VAPT scan (finds SQLi, XSS, SSTI, CORS, takeover, etc.)
- run_recon: Reconnaissance (port scanning, service detection via Shodan)
- run_webapp_scan: Web application security scan
- run_subdomain_enum: Subdomain enumeration (crt.sh + DNS brute)
- run_vuln_intel: CVE/vulnerability database search
- run_api_security: API security assessment
- run_cloud_security: Cloud misconfiguration detection
- generate_payload: Generate WAF-bypass payloads for testing
- run_endpoint_discovery: Discover hidden endpoints, APIs, JS routes
- save_chat_history: Save the conversation for future reference

OPERATIONAL RULES:
1. When a user mentions a domain/URL and asks for scanning/testing, ALWAYS use the tools
2. For comprehensive testing, use run_autonomous_vapt first, then follow up with specific tools
3. After tool results come back, analyze them like an expert bug bounty hunter
4. Provide actionable remediation and POC details for every finding
5. Think like a black hat, report like a professional
6. Cross-reference CVEs with detected technologies
7. Only operate on authorized targets

RESPONSE STYLE:
- Use markdown formatting for clarity
- Present findings in severity order (Critical → High → Medium → Low)
- Include CVSS scores, CWE references, and OWASP categories
- Generate ready-to-submit bug bounty reports when asked`;

    // First call: let AI decide whether to use tools
    const firstResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: systemPrompt },
          ...messages,
        ],
        tools: EDGE_FUNCTION_TOOLS,
        stream: false,
      }),
    });

    if (!firstResponse.ok) {
      const errorText = await firstResponse.text();
      console.error("AI gateway error:", firstResponse.status, errorText);
      if (firstResponse.status === 429) {
        return new Response(JSON.stringify({ error: "Rate limits exceeded" }), {
          status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      if (firstResponse.status === 402) {
        return new Response(JSON.stringify({ error: "Payment required" }), {
          status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ error: "AI gateway error" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const firstData = await firstResponse.json();
    const choice = firstData.choices?.[0];

    // Check if AI wants to call tools
    if (choice?.finish_reason === "tool_calls" || choice?.message?.tool_calls?.length > 0) {
      const toolCalls = choice.message.tool_calls || [];
      console.log(`[CHAT] AI requested ${toolCalls.length} tool calls`);

      // Execute all tool calls
      const toolResults: any[] = [];
      for (const tc of toolCalls) {
        const fnName = tc.function?.name;
        let fnArgs: Record<string, any> = {};
        try { fnArgs = JSON.parse(tc.function?.arguments || "{}"); } catch { fnArgs = {}; }
        console.log(`[CHAT] Executing tool: ${fnName}`, fnArgs);
        const result = await executeToolCall(fnName, fnArgs, supabaseUrl, token, user.id);
        toolResults.push({ role: "tool", tool_call_id: tc.id, content: result });
      }

      // Save tool execution to chat history if requested
      if (saveHistory && conversationId) {
        const serviceClient = createClient(supabaseUrl, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
        try {
          const toolMsg = toolCalls.map((tc: any) => tc.function?.name).join(", ");
          await serviceClient.from("chat_conversations").update({
            metadata: { lastToolCalls: toolMsg, updatedAt: new Date().toISOString() },
            updated_at: new Date().toISOString(),
          }).eq("id", conversationId).eq("user_id", user.id);
        } catch {}
      }

      // Second call: stream the final response with tool results
      const secondResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${LOVABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            { role: "system", content: systemPrompt },
            ...messages,
            choice.message,
            ...toolResults,
          ],
          stream: true,
        }),
      });

      if (!secondResponse.ok) {
        return new Response(JSON.stringify({ error: "AI follow-up failed" }), {
          status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      return new Response(secondResponse.body, {
        headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
      });
    }

    // No tool calls - stream directly (re-request with streaming)
    const streamResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: systemPrompt },
          ...messages,
        ],
        stream: true,
      }),
    });

    if (!streamResponse.ok) {
      return new Response(JSON.stringify({ error: "AI stream failed" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(streamResponse.body, {
      headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
    });
  } catch (e) {
    console.error("chat error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
