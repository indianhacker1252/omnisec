// OmniSec™ © HARSH MALIK
// vapt-planner — agentic VAPT orchestrator. Uses Lovable AI (Gemini 2.5 Pro)
// with tool-calling to plan & enqueue detector jobs based on live recon/state.
//
// Tools exposed to the LLM:
//   queue_recon(target)                       -> enqueue subdomain/tech recon
//   queue_detector(name, params)              -> enqueue any detector
//   query_findings(scan_id, severity?)        -> read current findings
//   query_jobs(scan_id)                       -> read job statuses
//   note(text)                                -> log a rationale line
//   finalize(summary)                         -> mark scan complete
//
// The planner is invoked once when a scan starts; it loops up to 20 steps,
// adapting its plan based on observed results. Workers consume the jobs.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPA_URL = Deno.env.get("SUPABASE_URL")!;
const SRV_KEY  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const LOVABLE  = Deno.env.get("LOVABLE_API_KEY")!;

const SYSTEM_PROMPT = `You are OmniSec's autonomous VAPT planner — designed to outperform XBOW.
Goal: discover the maximum number of HIGH/CRITICAL vulnerabilities on the target while
staying lawful (scope already validated). You reason step-by-step.

Mandatory workflow:
1. queue_recon first to map subdomains, tech stack, endpoints, WAF.
2. Call query_context to load the latest target_context for this scan (tech, waf, frameworks).
3. Call query_kg with a detected tech (e.g. "php","aspnet","wordpress","graphql") to see which
   detector+payload classes have historically succeeded on similar stacks — bias toward those.
4. Queue detectors covering OWASP A01-A10 in priority order:
   - A01 BOLA/IDOR/auth → vapt-bopla, vapt-advanced
   - A02 Crypto/JWT     → vapt-chains (jwtAttacks)
   - A03 Injection      → autonomous-vapt, vapt-chains
   - A04 Insecure design→ vapt-advanced
   - A05 Misconfig      → autonomous-vapt
   - A06 Vuln deps      → vapt-intel
   - A07 Auth fail      → vapt-oauth
   - A08 Integrity      → vapt-chains (cicdWebhook, samlXsw)
   - A09 Logging        → autonomous-vapt
   - A10 SSRF           → vapt-chains (redirectSsrfChain, pdfEngineSsrf)
5. After each batch, call query_findings + query_jobs. For every HIGH or CRITICAL finding,
   call queue_detector with name="verify-finding" and params={action:"generate_script", finding:<finding>}
   to trigger dual-confirmation.
6. If specific tech is detected, queue its specialized scanner (GraphQL → vapt-graphql,
   OAuth → vapt-oauth, SAML → vapt-chains samlXsw, WordPress/PHP → vapt-intel).
7. When you've covered all A01-A10 OR queued >=18 detectors → call finalize.

Be decisive. Don't repeat queued detectors. Use note() to record reasoning.`;

const TOOLS = [
  {
    type: "function",
    function: {
      name: "queue_recon",
      description: "Enqueue subdomain enumeration & tech fingerprinting for the target.",
      parameters: {
        type: "object",
        properties: { target: { type: "string" } },
        required: ["target"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "queue_detector",
      description: "Enqueue any detector edge function (autonomous-vapt, vapt-advanced, vapt-intel, vapt-graphql, vapt-oauth, vapt-bopla, vapt-portscan, vapt-waf-bypass, vapt-chains).",
      parameters: {
        type: "object",
        properties: {
          name: { type: "string" },
          params: { type: "object", description: "Extra params merged into the body." },
          priority: { type: "number", description: "Lower = sooner. Default 100." },
        },
        required: ["name"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "query_findings",
      description: "Read findings emitted so far for this scan.",
      parameters: { type: "object", properties: { severity: { type: "string" } } },
    },
  },
  {
    type: "function",
    function: {
      name: "query_jobs",
      description: "Read scan_jobs statuses for this scan.",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function",
    function: {
      name: "note",
      description: "Record a short reasoning note (shown in PlannerThoughts UI).",
      parameters: {
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "finalize",
      description: "Mark planning complete. Workers will continue executing queued jobs.",
      parameters: {
        type: "object",
        properties: { summary: { type: "string" } },
        required: ["summary"],
      },
    },
  },
];

async function llm(messages: any[]) {
  const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${LOVABLE}`,
    },
    body: JSON.stringify({
      model: "google/gemini-2.5-pro",
      messages,
      tools: TOOLS,
      tool_choice: "auto",
    }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`LLM ${r.status}: ${t.slice(0, 200)}`);
  }
  return r.json();
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  try {
    const { scanId, target, userId } = await req.json();
    if (!scanId || !target) {
      return new Response(JSON.stringify({ error: "scanId+target required" }), {
        status: 400, headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    const supa = createClient(SUPA_URL, SRV_KEY);
    let step = 0;

    const logDecision = async (decision: string, rationale: string, tool_call?: any, tool_result?: any) => {
      await supa.from("planner_decisions").insert({
        scan_id: scanId, user_id: userId, step, decision, rationale, tool_call, tool_result,
      });
    };

    const enqueue = async (detector: string, params: any = {}, priority = 100) => {
      const { data, error } = await supa.from("scan_jobs").insert({
        scan_id: scanId, user_id: userId, detector, target, params, priority,
      }).select().single();
      if (error) throw error;
      return data;
    };

    const messages: any[] = [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `Target: ${target}\nScan ID: ${scanId}\nPlan and queue the attack now.` },
    ];

    let finalized = false;
    const MAX_STEPS = 20;

    while (step < MAX_STEPS && !finalized) {
      step++;
      const resp = await llm(messages);
      const msg = resp?.choices?.[0]?.message;
      if (!msg) break;
      messages.push(msg);

      const calls = msg.tool_calls ?? [];
      if (!calls.length) {
        await logDecision("planner-done", msg.content ?? "");
        break;
      }

      for (const c of calls) {
        const name = c.function?.name;
        let args: any = {};
        try { args = JSON.parse(c.function?.arguments || "{}"); } catch {}
        let result: any = { ok: true };

        try {
          if (name === "queue_recon") {
            const j = await enqueue("recon", { action: "enumerate", domain: args.target ?? target }, 10);
            result = { queued_job: j.id };
          } else if (name === "queue_detector") {
            const j = await enqueue(args.name, args.params ?? {}, args.priority ?? 100);
            result = { queued_job: j.id };
          } else if (name === "query_findings") {
            const { data } = await supa.from("recon_findings").select("finding_type,severity,title,url_path")
              .eq("scan_id", scanId).limit(50);
            result = { findings: data ?? [] };
          } else if (name === "query_jobs") {
            const { data } = await supa.from("scan_jobs").select("detector,status,error")
              .eq("scan_id", scanId).limit(50);
            result = { jobs: data ?? [] };
          } else if (name === "note") {
            result = { noted: true };
          } else if (name === "finalize") {
            finalized = true;
            result = { finalized: true };
          } else {
            result = { error: `unknown tool ${name}` };
          }
        } catch (e: any) {
          result = { error: String(e?.message ?? e) };
        }

        await logDecision(name, args.text ?? args.summary ?? JSON.stringify(args).slice(0, 200), { name, args }, result);
        messages.push({
          role: "tool",
          tool_call_id: c.id,
          content: JSON.stringify(result).slice(0, 2000),
        });
      }
    }

    return new Response(JSON.stringify({ ok: true, steps: step, finalized }), {
      headers: { ...cors, "Content-Type": "application/json" },
    });
  } catch (e: any) {
    console.error("planner error", e);
    return new Response(JSON.stringify({ error: String(e?.message ?? e) }), {
      status: 500, headers: { ...cors, "Content-Type": "application/json" },
    });
  }
});
