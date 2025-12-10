import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * Learning VAPT Assistant Edge Function
 * 
 * ⚠️ IMPORTANT: This tool is for AUTHORIZED PENETRATION TESTING ONLY.
 * Misuse for unauthorized access or malicious purposes is strictly prohibited
 * and may violate laws including the Computer Fraud and Abuse Act (CFAA).
 * 
 * Always ensure you have written authorization before testing any target.
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// LLM Prompt template for generating improvement suggestions
const SUGGESTION_PROMPT_TEMPLATE = `You are an expert penetration testing assistant helping with AUTHORIZED security assessments.

⚠️ ETHICAL GUIDELINES - YOU MUST FOLLOW:
1. Only provide advice for AUTHORIZED testing with written permission
2. Do NOT provide detailed exploit payloads that could be copy-pasted for attacks
3. Use TEMPLATE placeholders like {{PAYLOAD}}, {{VALUE}}, {{INPUT}} instead of real payloads
4. Focus on methodology, strategies, and high-level approaches
5. Emphasize responsible disclosure and legal compliance

CURRENT TEST ACTION:
- Target: {{TARGET_URL}}
- Method: {{METHOD}}
- Test Type: {{TEST_TYPE}}
- Injection Point: {{INJECTION_POINT}}
- Payload Attempted: {{PAYLOAD_SENT}}
- Outcome: {{OUTCOME}}
- Notes: {{NOTES}}

SIMILAR SUCCESSFUL PAST ACTIONS:
{{SIMILAR_ACTIONS}}

TASK:
1. Analyze why the current test may not have achieved the expected result
2. Based on successful past actions and security testing best practices, suggest 3-5 improved strategies
3. For each strategy, provide:
   - A clear explanation of the approach
   - Why it might work better
   - A SAFE payload template using placeholders (e.g., {{PAYLOAD}}, {{CONTEXT}})
4. Consider different encoding schemes, injection contexts, and bypass techniques
5. Remind the tester about scope limitations and ethical considerations

Respond in JSON format:
{
  "explanation": "Analysis of why current approach may have failed",
  "strategies": [
    {
      "name": "Strategy name",
      "description": "Detailed explanation",
      "rationale": "Why this might work",
      "payload_template": "Safe template with {{PLACEHOLDERS}}"
    }
  ],
  "ethical_reminder": "Brief reminder about authorization and scope"
}`;

interface TestAction {
  id?: string;
  target_url: string;
  method: string;
  injection_point?: string;
  payload_sent?: string;
  transformed_payload?: string;
  request_headers?: Record<string, string>;
  request_body?: string;
  response_status?: number;
  response_headers?: Record<string, string>;
  response_body?: string;
  outcome_label?: string;
  test_type: string;
  notes?: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Get user from auth header
    const authHeader = req.headers.get("Authorization");
    let userId: string | null = null;
    
    if (authHeader) {
      const token = authHeader.replace("Bearer ", "");
      const { data: { user } } = await supabase.auth.getUser(token);
      userId = user?.id || null;
    }

    const url = new URL(req.url);
    const path = url.pathname.split("/").filter(Boolean);
    const action = path[path.length - 1];

    // Parse request body
    let body: any = {};
    if (req.method !== "GET") {
      try {
        body = await req.json();
      } catch {
        body = {};
      }
    }

    // Route: POST /log-action - Log a test action
    if (action === "log-action" && req.method === "POST") {
      const testAction: TestAction = body;
      
      if (!testAction.target_url || !testAction.test_type) {
        return new Response(
          JSON.stringify({ error: "target_url and test_type are required" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const { data, error } = await supabase
        .from("vapt_test_actions")
        .insert({
          target_url: testAction.target_url,
          method: testAction.method || "GET",
          injection_point: testAction.injection_point,
          payload_sent: testAction.payload_sent,
          transformed_payload: testAction.transformed_payload,
          request_headers: testAction.request_headers || {},
          request_body: testAction.request_body,
          response_status: testAction.response_status,
          response_headers: testAction.response_headers || {},
          response_body: testAction.response_body?.substring(0, 10000), // Limit size
          outcome_label: testAction.outcome_label || "no_effect",
          test_type: testAction.test_type,
          notes: testAction.notes,
          operator_id: userId,
        })
        .select()
        .single();

      if (error) {
        console.error("Error logging action:", error);
        return new Response(
          JSON.stringify({ error: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      return new Response(
        JSON.stringify({ success: true, action: data }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Route: GET /actions - List all actions for user
    if (action === "actions" && req.method === "GET") {
      const limit = parseInt(url.searchParams.get("limit") || "50");
      const testType = url.searchParams.get("test_type");
      
      let query = supabase
        .from("vapt_test_actions")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(limit);
      
      if (userId) {
        query = query.eq("operator_id", userId);
      }
      if (testType) {
        query = query.eq("test_type", testType);
      }

      const { data, error } = await query;

      if (error) {
        return new Response(
          JSON.stringify({ error: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      return new Response(
        JSON.stringify({ actions: data }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Route: POST /similar - Find similar past actions
    if (action === "similar" && req.method === "POST") {
      const { test_type, injection_point, domain, search_text, limit = 5 } = body;

      if (!test_type) {
        return new Response(
          JSON.stringify({ error: "test_type is required" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const { data, error } = await supabase.rpc("find_similar_vapt_actions", {
        p_operator_id: userId,
        p_test_type: test_type,
        p_injection_point: injection_point || null,
        p_domain: domain || null,
        p_search_text: search_text || null,
        p_limit: limit,
      });

      if (error) {
        console.error("Error finding similar actions:", error);
        return new Response(
          JSON.stringify({ error: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      return new Response(
        JSON.stringify({ similar_actions: data }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Route: POST /suggestions - Get AI-powered improvement suggestions
    if (action === "suggestions" && req.method === "POST") {
      const { action_id, current_action } = body;

      let testAction: TestAction | null = current_action;

      // If action_id provided, fetch from database
      if (action_id && !testAction) {
        const { data, error } = await supabase
          .from("vapt_test_actions")
          .select("*")
          .eq("id", action_id)
          .single();
        
        if (error || !data) {
          return new Response(
            JSON.stringify({ error: "Action not found" }),
            { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }
        testAction = data;
      }

      if (!testAction) {
        return new Response(
          JSON.stringify({ error: "Either action_id or current_action is required" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      // Find similar successful past actions
      const { data: similarActions } = await supabase.rpc("find_similar_vapt_actions", {
        p_operator_id: userId,
        p_test_type: testAction.test_type,
        p_injection_point: testAction.injection_point || null,
        p_domain: null,
        p_search_text: null,
        p_limit: 5,
      });

      // Format similar actions for prompt
      const similarActionsText = (similarActions || [])
        .filter((a: any) => a.outcome_label === "confirmed_issue" || a.outcome_label === "potential_issue")
        .map((a: any, i: number) => 
          `${i + 1}. Target: ${a.target_url}, Injection: ${a.injection_point}, Outcome: ${a.outcome_label}, Notes: ${a.notes || "N/A"}`
        )
        .join("\n") || "No similar successful actions found in history.";

      // Build the prompt
      const prompt = SUGGESTION_PROMPT_TEMPLATE
        .replace("{{TARGET_URL}}", testAction.target_url)
        .replace("{{METHOD}}", testAction.method || "GET")
        .replace("{{TEST_TYPE}}", testAction.test_type)
        .replace("{{INJECTION_POINT}}", testAction.injection_point || "Unknown")
        .replace("{{PAYLOAD_SENT}}", testAction.payload_sent || "None")
        .replace("{{OUTCOME}}", testAction.outcome_label || "no_effect")
        .replace("{{NOTES}}", testAction.notes || "None")
        .replace("{{SIMILAR_ACTIONS}}", similarActionsText);

      // Call Lovable AI for suggestions
      const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
      if (!LOVABLE_API_KEY) {
        return new Response(
          JSON.stringify({ error: "AI service not configured" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const aiResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
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
              content: "You are an expert penetration testing assistant. Always respond with valid JSON. Never provide actual exploit code - only templates with placeholders."
            },
            { role: "user", content: prompt }
          ],
        }),
      });

      if (!aiResponse.ok) {
        if (aiResponse.status === 429) {
          return new Response(
            JSON.stringify({ error: "Rate limit exceeded. Please try again later." }),
            { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }
        console.error("AI API error:", await aiResponse.text());
        return new Response(
          JSON.stringify({ error: "AI service error" }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const aiData = await aiResponse.json();
      const aiContent = aiData.choices?.[0]?.message?.content || "";

      // Parse AI response
      let suggestions;
      try {
        // Extract JSON from response (handle markdown code blocks)
        const jsonMatch = aiContent.match(/```json\s*([\s\S]*?)\s*```/) || 
                          aiContent.match(/```\s*([\s\S]*?)\s*```/) ||
                          [null, aiContent];
        suggestions = JSON.parse(jsonMatch[1] || aiContent);
      } catch (e) {
        console.error("Failed to parse AI response:", aiContent);
        suggestions = {
          explanation: aiContent,
          strategies: [],
          ethical_reminder: "Always ensure you have authorization before testing."
        };
      }

      // Store suggestion in database
      if (action_id) {
        await supabase.from("vapt_suggestions").insert({
          action_id: action_id,
          explanation: suggestions.explanation || "",
          strategies: suggestions.strategies || [],
          payload_templates: suggestions.strategies?.map((s: any) => s.payload_template).filter(Boolean) || [],
          model_used: "google/gemini-2.5-flash",
        });
      }

      return new Response(
        JSON.stringify({ 
          suggestions,
          similar_actions_used: similarActions?.length || 0 
        }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Route: POST /feedback - Record feedback on suggestions
    if (action === "feedback" && req.method === "POST") {
      const { action_id, suggestion_id, rating, comments } = body;

      if (!action_id || !rating) {
        return new Response(
          JSON.stringify({ error: "action_id and rating are required" }),
          { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const { data, error } = await supabase
        .from("vapt_feedback")
        .insert({
          action_id,
          suggestion_id,
          rating,
          comments,
          operator_id: userId,
        })
        .select()
        .single();

      if (error) {
        return new Response(
          JSON.stringify({ error: error.message }),
          { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      return new Response(
        JSON.stringify({ success: true, feedback: data }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Route: GET/POST /config - Manage assistant configuration
    if (action === "config") {
      if (req.method === "GET") {
        const { data } = await supabase
          .from("vapt_config")
          .select("*")
          .eq("operator_id", userId)
          .single();

        return new Response(
          JSON.stringify({ 
            config: data || { 
              mode: "observe_only", 
              allowed_targets: [], 
              log_level: "info" 
            } 
          }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      if (req.method === "POST") {
        const { mode, allowed_targets, log_level } = body;

        const { data, error } = await supabase
          .from("vapt_config")
          .upsert({
            operator_id: userId,
            mode: mode || "observe_only",
            allowed_targets: allowed_targets || [],
            log_level: log_level || "info",
            updated_at: new Date().toISOString(),
          })
          .select()
          .single();

        if (error) {
          return new Response(
            JSON.stringify({ error: error.message }),
            { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        return new Response(
          JSON.stringify({ success: true, config: data }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
    }

    // Route: GET /stats - Get learning statistics
    if (action === "stats" && req.method === "GET") {
      const { data: actions } = await supabase
        .from("vapt_test_actions")
        .select("test_type, outcome_label")
        .eq("operator_id", userId);

      const { data: feedback } = await supabase
        .from("vapt_feedback")
        .select("rating")
        .eq("operator_id", userId);

      const stats = {
        total_actions: actions?.length || 0,
        by_test_type: {} as Record<string, number>,
        by_outcome: {} as Record<string, number>,
        feedback_summary: {
          helpful: 0,
          not_helpful: 0,
          partially_helpful: 0,
        },
      };

      actions?.forEach((a) => {
        stats.by_test_type[a.test_type] = (stats.by_test_type[a.test_type] || 0) + 1;
        stats.by_outcome[a.outcome_label] = (stats.by_outcome[a.outcome_label] || 0) + 1;
      });

      feedback?.forEach((f) => {
        if (f.rating in stats.feedback_summary) {
          stats.feedback_summary[f.rating as keyof typeof stats.feedback_summary]++;
        }
      });

      return new Response(
        JSON.stringify({ stats }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({ error: "Unknown endpoint", available: ["/log-action", "/actions", "/similar", "/suggestions", "/feedback", "/config", "/stats"] }),
      { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("VAPT Learning error:", error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
