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
    // Authentication check
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { action, siemEndpoint, apiKey } = await req.json();
    console.log(`[BLUETEAM] User ${user.id} request: ${action}`);

    if (siemEndpoint && apiKey) {
      try {
        console.log("Connecting to SIEM:", siemEndpoint);
        const siemResponse = await fetch(siemEndpoint, {
          method: "GET",
          headers: { "Authorization": `Bearer ${apiKey}`, "Content-Type": "application/json" }
        });
        if (!siemResponse.ok) throw new Error(`SIEM returned ${siemResponse.status}`);
        const siemData = await siemResponse.json();
        return new Response(JSON.stringify({
          success: true, source: "SIEM",
          alerts: siemData.alerts || siemData.data || [],
          metrics: siemData.metrics || {},
          mitreCoverage: siemData.mitreCoverage || {},
          timestamp: new Date().toISOString()
        }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      } catch (siemError) {
        console.error("SIEM connection failed:", siemError);
        return new Response(JSON.stringify({
          success: false, error: "SIEM_CONNECTION_FAILED",
          message: siemError instanceof Error ? siemError.message : "Failed to connect to SIEM"
        }), { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
    }

    return new Response(JSON.stringify({
      success: false, error: "SIEM_NOT_CONFIGURED",
      message: "Blue Team module requires SIEM integration for real-time security alerts",
      instructions: {
        title: "Configure SIEM Integration",
        description: "Connect your SIEM platform to receive real-time alerts",
        supportedPlatforms: [
          { name: "Splunk", endpoint: "https://your-splunk:8089/services/search/jobs" },
          { name: "Elastic SIEM", endpoint: "https://your-elastic:5601/api/detection_engine/signals" },
          { name: "Microsoft Sentinel", endpoint: "https://management.azure.com/..." },
          { name: "Wazuh", endpoint: "https://your-wazuh:55000/security/alerts" },
        ],
        steps: [
          "1. Generate an API key with read access to alerts",
          "2. Note the API endpoint URL",
          "3. Enter credentials in the Blue Team module settings",
          "4. Test the connection"
        ]
      },
      timestamp: new Date().toISOString()
    }), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  } catch (error: unknown) {
    console.error("Blue Team error:", error);
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  }
});
