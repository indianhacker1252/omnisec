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

    const { action, siemEndpoint, apiKey } = await req.json();

    // Check if user provided SIEM integration details
    if (siemEndpoint && apiKey) {
      // Real SIEM integration - fetch actual alerts
      try {
        const siemResponse = await fetch(siemEndpoint, {
          method: "GET",
          headers: {
            "Authorization": `Bearer ${apiKey}`,
            "Content-Type": "application/json"
          }
        });

        if (!siemResponse.ok) {
          throw new Error(`SIEM returned ${siemResponse.status}`);
        }

        const siemData = await siemResponse.json();

        // Audit log
        await supabaseClient.from("security_audit_log").insert({
          user_id: user.id,
          action: "siem_alerts_fetched",
          module: "blue_team",
          target: siemEndpoint,
          result: `Fetched ${siemData.alerts?.length || 0} alerts`
        });

        return new Response(
          JSON.stringify({
            success: true,
            source: "SIEM",
            alerts: siemData.alerts || [],
            metrics: siemData.metrics || {},
            mitreCoverage: siemData.mitreCoverage || {},
            timestamp: new Date().toISOString()
          }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      } catch (siemError) {
        console.error("SIEM connection failed:", siemError);
        return new Response(
          JSON.stringify({
            success: false,
            error: "SIEM_CONNECTION_FAILED",
            message: siemError instanceof Error ? siemError.message : "Failed to connect to SIEM"
          }),
          { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }
    }

    // No SIEM configured - return configuration required message
    return new Response(
      JSON.stringify({
        success: false,
        error: "SIEM_NOT_CONFIGURED",
        message: "Blue Team module requires SIEM integration for real alerts",
        instructions: {
          title: "Configure SIEM Integration",
          description: "To receive real security alerts, connect your SIEM/log management platform",
          supportedPlatforms: [
            { name: "Splunk", endpoint: "https://your-splunk:8089/services/search/jobs" },
            { name: "Elastic SIEM", endpoint: "https://your-elastic:9200/_security/alerts" },
            { name: "Microsoft Sentinel", endpoint: "https://management.azure.com/subscriptions/.../alerts" },
            { name: "IBM QRadar", endpoint: "https://your-qradar/api/siem/offenses" },
            { name: "Wazuh", endpoint: "https://your-wazuh:55000/security/alerts" },
            { name: "TheHive", endpoint: "https://your-hive:9000/api/alert" }
          ],
          steps: [
            "1. Generate an API key/token in your SIEM platform",
            "2. Configure the endpoint URL for your SIEM's alerts API",
            "3. Add SIEM credentials in OmniSec Settings > Integrations",
            "4. Alerts will be fetched in real-time from your SIEM"
          ]
        },
        alternatives: [
          "Use local log analysis tools (OSSEC, Wazuh agent)",
          "Configure syslog forwarding to analyze logs",
          "Deploy OmniSec agent on endpoints for EDR functionality"
        ],
        timestamp: new Date().toISOString()
      }),
      { 
        status: 400, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
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
