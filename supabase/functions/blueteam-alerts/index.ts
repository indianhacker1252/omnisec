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
    const { action, siemEndpoint, apiKey } = await req.json();

    console.log("Blue Team request:", action);

    // Check if user provided SIEM integration details
    if (siemEndpoint && apiKey) {
      // Real SIEM integration - fetch actual alerts
      try {
        console.log("Connecting to SIEM:", siemEndpoint);
        
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

        return new Response(
          JSON.stringify({
            success: true,
            source: "SIEM",
            alerts: siemData.alerts || siemData.data || [],
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

    // No SIEM configured - return configuration required message with detailed guidance
    return new Response(
      JSON.stringify({
        success: false,
        error: "SIEM_NOT_CONFIGURED",
        message: "Blue Team module requires SIEM integration for real-time security alerts",
        instructions: {
          title: "Configure SIEM Integration",
          description: "Connect your Security Information and Event Management (SIEM) platform to receive real-time alerts",
          supportedPlatforms: [
            { 
              name: "Splunk", 
              endpoint: "https://your-splunk:8089/services/search/jobs",
              documentation: "https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch"
            },
            { 
              name: "Elastic SIEM", 
              endpoint: "https://your-elastic:5601/api/detection_engine/signals",
              documentation: "https://www.elastic.co/guide/en/security/current/signals-api-overview.html"
            },
            { 
              name: "Microsoft Sentinel", 
              endpoint: "https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.SecurityInsights/incidents",
              documentation: "https://learn.microsoft.com/en-us/rest/api/securityinsights/"
            },
            { 
              name: "IBM QRadar", 
              endpoint: "https://your-qradar/api/siem/offenses",
              documentation: "https://www.ibm.com/docs/en/qradar"
            },
            { 
              name: "Wazuh", 
              endpoint: "https://your-wazuh:55000/security/alerts",
              documentation: "https://documentation.wazuh.com/current/user-manual/api/reference.html"
            },
            { 
              name: "TheHive/Cortex", 
              endpoint: "https://your-hive:9000/api/alert",
              documentation: "https://docs.thehive-project.org/thehive/api-docs/"
            },
            {
              name: "Sumo Logic",
              endpoint: "https://api.sumologic.com/api/v1/collectors",
              documentation: "https://help.sumologic.com/docs/api/"
            }
          ],
          steps: [
            "1. Access your SIEM platform's admin panel",
            "2. Generate an API key/token with read access to alerts",
            "3. Note the API endpoint URL for alerts/incidents",
            "4. Enter credentials in the Blue Team module settings",
            "5. Test the connection to verify integration"
          ],
          freeAlternatives: [
            {
              name: "Wazuh (Open Source)",
              description: "Free, open-source SIEM with built-in threat detection",
              link: "https://wazuh.com/"
            },
            {
              name: "Security Onion",
              description: "Free and open-source network security monitoring",
              link: "https://securityonionsolutions.com/"
            },
            {
              name: "OSSEC",
              description: "Free host-based intrusion detection system",
              link: "https://www.ossec.net/"
            }
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
    console.error("Blue Team error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  }
});
