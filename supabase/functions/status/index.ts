import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const SHODAN_API_KEY = Deno.env.get("SHODAN_API_KEY");
    const NVD_API_KEY = Deno.env.get("NVD_API_KEY");
    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");

    return new Response(
      JSON.stringify({
        time: new Date().toISOString(),
        aiEnabled: Boolean(LOVABLE_API_KEY),
        shodanConfigured: Boolean(SHODAN_API_KEY),
        nvdConfigured: Boolean(NVD_API_KEY),
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("status error", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});