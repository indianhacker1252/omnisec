import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

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

    const { scanType } = await req.json();

    // IMPORTANT: Wireless scanning requires LOCAL hardware access
    // This cloud function CANNOT scan real wireless networks
    // It provides educational information about what a real scan would show

    return new Response(
      JSON.stringify({
        success: false,
        error: "LOCAL_HARDWARE_REQUIRED",
        message: "Wireless scanning requires local hardware access (WiFi adapter, Bluetooth, NFC reader). Cloud-based scanning is not possible.",
        instructions: {
          title: "How to Perform Real Wireless Scans",
          steps: [
            "1. Install OmniSec locally or use Kali Linux integration",
            "2. Ensure you have appropriate wireless hardware (monitor mode capable WiFi adapter)",
            "3. For WiFi: Use airmon-ng to enable monitor mode",
            "4. For Bluetooth: Ensure hciconfig shows your adapter",
            "5. For NFC: Connect a compatible NFC reader (ACR122U, PN532)",
            "6. Run scans from local terminal with proper permissions"
          ],
          tools: {
            wifi: ["airodump-ng", "kismet", "wifite", "bettercap"],
            bluetooth: ["hcitool", "btscanner", "bettercap", "bleah"],
            nfc: ["libnfc", "mfoc", "nfc-tools"],
            rf: ["GNU Radio", "HackRF", "RTL-SDR"]
          }
        },
        alternatives: [
          "Use Kali Integration module to connect to a local Kali instance",
          "Deploy OmniSec agent on local machine with wireless hardware",
          "Use remote Raspberry Pi with wireless adapters as scanning node"
        ],
        scanType,
        timestamp: new Date().toISOString()
      }),
      { 
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      }
    );
  } catch (error: any) {
    console.error("Wireless scan error:", error);
    return new Response(
      JSON.stringify({ 
        error: error?.message || "Unknown error",
        success: false 
      }),
      { 
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      }
    );
  }
});
