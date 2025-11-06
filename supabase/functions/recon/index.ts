import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Max-Age": "86400",
};

type ReconResult = {
  host: string;
  ip: string;
  status: "online" | "offline";
  ports: { port: number; transport?: string; product?: string; service?: string }[];
  timestamp: string;
};

function validateTarget(target: string): boolean {
  const blockedPatterns = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^0\./,
    /^224\./,
    /^240\./,
    /localhost/i,
    /metadata/i,
    /internal/i,
  ];
  
  return !blockedPatterns.some(p => p.test(target));
}

async function resolveARecord(host: string): Promise<string | null> {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`);
    const data = await r.json();
    const ip = data?.Answer?.find((a: any) => a.type === 1)?.data;
    return ip || null;
  } catch (e) {
    console.error("dns resolve error", e);
    return null;
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    // Initialize Supabase client
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );

    // Authenticate user (recon is available to all authenticated users)
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const { target } = await req.json();
    if (!target || typeof target !== "string") {
      return new Response(JSON.stringify({ error: "Invalid request" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (!validateTarget(target)) {
      return new Response(JSON.stringify({ error: "Invalid target address" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const SHODAN_API_KEY = Deno.env.get("SHODAN_API_KEY");
    if (!SHODAN_API_KEY) {
      return new Response(JSON.stringify({ error: "Service not configured" }), { status: 503, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // If target is IP keep it, else resolve
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const ip = ipRegex.test(target) ? target : (await resolveARecord(target));
    if (!ip) {
      return new Response(JSON.stringify({ error: "Invalid target" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (!validateTarget(ip)) {
      return new Response(JSON.stringify({ error: "Invalid target address" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const shodanResp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`);
    if (!shodanResp.ok) {
      console.error("shodan error", shodanResp.status);
      return new Response(JSON.stringify({ error: "External service error" }), { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const shodan = await shodanResp.json();

    const ports = Array.isArray(shodan?.data)
      ? shodan.data.map((d: any) => ({ port: d.port, transport: d.transport, product: d.product, service: d._shodan?.module || d.product }))
      : (Array.isArray(shodan?.ports) ? shodan.ports.map((p: number) => ({ port: p })) : []);

    const result: ReconResult = {
      host: target,
      ip,
      status: "online",
      ports: ports.filter((p: any) => typeof p.port === "number"),
      timestamp: new Date().toISOString(),
    };

    // Audit log
    await supabaseClient.from("security_audit_log").insert({
      user_id: user.id,
      action: "reconnaissance_completed",
      resource_type: "network_target",
      resource_id: target,
      details: {
        target: target,
        ip: ip,
        ports_found: result.ports.length,
        ports: result.ports.map((p: any) => p.port),
        timestamp: new Date().toISOString()
      },
      ip_address: req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || "unknown"
    });

    return new Response(JSON.stringify(result), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("recon error", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
