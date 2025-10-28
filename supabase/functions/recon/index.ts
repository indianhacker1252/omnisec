import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

type ReconResult = {
  host: string;
  ip: string;
  status: "online" | "offline";
  ports: { port: number; transport?: string; product?: string; service?: string }[];
  timestamp: string;
};

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
    const { target } = await req.json();
    if (!target || typeof target !== "string") {
      return new Response(JSON.stringify({ error: "Missing target" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const SHODAN_API_KEY = Deno.env.get("SHODAN_API_KEY");
    if (!SHODAN_API_KEY) {
      return new Response(JSON.stringify({ error: "SHODAN_API_KEY not configured. Please add it in backend settings." }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // If target is IP keep it, else resolve
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const ip = ipRegex.test(target) ? target : (await resolveARecord(target));
    if (!ip) {
      return new Response(JSON.stringify({ error: "Could not resolve target to an IPv4 address" }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const shodanResp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`);
    if (!shodanResp.ok) {
      const t = await shodanResp.text();
      console.error("shodan error", shodanResp.status, t);
      return new Response(JSON.stringify({ error: "Shodan API error", details: t }), { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } });
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

    return new Response(JSON.stringify(result), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("recon error", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
