import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Max-Age": "86400",
};

type ReconResult = {
  host: string;
  ip: string;
  status: "online" | "offline" | "unknown";
  ports: { port: number; transport?: string; product?: string; service?: string }[];
  hostnames?: string[];
  org?: string;
  isp?: string;
  asn?: string;
  country?: string;
  city?: string;
  timestamp: string;
  source: string;
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
    const { target } = await req.json();
    if (!target || typeof target !== "string") {
      return new Response(JSON.stringify({ error: "Missing target parameter" }), { 
        status: 400, 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }

    // Clean target
    const cleanTarget = target.trim().replace(/^https?:\/\//, '').split('/')[0];

    if (!validateTarget(cleanTarget)) {
      return new Response(JSON.stringify({ error: "Invalid target - private/internal addresses not allowed" }), { 
        status: 400, 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }

    // If target is IP keep it, else resolve
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const ip = ipRegex.test(cleanTarget) ? cleanTarget : (await resolveARecord(cleanTarget));
    
    if (!ip) {
      return new Response(JSON.stringify({ 
        error: "Could not resolve hostname to IP address",
        host: cleanTarget 
      }), { 
        status: 400, 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }

    if (!validateTarget(ip)) {
      return new Response(JSON.stringify({ error: "Resolved IP is a private/internal address" }), { 
        status: 400, 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }

    console.log(`Performing recon on: ${cleanTarget} (IP: ${ip})`);

    const SHODAN_API_KEY = Deno.env.get("SHODAN_API_KEY");
    
    if (!SHODAN_API_KEY) {
      // Fallback: Basic DNS and HTTP check without Shodan
      console.log("No Shodan API key - performing basic recon");
      
      const basicResult: ReconResult = {
        host: cleanTarget,
        ip: ip,
        status: "unknown",
        ports: [],
        timestamp: new Date().toISOString(),
        source: "DNS Resolution (Shodan API key not configured)"
      };

      // Try to get more info from IP-API (free)
      try {
        const ipApiResp = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,as`);
        if (ipApiResp.ok) {
          const ipData = await ipApiResp.json();
          if (ipData.status === "success") {
            basicResult.country = ipData.country;
            basicResult.city = ipData.city;
            basicResult.isp = ipData.isp;
            basicResult.org = ipData.org;
            basicResult.asn = ipData.as;
            basicResult.status = "online";
          }
        }
      } catch (e) {
        console.error("IP-API error:", e);
      }

      // Check common ports via HTTP
      const commonPorts = [80, 443, 8080, 8443];
      for (const port of commonPorts) {
        try {
          const protocol = port === 443 || port === 8443 ? 'https' : 'http';
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 3000);
          
          const resp = await fetch(`${protocol}://${ip}:${port}`, {
            method: 'HEAD',
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          
          basicResult.ports.push({
            port: port,
            service: protocol,
            product: resp.headers.get('server') || undefined
          });
          basicResult.status = "online";
        } catch (e) {
          // Port not accessible
        }
      }

      return new Response(JSON.stringify(basicResult), { 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }

    // Use Shodan API
    const shodanResp = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}`);
    
    if (!shodanResp.ok) {
      const errorText = await shodanResp.text();
      console.error("Shodan error:", shodanResp.status, errorText);
      
      if (shodanResp.status === 404) {
        return new Response(JSON.stringify({ 
          host: cleanTarget,
          ip: ip,
          status: "online",
          ports: [],
          message: "No Shodan data available for this IP. The host may not have been recently scanned by Shodan.",
          timestamp: new Date().toISOString(),
          source: "Shodan API"
        }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
      
      return new Response(JSON.stringify({ 
        error: "Shodan API error", 
        details: errorText.substring(0, 200) 
      }), { 
        status: 502, 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }
    
    const shodan = await shodanResp.json();

    const ports = Array.isArray(shodan?.data)
      ? shodan.data.map((d: any) => ({ 
          port: d.port, 
          transport: d.transport, 
          product: d.product, 
          service: d._shodan?.module || d.product,
          version: d.version,
          banner: d.data?.substring(0, 200)
        }))
      : (Array.isArray(shodan?.ports) ? shodan.ports.map((p: number) => ({ port: p })) : []);

    const result: ReconResult = {
      host: cleanTarget,
      ip,
      status: "online",
      ports: ports.filter((p: any) => typeof p.port === "number"),
      hostnames: shodan.hostnames || [],
      org: shodan.org,
      isp: shodan.isp,
      asn: shodan.asn,
      country: shodan.country_name,
      city: shodan.city,
      timestamp: new Date().toISOString(),
      source: "Shodan API"
    };

    console.log(`Recon complete: Found ${result.ports.length} ports`);

    return new Response(JSON.stringify(result), { 
      headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  } catch (e) {
    console.error("recon error", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), { 
      status: 500, 
      headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }
});
