import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface SubdomainResult {
  subdomain: string;
  ip?: string;
  status: "active" | "inactive" | "unknown";
  ports?: number[];
}

async function resolveSubdomain(subdomain: string): Promise<SubdomainResult> {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(subdomain)}&type=A`);
    const data = await r.json();
    const ip = data?.Answer?.find((a: any) => a.type === 1)?.data;
    return {
      subdomain,
      ip: ip || undefined,
      status: ip ? "active" : "inactive"
    };
  } catch {
    return { subdomain, status: "unknown" };
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { domain } = await req.json();
    
    if (!domain || typeof domain !== "string") {
      return new Response(JSON.stringify({ error: "Missing domain parameter" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // Clean domain
    const cleanDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
    
    console.log(`Enumerating subdomains for: ${cleanDomain}`);

    const subdomains: SubdomainResult[] = [];
    const startTime = Date.now();

    // Common subdomain prefixes to check
    const commonPrefixes = [
      "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
      "admin", "administrator", "blog", "dev", "development", "staging",
      "test", "api", "app", "apps", "m", "mobile", "cdn", "static",
      "assets", "img", "images", "js", "css", "media", "files",
      "shop", "store", "secure", "ssl", "portal", "login", "auth",
      "sso", "gateway", "vpn", "remote", "proxy", "db", "database",
      "mysql", "postgres", "redis", "mongo", "elasticsearch", "es",
      "kibana", "grafana", "prometheus", "jenkins", "gitlab", "github",
      "jira", "confluence", "wiki", "docs", "support", "help", "status",
      "monitor", "metrics", "logs", "analytics", "tracking", "crm",
      "erp", "hr", "finance", "payments", "billing", "checkout",
      "cart", "search", "internal", "intranet", "extranet", "partners",
      "demo", "sandbox", "preview", "beta", "alpha", "stage", "prod",
      "production", "backup", "bak", "old", "new", "v1", "v2", "v3",
      "legacy", "www1", "www2", "web", "web1", "web2", "mail2",
      "email", "newsletter", "marketing", "sales", "events", "news",
      "forum", "community", "chat", "irc", "slack", "teams",
      "calendar", "meet", "video", "stream", "live", "download",
      "upload", "cloud", "aws", "azure", "gcp", "s3", "storage"
    ];

    // Check each subdomain in parallel (batches of 10)
    const batchSize = 10;
    for (let i = 0; i < commonPrefixes.length; i += batchSize) {
      const batch = commonPrefixes.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map(prefix => resolveSubdomain(`${prefix}.${cleanDomain}`))
      );
      subdomains.push(...results.filter(r => r.status === "active"));
    }

    // Also check the root domain
    const rootResult = await resolveSubdomain(cleanDomain);
    if (rootResult.status === "active") {
      subdomains.unshift(rootResult);
    }

    // Try crt.sh for certificate transparency logs
    try {
      const crtResponse = await fetch(`https://crt.sh/?q=%.${cleanDomain}&output=json`, {
        signal: AbortSignal.timeout(8000)
      });
      if (crtResponse.ok) {
        const crtData = await crtResponse.json();
        const ctSubdomains = new Set<string>();
        
        for (const cert of crtData.slice(0, 100)) {
          const names = cert.name_value?.split('\n') || [];
          for (const name of names) {
            const clean = name.replace(/^\*\./, '').toLowerCase();
            if (clean.endsWith(cleanDomain) && !clean.includes('*')) {
              ctSubdomains.add(clean);
            }
          }
        }
        
        // Check newly found subdomains
        const newSubs = Array.from(ctSubdomains).filter(
          s => !subdomains.some(sub => sub.subdomain === s)
        );
        
        const ctResults = await Promise.all(
          newSubs.slice(0, 30).map(sub => resolveSubdomain(sub))
        );
        subdomains.push(...ctResults.filter(r => r.status === "active"));
      }
    } catch (e) {
      console.log("crt.sh lookup failed, continuing with bruteforce results");
    }

    // Deduplicate
    const uniqueSubdomains = Array.from(
      new Map(subdomains.map(s => [s.subdomain, s])).values()
    );

    const scanTime = Date.now() - startTime;
    console.log(`Found ${uniqueSubdomains.length} subdomains in ${scanTime}ms`);

    return new Response(JSON.stringify({
      success: true,
      domain: cleanDomain,
      subdomains: uniqueSubdomains,
      total: uniqueSubdomains.length,
      scanTime,
      timestamp: new Date().toISOString()
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (e: any) {
    console.error("Subdomain enumeration error:", e);
    return new Response(JSON.stringify({ 
      error: e?.message || "Unknown error",
      success: false 
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
