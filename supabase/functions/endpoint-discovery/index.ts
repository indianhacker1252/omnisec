import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface Endpoint {
  url: string;
  method: string;
  status?: number;
  contentType?: string;
  size?: number;
  description?: string;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { target, depth = 2 } = await req.json();
    
    if (!target) {
      return new Response(JSON.stringify({ error: "Missing target" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const url = new URL(target.startsWith('http') ? target : `https://${target}`);
    console.log(`Discovering endpoints for: ${url.origin}`);

    const endpoints: Endpoint[] = [];
    const visited = new Set<string>();
    const startTime = Date.now();

    // Common API endpoints to probe
    const apiPaths = [
      // REST API patterns
      "/api", "/api/v1", "/api/v2", "/api/v3",
      "/v1", "/v2", "/v3",
      "/rest", "/rest/api",
      "/graphql", "/graphql/v1",
      "/query", "/rpc",
      
      // Common resources
      "/api/users", "/api/user", "/api/auth", "/api/login",
      "/api/register", "/api/logout", "/api/profile",
      "/api/products", "/api/items", "/api/orders",
      "/api/search", "/api/config", "/api/settings",
      "/api/health", "/api/status", "/api/ping",
      "/api/version", "/api/info", "/api/docs",
      
      // Auth endpoints
      "/oauth", "/oauth2", "/oauth/token", "/oauth/authorize",
      "/auth/login", "/auth/logout", "/auth/register",
      "/login", "/signin", "/signup", "/register",
      "/forgot-password", "/reset-password",
      
      // Admin paths
      "/admin", "/admin/api", "/admin/login",
      "/administrator", "/manage", "/management",
      "/dashboard", "/console", "/panel",
      
      // Documentation
      "/swagger", "/swagger.json", "/swagger.yaml",
      "/swagger-ui", "/swagger-ui.html",
      "/api-docs", "/docs", "/documentation",
      "/redoc", "/openapi", "/openapi.json",
      
      // Debug/Dev endpoints
      "/debug", "/test", "/dev",
      "/phpinfo.php", "/info.php",
      "/actuator", "/actuator/health", "/actuator/info",
      "/metrics", "/prometheus",
      
      // File paths
      "/static", "/assets", "/public",
      "/uploads", "/files", "/media",
      "/images", "/img", "/js", "/css",
      
      // Misc
      "/sitemap.xml", "/robots.txt",
      "/favicon.ico", "/.well-known",
      "/feed", "/rss", "/atom",
      "/websocket", "/ws", "/socket.io"
    ];

    // Probe each endpoint
    const batchSize = 15;
    for (let i = 0; i < apiPaths.length; i += batchSize) {
      const batch = apiPaths.slice(i, i + batchSize);
      const results = await Promise.all(batch.map(async (path) => {
        const testUrl = `${url.origin}${path}`;
        if (visited.has(testUrl)) return null;
        visited.add(testUrl);

        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4000);
          
          const resp = await fetch(testUrl, {
            method: "GET",
            signal: controller.signal,
            redirect: "manual",
            headers: { "User-Agent": "OmniSec Endpoint Discovery/1.0" }
          });
          clearTimeout(timeoutId);

          // Consider 200, 401, 403 as valid endpoints
          if ([200, 201, 401, 403, 405].includes(resp.status)) {
            return {
              url: testUrl,
              method: "GET",
              status: resp.status,
              contentType: resp.headers.get("content-type") || undefined,
              size: parseInt(resp.headers.get("content-length") || "0") || undefined,
              description: getEndpointDescription(path, resp.status)
            };
          }
          return null;
        } catch {
          return null;
        }
      }));

      endpoints.push(...results.filter(Boolean) as Endpoint[]);
    }

    // Try to parse robots.txt for more paths
    try {
      const robotsResp = await fetch(`${url.origin}/robots.txt`, {
        signal: AbortSignal.timeout(3000)
      });
      if (robotsResp.ok) {
        const robotsText = await robotsResp.text();
        const disallowed = robotsText.match(/Disallow:\s*(\S+)/gi) || [];
        for (const line of disallowed.slice(0, 20)) {
          const path = line.replace(/Disallow:\s*/i, '').trim();
          if (path && path !== '/' && !visited.has(`${url.origin}${path}`)) {
            endpoints.push({
              url: `${url.origin}${path}`,
              method: "GET",
              description: "Found in robots.txt (may be sensitive)"
            });
          }
        }
      }
    } catch {
      // robots.txt not accessible
    }

    const scanTime = Date.now() - startTime;
    console.log(`Found ${endpoints.length} endpoints in ${scanTime}ms`);

    return new Response(JSON.stringify({
      success: true,
      target: url.origin,
      endpoints: endpoints.sort((a, b) => (a.status || 999) - (b.status || 999)),
      total: endpoints.length,
      scanTime,
      timestamp: new Date().toISOString()
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (e: any) {
    console.error("Endpoint discovery error:", e);
    return new Response(JSON.stringify({ 
      error: e?.message || "Unknown error",
      success: false 
    }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});

function getEndpointDescription(path: string, status: number): string {
  if (status === 401 || status === 403) return "Authentication required - potential sensitive endpoint";
  if (path.includes("api")) return "API endpoint discovered";
  if (path.includes("admin")) return "Administrative interface";
  if (path.includes("swagger") || path.includes("docs")) return "API documentation";
  if (path.includes("graphql")) return "GraphQL endpoint";
  if (path.includes("auth") || path.includes("login")) return "Authentication endpoint";
  if (path.includes("actuator") || path.includes("health")) return "Health/monitoring endpoint";
  return "Accessible endpoint";
}
