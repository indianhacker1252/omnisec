import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

/**
 * OmniSec™ Payload Mutation & Retry Engine
 * 
 * MutationEngine: AI-powered payload obfuscation when WAF/filter blocks original payload
 * AttackExecutionLoop: Autonomous retry with mutated payloads (max 3 retries per param)
 * 
 * Events emitted to scan_progress:
 *   MUTATION_START, MUTATION_SUCCESS, MUTATION_FAIL, MAX_RETRIES_REACHED
 */

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

// ── Strict Interfaces ────────────────────────────────────────────────────────

interface PayloadAttempt {
  payload: string;
  status: number;
  blocked: boolean;
  response: string;
  timestamp: number;
}

interface MutationChain {
  id: string;
  targetUrl: string;
  parameter: string;
  originalPayload: string;
  attempts: PayloadAttempt[];
  currentPayload: string;
  attemptCount: number;
  maxRetries: number;
  status: 'pending' | 'mutating' | 'success' | 'defended' | 'error';
  mutationReason: string;
  finalResult?: string;
}

interface MutationRequest {
  action: 'execute_with_retry' | 'mutate_payload' | 'batch_execute';
  targetUrl: string;
  parameter: string;
  payload: string;
  method?: string;
  targetContext?: string;
  scanId?: string;
  techStack?: string[];
  maxRetries?: number;
  // batch mode
  targets?: Array<{ url: string; parameter: string; payload: string; method?: string }>;
}

interface MutationResult {
  chain: MutationChain;
  finding?: any;
  events: Array<{ type: string; data: any; timestamp: number }>;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    // Authentication check
    const authClient = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } }
    );
    const { data: { user }, error: authError } = await authClient.auth.getUser();
    if (authError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const body: MutationRequest = await req.json();
    const { action, scanId } = body;

    // ── Emit events to scan_progress for real-time UI ──────────────────
    const emitMutationEvent = async (type: string, data: any) => {
      if (!scanId) return;
      try {
        await supabase.from('scan_progress').insert({
          scan_id: scanId,
          phase: 'mutation',
          phase_number: 15,
          total_phases: 16,
          progress: -1,
          message: `🧬 ${type}: ${JSON.stringify(data).slice(0, 300)}`,
          findings_so_far: 0,
          endpoints_discovered: 0,
        });
      } catch {}
    };

    // ═══════════════════════════════════════════════════════════════════
    // ACTION: mutate_payload — AI generates a single mutation
    // ═══════════════════════════════════════════════════════════════════
    if (action === 'mutate_payload') {
      const { payload, targetContext } = body;
      const mutated = await generateMutation(
        LOVABLE_API_KEY, payload, targetContext || 'web application', 'Blocked by WAF/filter'
      );
      return new Response(JSON.stringify({ mutatedPayload: mutated, original: payload }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ═══════════════════════════════════════════════════════════════════
    // ACTION: execute_with_retry — Full attack loop with mutation
    // ═══════════════════════════════════════════════════════════════════
    if (action === 'execute_with_retry') {
      const result = await attackExecutionLoop(
        body.targetUrl, body.parameter, body.payload,
        body.method || 'GET', body.targetContext || '',
        body.techStack || [], body.maxRetries || 3,
        LOVABLE_API_KEY, emitMutationEvent
      );
      return new Response(JSON.stringify(result), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ═══════════════════════════════════════════════════════════════════
    // ACTION: batch_execute — Multiple targets in parallel
    // ═══════════════════════════════════════════════════════════════════
    if (action === 'batch_execute' && body.targets) {
      const results: MutationResult[] = [];
      // Process in batches of 3 to avoid overwhelming
      for (let i = 0; i < body.targets.length; i += 3) {
        const batch = body.targets.slice(i, i + 3);
        const batchResults = await Promise.all(batch.map(t =>
          attackExecutionLoop(
            t.url, t.parameter, t.payload,
            t.method || 'GET', body.targetContext || '',
            body.techStack || [], body.maxRetries || 3,
            LOVABLE_API_KEY, emitMutationEvent
          )
        ));
        results.push(...batchResults);
      }
      return new Response(JSON.stringify({ results, total: results.length }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ error: 'Invalid action' }), {
      status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error: any) {
    console.error("[MUTATION ENGINE ERROR]", error);
    return new Response(JSON.stringify({ error: error.message || "Mutation engine failed" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// MUTATION ENGINE — AI-Powered Payload Obfuscation
// ═══════════════════════════════════════════════════════════════════════════════

async function generateMutation(
  apiKey: string | undefined,
  originalPayload: string,
  targetContext: string,
  errorReason: string
): Promise<string> {
  // Attempt AI mutation first
  if (apiKey) {
    try {
      const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            {
              role: "system",
              content: "You are an expert penetration tester specializing in WAF evasion for authorized security testing. You generate obfuscated payloads. Output ONLY the raw payload string, no markdown, no explanations, no backticks."
            },
            {
              role: "user",
              content: `The payload '${originalPayload}' was blocked by a security filter on ${targetContext} with error: ${errorReason}. Generate a single, functionally equivalent but syntactically obfuscated payload (e.g., using different encoding, bypassing regex filters, case alternation, or polyglots) to evade detection. Output ONLY the raw payload string.`
            }
          ],
          temperature: 0.8,
          max_tokens: 200,
        }),
      });

      if (resp.ok) {
        const data = await resp.json();
        const content = (data.choices?.[0]?.message?.content || '').trim();
        // Validate: non-empty, not markdown, reasonable length
        if (content && content.length > 2 && content.length < 500
            && !content.startsWith('```') && !content.startsWith('#')
            && !content.includes('\n\n')) {
          // Strip any accidental backticks or quotes wrapping
          return content.replace(/^[`'"]+|[`'"]+$/g, '');
        }
      }
    } catch (e) {
      console.log('AI mutation failed, using fallback:', e);
    }
  }

  // Fallback: deterministic mutation techniques
  return fallbackMutation(originalPayload);
}

function fallbackMutation(payload: string): string {
  const techniques = [
    // Case alternation
    (p: string) => p.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(''),
    // Double URL encoding
    (p: string) => p.replace(/[<>"']/g, c => '%25' + c.charCodeAt(0).toString(16)),
    // HTML entity encoding
    (p: string) => p.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'),
    // Unicode escaping
    (p: string) => p.replace(/a/gi, '\\u0061').replace(/e/gi, '\\u0065'),
    // Comment injection (SQL)
    (p: string) => p.replace(/ /g, '/**/'),
    // Tab/newline substitution
    (p: string) => p.replace(/ /g, '%09'),
  ];

  const technique = techniques[Math.floor(Math.random() * techniques.length)];
  return technique(payload);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ATTACK EXECUTION LOOP — Async, Non-Blocking Retry with Mutation
// ═══════════════════════════════════════════════════════════════════════════════

async function attackExecutionLoop(
  targetUrl: string,
  parameter: string,
  originalPayload: string,
  method: string,
  targetContext: string,
  techStack: string[],
  maxRetries: number,
  apiKey: string | undefined,
  emitEvent: (type: string, data: any) => Promise<void>
): Promise<MutationResult> {
  const chain: MutationChain = {
    id: crypto.randomUUID(),
    targetUrl,
    parameter,
    originalPayload,
    attempts: [],
    currentPayload: originalPayload,
    attemptCount: 0,
    maxRetries,
    status: 'pending',
    mutationReason: '',
  };

  const events: Array<{ type: string; data: any; timestamp: number }> = [];
  const pushEvent = async (type: string, data: any) => {
    events.push({ type, data, timestamp: Date.now() });
    await emitEvent(type, { chainId: chain.id, parameter, ...data });
  };

  let currentPayload = originalPayload;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    chain.attemptCount = attempt + 1;

    try {
      // ── Fire Payload ──────────────────────────────────────────────
      const { status, responseText, blocked } = await firePayload(
        targetUrl, parameter, currentPayload, method
      );

      const attemptRecord: PayloadAttempt = {
        payload: currentPayload,
        status,
        blocked,
        response: responseText.slice(0, 300),
        timestamp: Date.now(),
      };
      chain.attempts.push(attemptRecord);

      // ── SUCCESS: Payload got through ──────────────────────────────
      if (!blocked) {
        chain.status = 'success';
        chain.finalResult = responseText.slice(0, 500);
        await pushEvent('MUTATION_SUCCESS', {
          payload: currentPayload,
          attempt: attempt + 1,
          status,
          wasOriginal: attempt === 0,
        });

        // Check if it actually found a vulnerability
        const finding = analyzeResponse(targetUrl, parameter, currentPayload, responseText, status, chain);
        return { chain, finding, events };
      }

      // ── BLOCKED: Need mutation ────────────────────────────────────
      if (attempt >= maxRetries) {
        // Max retries reached
        chain.status = 'defended';
        chain.mutationReason = `Blocked after ${attempt + 1} attempts (including ${attempt} mutations)`;
        await pushEvent('MAX_RETRIES_REACHED', {
          payload: currentPayload,
          totalAttempts: attempt + 1,
          parameter,
          targetUrl,
        });
        return { chain, events };
      }

      // ── MUTATE ────────────────────────────────────────────────────
      chain.status = 'mutating';
      const errorReason = status === 403 ? 'HTTP 403 Forbidden (WAF block)'
        : status === 406 ? 'HTTP 406 Not Acceptable (content filter)'
        : status === 0 ? 'Connection reset (IPS/firewall)'
        : `HTTP ${status} (filter response)`;

      await pushEvent('MUTATION_START', {
        originalPayload: currentPayload,
        attempt: attempt + 1,
        reason: errorReason,
      });

      // Generate mutation via AI
      const context = `${targetContext}. Tech: ${techStack.join(', ')}. Parameter: ${parameter}`;
      const mutatedPayload = await generateMutation(apiKey, currentPayload, context, errorReason);

      // Validate AI output — handle hallucinations
      if (!mutatedPayload || mutatedPayload.length < 2 || mutatedPayload === currentPayload) {
        // AI hallucinated or returned garbage — count as failed retry
        chain.attempts.push({
          payload: '[AI_HALLUCINATION]',
          status: -1,
          blocked: true,
          response: 'AI returned empty/invalid mutation',
          timestamp: Date.now(),
        });
        await pushEvent('MUTATION_FAIL', {
          reason: 'AI returned invalid mutation',
          attempt: attempt + 1,
        });
        // Use fallback mutation instead
        currentPayload = fallbackMutation(currentPayload);
      } else {
        currentPayload = mutatedPayload;
      }

      chain.currentPayload = currentPayload;

      // ── Randomized delay (2-5s) to evade rate-limiting ────────────
      const delay = 2000 + Math.floor(Math.random() * 3000);
      await new Promise(resolve => setTimeout(resolve, delay));

    } catch (error: any) {
      // Connection error (reset, timeout) — treat as block
      chain.attempts.push({
        payload: currentPayload,
        status: 0,
        blocked: true,
        response: error.message || 'Connection error',
        timestamp: Date.now(),
      });

      if (attempt >= maxRetries) {
        chain.status = 'defended';
        await pushEvent('MAX_RETRIES_REACHED', {
          payload: currentPayload,
          totalAttempts: attempt + 1,
          reason: 'Connection errors',
        });
        return { chain, events };
      }

      // Mutate and retry
      await pushEvent('MUTATION_START', {
        originalPayload: currentPayload,
        attempt: attempt + 1,
        reason: `Connection error: ${error.message}`,
      });

      const context = `${targetContext}. Tech: ${techStack.join(', ')}`;
      currentPayload = await generateMutation(apiKey, currentPayload, context, error.message);
      chain.currentPayload = currentPayload;

      const delay = 2000 + Math.floor(Math.random() * 3000);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  chain.status = 'defended';
  return { chain, events };
}

// ── Fire a single payload against target ──────────────────────────────────────

async function firePayload(
  targetUrl: string,
  parameter: string,
  payload: string,
  method: string
): Promise<{ status: number; responseText: string; blocked: boolean }> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    let response: Response;

    if (method.toUpperCase() === 'GET') {
      const url = new URL(targetUrl);
      url.searchParams.set(parameter, payload);
      response = await fetch(url.toString(), {
        signal: controller.signal,
        headers: { "User-Agent": "OmniSec MutationEngine/1.0" },
      });
    } else {
      const formData = new URLSearchParams();
      formData.set(parameter, payload);
      response = await fetch(targetUrl, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "OmniSec MutationEngine/1.0",
        },
        body: formData.toString(),
      });
    }

    clearTimeout(timeoutId);
    const responseText = await response.text();
    const status = response.status;

    // Determine if blocked
    const blocked = status === 403 || status === 406 || status === 429
      || responseText.toLowerCase().includes('blocked')
      || responseText.toLowerCase().includes('forbidden')
      || responseText.toLowerCase().includes('waf')
      || responseText.toLowerCase().includes('not acceptable');

    return { status, responseText, blocked };

  } catch (error: any) {
    clearTimeout(timeoutId);
    // Connection reset / timeout = blocked by IPS/firewall
    return { status: 0, responseText: error.message || 'Connection failed', blocked: true };
  }
}

// ── Analyze successful response for actual vulnerability ──────────────────────

function analyzeResponse(
  targetUrl: string,
  parameter: string,
  payload: string,
  responseText: string,
  status: number,
  chain: MutationChain
): any | null {
  const lowerBody = responseText.toLowerCase();

  // XSS detection
  if (responseText.includes(payload) || (payload.includes('alert') && responseText.includes('onerror='))) {
    return {
      id: `MUT-XSS-${Date.now()}`,
      severity: 'high',
      title: `Reflected XSS in "${parameter}" [WAF Bypassed${chain.attemptCount > 1 ? ` after ${chain.attemptCount} mutations` : ''}]`,
      description: `Payload reflected after ${chain.attemptCount} attempt(s). Original was blocked, mutated payload bypassed WAF.`,
      endpoint: targetUrl, method: 'GET', payload, owasp: 'A03:2021',
      evidence: `Reflected payload: ${payload}`,
      evidence2: chain.attemptCount > 1 ? `Original "${chain.originalPayload}" blocked → mutated to "${payload}"` : 'First attempt succeeded',
      dualConfirmed: chain.attemptCount > 1,
      remediation: 'Implement output encoding and strict CSP. WAF alone is insufficient.',
      cwe: 'CWE-79', cvss: 6.1, confidence: chain.attemptCount > 1 ? 95 : 85,
      category: 'injection', retryCount: chain.attemptCount,
      mutationChain: chain.attempts.map(a => ({ payload: a.payload, status: a.status, blocked: a.blocked })),
    };
  }

  // SQLi detection
  const sqlErrors = ['sql syntax', 'mysql_fetch', 'pg_query', 'sqlite', 'ora-', 'sql error',
    'syntax error', 'unclosed quotation', 'warning: mysql', 'you have an error'];
  if (sqlErrors.some(e => lowerBody.includes(e))) {
    return {
      id: `MUT-SQLI-${Date.now()}`,
      severity: 'critical',
      title: `SQL Injection in "${parameter}" [WAF Bypassed${chain.attemptCount > 1 ? ` after ${chain.attemptCount} mutations` : ''}]`,
      description: `SQL error triggered after ${chain.attemptCount} attempt(s). Mutated payload evaded filters.`,
      endpoint: targetUrl, method: 'GET', payload, owasp: 'A03:2021',
      evidence: `SQL error in response: ${responseText.slice(0, 200)}`,
      evidence2: chain.attemptCount > 1 ? `Original "${chain.originalPayload}" blocked → mutated` : 'First attempt',
      dualConfirmed: true,
      remediation: 'Use parameterized queries. WAF bypass proves defense-in-depth needed.',
      cwe: 'CWE-89', cvss: 9.8, confidence: 97,
      category: 'injection', retryCount: chain.attemptCount,
      mutationChain: chain.attempts.map(a => ({ payload: a.payload, status: a.status, blocked: a.blocked })),
    };
  }

  // Command injection detection
  if (lowerBody.includes('uid=') || lowerBody.includes('root:') || lowerBody.includes('directory of')) {
    return {
      id: `MUT-CMDI-${Date.now()}`,
      severity: 'critical',
      title: `Command Injection in "${parameter}" [WAF Bypassed]`,
      description: `OS command output returned. Mutated payload evaded WAF.`,
      endpoint: targetUrl, method: 'GET', payload, owasp: 'A03:2021',
      evidence: `Command output: ${responseText.slice(0, 200)}`,
      remediation: 'Never pass user input to OS commands.',
      cwe: 'CWE-78', cvss: 9.8, confidence: 96,
      category: 'injection', retryCount: chain.attemptCount,
    };
  }

  // Path traversal detection
  if (lowerBody.includes('root:x:0:0') || lowerBody.includes('/bin/bash') || lowerBody.includes('[extensions]')) {
    return {
      id: `MUT-TRAV-${Date.now()}`,
      severity: 'critical',
      title: `Path Traversal in "${parameter}" [WAF Bypassed]`,
      description: `Server file content leaked. Mutated encoding bypassed filter.`,
      endpoint: targetUrl, method: 'GET', payload, owasp: 'A01:2021',
      evidence: `File content: ${responseText.slice(0, 200)}`,
      remediation: 'Validate file paths against allowlist.',
      cwe: 'CWE-22', cvss: 9.3, confidence: 97,
      category: 'traversal', retryCount: chain.attemptCount,
    };
  }

  return null;
}
