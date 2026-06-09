// OmniSec™ © HARSH MALIK
// scan-worker — durable queue consumer. Claims one job at a time, dispatches
// the named detector edge function with the job params, and records the
// result. Loops for ~45s per invocation; pg_cron re-invokes every minute.

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPA_URL = Deno.env.get("SUPABASE_URL")!;
const SRV_KEY  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const ANON     = Deno.env.get("SUPABASE_ANON_KEY")!;

// Detector → edge function endpoint mapping
const DETECTOR_ROUTES: Record<string, string> = {
  "recon":            "recon-orchestrator",
  "autonomous-vapt":  "autonomous-vapt",
  "vapt-advanced":    "vapt-advanced",
  "vapt-intel":       "vapt-intel",
  "vapt-graphql":     "vapt-graphql",
  "vapt-oauth":       "vapt-oauth",
  "vapt-bopla":       "vapt-bopla",
  "vapt-portscan":    "vapt-portscan",
  "vapt-waf-bypass":  "vapt-waf-bypass",
  "vapt-chains":      "vapt-chains",
  "verify-finding":   "verify-finding",
  "payload-generator":"payload-generator",
};

async function dispatch(detector: string, body: any, signal: AbortSignal) {
  const fn = DETECTOR_ROUTES[detector] ?? detector;
  const res = await fetch(`${SUPA_URL}/functions/v1/${fn}`, {
    method: "POST",
    signal,
    headers: {
      "Content-Type": "application/json",
      "apikey": ANON,
      "Authorization": `Bearer ${SRV_KEY}`,
      "x-internal-worker": "1",
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json: any = null; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { ok: res.ok, status: res.status, json };
}

async function processOne(supa: any, worker: string): Promise<boolean> {
  const { data: claimed, error: claimErr } = await supa.rpc("claim_next_scan_job", {
    p_worker: worker, p_batch: 1,
  });
  if (claimErr) { console.error("claim error", claimErr); return false; }
  const job = (claimed ?? [])[0];
  if (!job) return false;

  console.log(`[worker] picked ${job.id} detector=${job.detector} scan=${job.scan_id}`);
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 130_000); // < edge 150s limit
  try {
    const body = {
      scanId: job.scan_id, scan_id: job.scan_id,
      target: job.target, targetUrl: job.target,
      userId: job.user_id, jobId: job.id,
      ...(job.params ?? {}),
    };
    const r = await dispatch(job.detector, body, ctrl.signal);
    await supa.from("scan_jobs").update({
      status: r.ok ? "completed" : (job.attempts >= job.max_attempts ? "failed" : "requeued"),
      result: r.json, error: r.ok ? null : `HTTP ${r.status}`,
      completed_at: new Date().toISOString(),
      locked_by: null, locked_at: null, updated_at: new Date().toISOString(),
    }).eq("id", job.id);
  } catch (e: any) {
    console.error(`[worker] job ${job.id} failed`, e);
    await supa.from("scan_jobs").update({
      status: job.attempts >= job.max_attempts ? "failed" : "requeued",
      error: String(e?.message ?? e),
      locked_by: null, locked_at: null, updated_at: new Date().toISOString(),
    }).eq("id", job.id);
  } finally {
    clearTimeout(timeout);
  }
  return true;
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  const supa = createClient(SUPA_URL, SRV_KEY);
  const worker = `w-${crypto.randomUUID().slice(0, 8)}`;
  const deadline = Date.now() + 45_000;
  let processed = 0;
  while (Date.now() < deadline) {
    const got = await processOne(supa, worker);
    if (!got) { await new Promise(r => setTimeout(r, 2500)); continue; }
    processed++;
  }
  return new Response(JSON.stringify({ worker, processed }), {
    headers: { ...cors, "Content-Type": "application/json" },
  });
});
