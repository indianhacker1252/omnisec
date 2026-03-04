import { supabase } from "@/integrations/supabase/client";

export interface SubdomainEntry {
  subdomain: string;
  ip?: string;
}

export interface EnumerationResult {
  success: boolean;
  domain: string;
  subdomains: SubdomainEntry[];
  total: number;
  queuedForScanning: number;
}

export interface QueueStatus {
  pending: number;
  scanning: number;
  completed: number;
  failed: number;
  total: number;
}

/**
 * Start recursive subdomain enumeration and queue all verified subdomains.
 */
export async function enumerateAndQueue(domain: string): Promise<EnumerationResult> {
  const { data, error } = await supabase.functions.invoke("recon-orchestrator", {
    body: { action: "enumerate", domain },
  });

  if (error) throw new Error(error.message || "Enumeration failed");
  return data as EnumerationResult;
}

/**
 * Get the current state of the recon queue.
 */
export async function getQueueStatus(): Promise<QueueStatus> {
  const { data, error } = await supabase
    .from("recon_queue")
    .select("status");

  if (error) throw error;

  const counts: Record<string, number> = { pending: 0, scanning: 0, completed: 0, failed: 0 };
  (data || []).forEach((item: any) => {
    counts[item.status] = (counts[item.status] || 0) + 1;
  });

  return {
    ...counts,
    total: (data || []).length,
  } as QueueStatus;
}

/**
 * Get all queue items for a domain.
 */
export async function getQueueItems(domain?: string) {
  let query = supabase
    .from("recon_queue")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(200);

  if (domain) {
    query = query.eq("domain", domain);
  }

  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

/**
 * Get all deduplicated findings, optionally filtered.
 */
export async function getFindings(filters?: { severity?: string; verification_status?: string }) {
  let query = supabase
    .from("recon_findings")
    .select("*")
    .order("last_seen", { ascending: false })
    .limit(200);

  if (filters?.severity) query = query.eq("severity", filters.severity);
  if (filters?.verification_status) query = query.eq("verification_status", filters.verification_status);

  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

/**
 * Clear the queue for a domain.
 */
export async function clearQueue(domain?: string) {
  let query = supabase.from("recon_queue").delete();
  if (domain) {
    query = query.eq("domain", domain);
  } else {
    query = query.neq("status", "__never__"); // delete all
  }
  await query;
}
