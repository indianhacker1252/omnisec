import { supabase } from "@/integrations/supabase/client";

export interface RawFinding {
  target_host: string;
  url_path?: string;
  vulnerable_parameter?: string;
  finding_type: string;
  title: string;
  description?: string;
  severity?: string;
  source_module?: string;
  raw_data?: any;
}

export interface NormalizeResult {
  success: boolean;
  deduplicated: boolean;
  hash?: string;
  finding?: any;
  existingId?: string;
}

/**
 * Generates a client-side hash for quick local dedup checks.
 */
export function generateFindingHash(
  host: string,
  path: string,
  param: string,
  type: string
): string {
  const raw = `${host}|${path || ""}|${param || ""}|${type}`.toLowerCase();
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    const char = raw.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36) + "-" + raw.length.toString(36);
}

/**
 * Send a finding through the normalization pipeline (server-side dedup).
 */
export async function normalizeFinding(finding: RawFinding): Promise<NormalizeResult> {
  const { data, error } = await supabase.functions.invoke("recon-orchestrator", {
    body: { action: "normalize", finding },
  });

  if (error) {
    console.error("Normalization error:", error);
    return { success: false, deduplicated: false };
  }

  return data as NormalizeResult;
}

/**
 * Batch normalize multiple findings.
 */
export async function normalizeFindings(findings: RawFinding[]): Promise<NormalizeResult[]> {
  const results = await Promise.all(findings.map(normalizeFinding));
  return results;
}
