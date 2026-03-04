import { supabase } from "@/integrations/supabase/client";

export interface VerificationResult {
  success: boolean;
  verified: boolean;
  evidence?: any;
}

/**
 * Request server-side secondary verification of a finding.
 */
export async function verifyFinding(finding: {
  id: string;
  target_host: string;
  url_path?: string;
  finding_type: string;
  url?: string;
}): Promise<VerificationResult> {
  const { data, error } = await supabase.functions.invoke("recon-orchestrator", {
    body: { action: "verify", finding },
  });

  if (error) {
    console.error("Verification error:", error);
    return { success: false, verified: false };
  }

  return data as VerificationResult;
}

/**
 * Batch verify multiple findings.
 */
export async function verifyFindings(
  findings: Array<{ id: string; target_host: string; url_path?: string; finding_type: string }>
): Promise<VerificationResult[]> {
  return Promise.all(findings.map(verifyFinding));
}
