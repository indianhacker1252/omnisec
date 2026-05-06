-- Sensitive exploit proof storage (admin-only readable)
CREATE TABLE IF NOT EXISTS public.finding_exploit_proofs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id TEXT,
  scan_id TEXT,
  target_host TEXT,
  vuln_class TEXT NOT NULL,
  exploit_technique TEXT NOT NULL,
  request_dump TEXT,
  response_dump TEXT,
  extracted_data JSONB DEFAULT '{}'::jsonb,
  sensitivity_level TEXT NOT NULL DEFAULT 'sensitive',
  confirmed BOOLEAN NOT NULL DEFAULT false,
  reproduction_steps TEXT,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.finding_exploit_proofs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Admins see all exploit proofs"
  ON public.finding_exploit_proofs FOR SELECT
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "Owners see own exploit proofs"
  ON public.finding_exploit_proofs FOR SELECT
  TO authenticated
  USING (created_by = auth.uid());

CREATE POLICY "Authenticated insert exploit proofs"
  ON public.finding_exploit_proofs FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE INDEX IF NOT EXISTS idx_exploit_proofs_scan ON public.finding_exploit_proofs(scan_id);
CREATE INDEX IF NOT EXISTS idx_exploit_proofs_finding ON public.finding_exploit_proofs(finding_id);
