
-- Recon findings table with hash-based deduplication
CREATE TABLE public.recon_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  hash_signature text NOT NULL UNIQUE,
  target_host text NOT NULL,
  url_path text,
  vulnerable_parameter text,
  finding_type text NOT NULL,
  title text NOT NULL,
  description text,
  severity text NOT NULL DEFAULT 'info',
  verification_status text NOT NULL DEFAULT 'pending',
  confidence_score integer DEFAULT 0,
  evidence jsonb,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  seen_count integer NOT NULL DEFAULT 1,
  source_module text,
  raw_data jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Recon queue table for pipeline management
CREATE TABLE public.recon_queue (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  domain text NOT NULL,
  subdomain text NOT NULL,
  ip_address text,
  status text NOT NULL DEFAULT 'pending',
  scan_phase text DEFAULT 'discovered',
  parent_domain text,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  error_message text,
  UNIQUE(subdomain)
);

-- Enable RLS
ALTER TABLE public.recon_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recon_queue ENABLE ROW LEVEL SECURITY;

-- RLS policies for recon_findings
CREATE POLICY "Authenticated users can view findings" ON public.recon_findings FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated users can insert findings" ON public.recon_findings FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated users can update findings" ON public.recon_findings FOR UPDATE TO authenticated USING (true);

-- RLS policies for recon_queue
CREATE POLICY "Authenticated users can view queue" ON public.recon_queue FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated users can insert queue" ON public.recon_queue FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated users can update queue" ON public.recon_queue FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Authenticated users can delete queue" ON public.recon_queue FOR DELETE TO authenticated USING (true);

-- Index for fast hash lookups
CREATE INDEX idx_recon_findings_hash ON public.recon_findings(hash_signature);
CREATE INDEX idx_recon_queue_status ON public.recon_queue(status);
CREATE INDEX idx_recon_queue_domain ON public.recon_queue(domain);

-- Enable realtime for queue monitoring
ALTER PUBLICATION supabase_realtime ADD TABLE public.recon_queue;
ALTER PUBLICATION supabase_realtime ADD TABLE public.recon_findings;
