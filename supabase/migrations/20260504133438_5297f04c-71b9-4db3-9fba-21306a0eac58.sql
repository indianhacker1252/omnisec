-- Enable required extensions for background scan chaining
CREATE EXTENSION IF NOT EXISTS pg_net;
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Track each pass of a multi-pass scan
CREATE TABLE IF NOT EXISTS public.scan_passes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id TEXT NOT NULL,
  pass_number INTEGER NOT NULL,
  pass_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  target TEXT NOT NULL,
  findings_count INTEGER DEFAULT 0,
  payload JSONB DEFAULT '{}'::jsonb,
  error_message TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_passes_scan_id ON public.scan_passes(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_passes_status ON public.scan_passes(status);

ALTER TABLE public.scan_passes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Authenticated read scan_passes" ON public.scan_passes FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert scan_passes" ON public.scan_passes FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update scan_passes" ON public.scan_passes FOR UPDATE TO authenticated USING (true);

-- Stored / second-order canary tracking
CREATE TABLE IF NOT EXISTS public.scan_canaries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id TEXT NOT NULL,
  canary_token TEXT NOT NULL UNIQUE,
  injected_url TEXT NOT NULL,
  injected_param TEXT,
  injected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reflected_url TEXT,
  reflected_at TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_canaries_scan ON public.scan_canaries(scan_id);
CREATE INDEX IF NOT EXISTS idx_canaries_token ON public.scan_canaries(canary_token);

ALTER TABLE public.scan_canaries ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Authenticated read canaries" ON public.scan_canaries FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert canaries" ON public.scan_canaries FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update canaries" ON public.scan_canaries FOR UPDATE TO authenticated USING (true);

-- Captured authenticated sessions for IDOR/BOLA/privesc testing
CREATE TABLE IF NOT EXISTS public.scan_auth_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id TEXT NOT NULL,
  user_label TEXT NOT NULL DEFAULT 'user_a',
  cookies JSONB DEFAULT '{}'::jsonb,
  bearer_token TEXT,
  custom_headers JSONB DEFAULT '{}'::jsonb,
  user_id_observed TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_scan ON public.scan_auth_sessions(scan_id);

ALTER TABLE public.scan_auth_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Authenticated read auth_sessions" ON public.scan_auth_sessions FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert auth_sessions" ON public.scan_auth_sessions FOR INSERT TO authenticated WITH CHECK (true);

-- Nuclei-style exploit template library
CREATE TABLE IF NOT EXISTS public.vapt_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  template_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  category TEXT NOT NULL,
  description TEXT,
  request JSONB NOT NULL,
  matchers JSONB NOT NULL,
  cve_ids TEXT[],
  tags TEXT[],
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_templates_category ON public.vapt_templates(category);
CREATE INDEX IF NOT EXISTS idx_templates_severity ON public.vapt_templates(severity);

ALTER TABLE public.vapt_templates ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Authenticated read templates" ON public.vapt_templates FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert templates" ON public.vapt_templates FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update templates" ON public.vapt_templates FOR UPDATE TO authenticated USING (true);

-- Function that triggers the next pass via pg_net background HTTP call
CREATE OR REPLACE FUNCTION public.chain_next_scan_pass()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  next_pass_number INTEGER;
  next_pass_name TEXT;
  fn_url TEXT;
  fn_endpoint TEXT;
  anon_key TEXT;
BEGIN
  -- Only chain when a pass transitions to 'completed'
  IF NEW.status <> 'completed' OR OLD.status = 'completed' THEN
    RETURN NEW;
  END IF;

  next_pass_number := NEW.pass_number + 1;

  -- Map pass number to logical pass name + edge function
  CASE next_pass_number
    WHEN 2 THEN next_pass_name := 'deep_discovery'; fn_endpoint := 'autonomous-vapt';
    WHEN 3 THEN next_pass_name := 'injection_tests'; fn_endpoint := 'autonomous-vapt';
    WHEN 4 THEN next_pass_name := 'auth_idor_bola'; fn_endpoint := 'vapt-advanced';
    WHEN 5 THEN next_pass_name := 'advanced_classes'; fn_endpoint := 'vapt-advanced';
    WHEN 6 THEN next_pass_name := 'template_intel_poc'; fn_endpoint := 'vapt-intel';
    ELSE RETURN NEW; -- chain done
  END CASE;

  fn_url := 'https://pavwekamqfnymbwujyld.supabase.co/functions/v1/' || fn_endpoint;
  anon_key := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBhdndla2FtcWZueW1id3VqeWxkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE1MjE5ODYsImV4cCI6MjA3NzA5Nzk4Nn0.8T102fUmjVBwRceMP4evVmmMcfhGqkSpntORWQYHz7g';

  -- Insert the next pass row as 'pending'
  INSERT INTO public.scan_passes (scan_id, pass_number, pass_name, status, target, payload)
  VALUES (NEW.scan_id, next_pass_number, next_pass_name, 'pending', NEW.target, NEW.payload);

  -- Fire-and-forget HTTP call to next pass edge function
  PERFORM net.http_post(
    url := fn_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'apikey', anon_key,
      'Authorization', 'Bearer ' || anon_key
    ),
    body := jsonb_build_object(
      'scanId', NEW.scan_id,
      'passNumber', next_pass_number,
      'passName', next_pass_name,
      'target', NEW.target,
      'continuation', true,
      'previousPayload', NEW.payload
    )
  );

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_chain_next_pass ON public.scan_passes;
CREATE TRIGGER trg_chain_next_pass
  AFTER UPDATE ON public.scan_passes
  FOR EACH ROW
  EXECUTE FUNCTION public.chain_next_scan_pass();