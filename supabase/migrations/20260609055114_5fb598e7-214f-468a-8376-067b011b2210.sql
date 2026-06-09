
CREATE TABLE public.target_context (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL,
  user_id UUID DEFAULT auth.uid(),
  target_host TEXT NOT NULL,
  tech_stack JSONB NOT NULL DEFAULT '[]'::jsonb,
  web_server TEXT,
  frameworks JSONB NOT NULL DEFAULT '[]'::jsonb,
  waf TEXT,
  auth_model TEXT,
  endpoints JSONB NOT NULL DEFAULT '[]'::jsonb,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX target_context_scan_idx ON public.target_context(scan_id);
CREATE INDEX target_context_host_idx ON public.target_context(target_host);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.target_context TO authenticated;
GRANT ALL ON public.target_context TO service_role;

ALTER TABLE public.target_context ENABLE ROW LEVEL SECURITY;
CREATE POLICY "target_context owner read"   ON public.target_context FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(),'admin'::app_role));
CREATE POLICY "target_context owner write"  ON public.target_context FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "target_context owner update" ON public.target_context FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(),'admin'::app_role));
CREATE POLICY "target_context owner delete" ON public.target_context FOR DELETE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(),'admin'::app_role));

CREATE TABLE public.kg_exploit_outcomes (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID DEFAULT auth.uid(),
  target_host TEXT NOT NULL,
  tech_tag TEXT,
  detector TEXT NOT NULL,
  payload_class TEXT,
  success BOOLEAN NOT NULL DEFAULT false,
  severity TEXT,
  signal JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX kg_outcomes_host_idx     ON public.kg_exploit_outcomes(target_host);
CREATE INDEX kg_outcomes_tech_idx     ON public.kg_exploit_outcomes(tech_tag);
CREATE INDEX kg_outcomes_detector_idx ON public.kg_exploit_outcomes(detector);

GRANT SELECT, INSERT ON public.kg_exploit_outcomes TO authenticated;
GRANT ALL ON public.kg_exploit_outcomes TO service_role;

ALTER TABLE public.kg_exploit_outcomes ENABLE ROW LEVEL SECURITY;
-- Owners see their full rows
CREATE POLICY "kg_outcomes owner read"  ON public.kg_exploit_outcomes FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(),'admin'::app_role));
-- Authenticated users can read anonymized aggregate rows (no user_id leak) by querying with user_id IS NULL filter — we expose a SECURITY DEFINER view-like RPC instead
CREATE POLICY "kg_outcomes owner write" ON public.kg_exploit_outcomes FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);

CREATE OR REPLACE FUNCTION public.kg_top_exploits(p_tech TEXT, p_limit INT DEFAULT 10)
RETURNS TABLE(detector TEXT, payload_class TEXT, success_count BIGINT, total_count BIGINT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT detector, payload_class,
         SUM(CASE WHEN success THEN 1 ELSE 0 END)::BIGINT AS success_count,
         COUNT(*)::BIGINT AS total_count
  FROM public.kg_exploit_outcomes
  WHERE tech_tag = p_tech
  GROUP BY detector, payload_class
  ORDER BY success_count DESC, total_count DESC
  LIMIT p_limit;
$$;
GRANT EXECUTE ON FUNCTION public.kg_top_exploits(TEXT, INT) TO authenticated;

CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;
CREATE TRIGGER update_target_context_updated_at BEFORE UPDATE ON public.target_context
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
