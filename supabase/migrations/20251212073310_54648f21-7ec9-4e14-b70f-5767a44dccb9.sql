-- Create alerts table for real-time security alerts
CREATE TABLE public.security_alerts (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  title TEXT NOT NULL,
  description TEXT,
  source_module TEXT,
  target TEXT,
  is_read BOOLEAN DEFAULT false,
  is_cleared BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  cleared_at TIMESTAMP WITH TIME ZONE
);

-- Create scan history table for all module operations
CREATE TABLE public.scan_history (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  module TEXT NOT NULL,
  scan_type TEXT NOT NULL,
  target TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE,
  duration_ms INTEGER,
  findings_count INTEGER DEFAULT 0,
  report JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create reports table
CREATE TABLE public.security_reports (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID REFERENCES public.scan_history(id),
  module TEXT NOT NULL,
  title TEXT NOT NULL,
  summary TEXT,
  findings JSONB,
  recommendations JSONB,
  severity_counts JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_reports ENABLE ROW LEVEL SECURITY;

-- Public read/write policies (since this is a VAPT tool, not user-specific)
CREATE POLICY "Allow all operations on security_alerts" ON public.security_alerts FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on scan_history" ON public.scan_history FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all operations on security_reports" ON public.security_reports FOR ALL USING (true) WITH CHECK (true);

-- Enable realtime for alerts
ALTER PUBLICATION supabase_realtime ADD TABLE public.security_alerts;
ALTER PUBLICATION supabase_realtime ADD TABLE public.scan_history;