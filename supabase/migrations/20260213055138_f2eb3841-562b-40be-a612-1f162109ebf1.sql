
-- Create table for real-time scan progress updates
CREATE TABLE public.scan_progress (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  phase_number INTEGER NOT NULL DEFAULT 0,
  total_phases INTEGER NOT NULL DEFAULT 10,
  progress INTEGER NOT NULL DEFAULT 0,
  message TEXT,
  findings_so_far INTEGER DEFAULT 0,
  endpoints_discovered INTEGER DEFAULT 0,
  current_endpoint TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.scan_progress ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all operations on scan_progress"
ON public.scan_progress FOR ALL
USING (true)
WITH CHECK (true);

-- Enable realtime for scan_progress
ALTER PUBLICATION supabase_realtime ADD TABLE public.scan_progress;
