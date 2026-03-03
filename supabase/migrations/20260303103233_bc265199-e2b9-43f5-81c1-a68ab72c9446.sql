
-- Drop overly permissive policies on security_alerts
DROP POLICY IF EXISTS "Allow all operations on security_alerts" ON public.security_alerts;

-- Drop overly permissive policies on scan_history
DROP POLICY IF EXISTS "Allow all operations on scan_history" ON public.scan_history;

-- Drop overly permissive policies on security_reports
DROP POLICY IF EXISTS "Allow all operations on security_reports" ON public.security_reports;

-- Drop overly permissive policies on scan_progress
DROP POLICY IF EXISTS "Allow all operations on scan_progress" ON public.scan_progress;

-- security_alerts: authenticated users can read, authenticated can insert (from edge functions acting as user)
CREATE POLICY "Authenticated users can view alerts"
ON public.security_alerts FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Authenticated users can insert alerts"
ON public.security_alerts FOR INSERT TO authenticated
WITH CHECK (true);

CREATE POLICY "Authenticated users can update alerts"
ON public.security_alerts FOR UPDATE TO authenticated
USING (true);

-- scan_history: authenticated users can read and write
CREATE POLICY "Authenticated users can view scan_history"
ON public.scan_history FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Authenticated users can insert scan_history"
ON public.scan_history FOR INSERT TO authenticated
WITH CHECK (true);

CREATE POLICY "Authenticated users can update scan_history"
ON public.scan_history FOR UPDATE TO authenticated
USING (true);

-- security_reports: authenticated users can read and write
CREATE POLICY "Authenticated users can view reports"
ON public.security_reports FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Authenticated users can insert reports"
ON public.security_reports FOR INSERT TO authenticated
WITH CHECK (true);

-- scan_progress: authenticated users can read and write
CREATE POLICY "Authenticated users can view progress"
ON public.scan_progress FOR SELECT TO authenticated
USING (true);

CREATE POLICY "Authenticated users can insert progress"
ON public.scan_progress FOR INSERT TO authenticated
WITH CHECK (true);

CREATE POLICY "Authenticated users can update progress"
ON public.scan_progress FOR UPDATE TO authenticated
USING (true);

CREATE POLICY "Authenticated users can delete progress"
ON public.scan_progress FOR DELETE TO authenticated
USING (true);
