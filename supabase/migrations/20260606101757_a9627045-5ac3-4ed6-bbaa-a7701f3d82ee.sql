
-- 1. scan_history
ALTER TABLE public.scan_history ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON public.scan_history(user_id);
DROP POLICY IF EXISTS "Authenticated users can view scan_history" ON public.scan_history;
DROP POLICY IF EXISTS "Authenticated users can insert scan_history" ON public.scan_history;
DROP POLICY IF EXISTS "Authenticated users can update scan_history" ON public.scan_history;
CREATE POLICY "Users view own scan_history" ON public.scan_history FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own scan_history" ON public.scan_history FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "Users update own scan_history" ON public.scan_history FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 2. security_alerts
ALTER TABLE public.security_alerts ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_security_alerts_user_id ON public.security_alerts(user_id);
DROP POLICY IF EXISTS "Authenticated users can view alerts" ON public.security_alerts;
DROP POLICY IF EXISTS "Authenticated users can insert alerts" ON public.security_alerts;
DROP POLICY IF EXISTS "Authenticated users can update alerts" ON public.security_alerts;
CREATE POLICY "Users view own alerts" ON public.security_alerts FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own alerts" ON public.security_alerts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "Users update own alerts" ON public.security_alerts FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 3. security_reports
ALTER TABLE public.security_reports ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_security_reports_user_id ON public.security_reports(user_id);
DROP POLICY IF EXISTS "Authenticated users can view reports" ON public.security_reports;
DROP POLICY IF EXISTS "Authenticated users can insert reports" ON public.security_reports;
CREATE POLICY "Users view own reports" ON public.security_reports FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own reports" ON public.security_reports FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);

-- 4. scan_progress
ALTER TABLE public.scan_progress ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_scan_progress_user_id ON public.scan_progress(user_id);
DROP POLICY IF EXISTS "Authenticated users can view progress" ON public.scan_progress;
DROP POLICY IF EXISTS "Authenticated users can insert progress" ON public.scan_progress;
DROP POLICY IF EXISTS "Authenticated users can update progress" ON public.scan_progress;
DROP POLICY IF EXISTS "Authenticated users can delete progress" ON public.scan_progress;
CREATE POLICY "Users view own progress" ON public.scan_progress FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own progress" ON public.scan_progress FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "Users update own progress" ON public.scan_progress FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users delete own progress" ON public.scan_progress FOR DELETE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 5. recon_findings
ALTER TABLE public.recon_findings ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_recon_findings_user_id ON public.recon_findings(user_id);
DROP POLICY IF EXISTS "Authenticated users can view findings" ON public.recon_findings;
DROP POLICY IF EXISTS "Authenticated users can insert findings" ON public.recon_findings;
DROP POLICY IF EXISTS "Authenticated users can update findings" ON public.recon_findings;
CREATE POLICY "Users view own findings" ON public.recon_findings FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own findings" ON public.recon_findings FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "Users update own findings" ON public.recon_findings FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 6. recon_queue
ALTER TABLE public.recon_queue ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_recon_queue_user_id ON public.recon_queue(user_id);
DROP POLICY IF EXISTS "Authenticated users can view queue" ON public.recon_queue;
DROP POLICY IF EXISTS "Authenticated users can insert queue" ON public.recon_queue;
DROP POLICY IF EXISTS "Authenticated users can update queue" ON public.recon_queue;
DROP POLICY IF EXISTS "Authenticated users can delete queue" ON public.recon_queue;
CREATE POLICY "Users view own queue" ON public.recon_queue FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own queue" ON public.recon_queue FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "Users update own queue" ON public.recon_queue FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users delete own queue" ON public.recon_queue FOR DELETE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 7. scan_passes
ALTER TABLE public.scan_passes ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_scan_passes_user_id ON public.scan_passes(user_id);
DROP POLICY IF EXISTS "Authenticated read scan_passes" ON public.scan_passes;
DROP POLICY IF EXISTS "Authenticated insert scan_passes" ON public.scan_passes;
DROP POLICY IF EXISTS "Authenticated update scan_passes" ON public.scan_passes;
CREATE POLICY "Users view own scan_passes" ON public.scan_passes FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own scan_passes" ON public.scan_passes FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "Users update own scan_passes" ON public.scan_passes FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 8. scan_canaries
ALTER TABLE public.scan_canaries ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_scan_canaries_user_id ON public.scan_canaries(user_id);
DROP POLICY IF EXISTS "Authenticated read canaries" ON public.scan_canaries;
DROP POLICY IF EXISTS "Authenticated insert canaries" ON public.scan_canaries;
DROP POLICY IF EXISTS "Authenticated update canaries" ON public.scan_canaries;
CREATE POLICY "Users view own canaries" ON public.scan_canaries FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own canaries" ON public.scan_canaries FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() OR user_id IS NULL);
CREATE POLICY "Users update own canaries" ON public.scan_canaries FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 9. scan_auth_sessions (bearer tokens — strict)
ALTER TABLE public.scan_auth_sessions ADD COLUMN IF NOT EXISTS user_id uuid DEFAULT auth.uid();
CREATE INDEX IF NOT EXISTS idx_scan_auth_sessions_user_id ON public.scan_auth_sessions(user_id);
DROP POLICY IF EXISTS "Authenticated read auth_sessions" ON public.scan_auth_sessions;
DROP POLICY IF EXISTS "Authenticated insert auth_sessions" ON public.scan_auth_sessions;
CREATE POLICY "Users view own auth_sessions" ON public.scan_auth_sessions FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users insert own auth_sessions" ON public.scan_auth_sessions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Users update own auth_sessions" ON public.scan_auth_sessions FOR UPDATE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin')) WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Users delete own auth_sessions" ON public.scan_auth_sessions FOR DELETE TO authenticated USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- 10. finding_exploit_proofs: insert must be by owner
DROP POLICY IF EXISTS "Authenticated insert exploit proofs" ON public.finding_exploit_proofs;
CREATE POLICY "Users insert own exploit proofs" ON public.finding_exploit_proofs FOR INSERT TO authenticated WITH CHECK (created_by = auth.uid());

-- 11. security_audit_log: authenticated only, own user_id
DROP POLICY IF EXISTS "System can insert logs" ON public.security_audit_log;
CREATE POLICY "Authenticated users insert own logs" ON public.security_audit_log FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());

-- 12. vapt_templates: admin-only writes
DROP POLICY IF EXISTS "Authenticated insert templates" ON public.vapt_templates;
DROP POLICY IF EXISTS "Authenticated update templates" ON public.vapt_templates;
CREATE POLICY "Admins insert templates" ON public.vapt_templates FOR INSERT TO authenticated WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Admins update templates" ON public.vapt_templates FOR UPDATE TO authenticated USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Admins delete templates" ON public.vapt_templates FOR DELETE TO authenticated USING (public.has_role(auth.uid(), 'admin'));

-- 13. Revoke EXECUTE on SECURITY DEFINER helpers from anon/authenticated
REVOKE EXECUTE ON FUNCTION public.has_role(uuid, app_role) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.has_role(uuid, app_role) FROM anon;
REVOKE EXECUTE ON FUNCTION public.has_role(uuid, app_role) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, app_role) TO service_role;

REVOKE EXECUTE ON FUNCTION public.find_similar_vapt_actions(uuid, text, text, text, text, integer) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.find_similar_vapt_actions(uuid, text, text, text, text, integer) FROM anon;
REVOKE EXECUTE ON FUNCTION public.find_similar_vapt_actions(uuid, text, text, text, text, integer) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.find_similar_vapt_actions(uuid, text, text, text, text, integer) TO service_role;

-- 14. Harden has_role: prevent probing other users' roles
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role app_role)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF _user_id IS DISTINCT FROM auth.uid()
     AND auth.uid() IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM public.user_roles
       WHERE user_id = auth.uid() AND role = 'admin'::app_role
     )
  THEN
    RETURN FALSE;
  END IF;

  RETURN EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND role = _role
  );
END;
$$;
