CREATE OR REPLACE FUNCTION public.chain_next_scan_pass()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  next_pass_number INTEGER;
  next_pass_name TEXT;
  fn_url TEXT;
  fn_endpoint TEXT;
  anon_key TEXT;
BEGIN
  IF NEW.status <> 'completed' OR OLD.status = 'completed' THEN
    RETURN NEW;
  END IF;

  next_pass_number := NEW.pass_number + 1;

  CASE next_pass_number
    WHEN 2  THEN next_pass_name := 'deep_validation';      fn_endpoint := 'autonomous-vapt';
    WHEN 3  THEN next_pass_name := 'contextual_injection'; fn_endpoint := 'autonomous-vapt';
    WHEN 4  THEN next_pass_name := 'auth_idor_bola';       fn_endpoint := 'vapt-advanced';
    WHEN 5  THEN next_pass_name := 'advanced_classes';     fn_endpoint := 'vapt-advanced';
    WHEN 6  THEN next_pass_name := 'template_intel_poc';   fn_endpoint := 'vapt-intel';
    WHEN 7  THEN next_pass_name := 'graphql_scan';         fn_endpoint := 'vapt-graphql';
    WHEN 8  THEN next_pass_name := 'oauth_scan';           fn_endpoint := 'vapt-oauth';
    WHEN 9  THEN next_pass_name := 'bopla_scan';           fn_endpoint := 'vapt-bopla';
    WHEN 10 THEN next_pass_name := 'port_service_scan';    fn_endpoint := 'vapt-portscan';
    WHEN 11 THEN next_pass_name := 'waf_bypass';           fn_endpoint := 'vapt-waf-bypass';
    WHEN 12 THEN next_pass_name := 'vapt_chains';          fn_endpoint := 'vapt-chains';
    ELSE RETURN NEW;
  END CASE;

  fn_url := 'https://pavwekamqfnymbwujyld.supabase.co/functions/v1/' || fn_endpoint;
  anon_key := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBhdndla2FtcWZueW1id3VqeWxkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE1MjE5ODYsImV4cCI6MjA3NzA5Nzk4Nn0.8T102fUmjVBwRceMP4evVmmMcfhGqkSpntORWQYHz7g';

  INSERT INTO public.scan_passes (scan_id, pass_number, pass_name, status, target, payload, user_id)
  VALUES (NEW.scan_id, next_pass_number, next_pass_name, 'pending', NEW.target, NEW.payload, NEW.user_id)
  ON CONFLICT DO NOTHING;

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
      'targetUrl', NEW.target,
      'continuation', true,
      'userId', NEW.user_id,
      'previousPayload', NEW.payload
    )
  );

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_chain_next_pass ON public.scan_passes;
DROP TRIGGER IF EXISTS chain_next_scan_pass_trigger ON public.scan_passes;
CREATE TRIGGER chain_next_scan_pass_trigger
AFTER UPDATE ON public.scan_passes
FOR EACH ROW EXECUTE FUNCTION public.chain_next_scan_pass();