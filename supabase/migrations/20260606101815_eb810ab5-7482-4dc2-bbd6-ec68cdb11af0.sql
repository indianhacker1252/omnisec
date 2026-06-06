
-- has_role MUST be executable by authenticated because RLS policies invoke it.
-- Revoking EXECUTE breaks every policy that calls has_role(auth.uid(), 'admin').
GRANT EXECUTE ON FUNCTION public.has_role(uuid, app_role) TO authenticated, anon;
