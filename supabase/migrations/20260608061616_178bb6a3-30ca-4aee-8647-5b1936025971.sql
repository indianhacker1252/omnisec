
create extension if not exists pg_cron;
create extension if not exists pg_net;

create table if not exists public.scan_jobs (
  id            uuid primary key default gen_random_uuid(),
  scan_id       uuid not null,
  user_id       uuid default auth.uid(),
  detector      text not null,
  target        text not null,
  params        jsonb not null default '{}'::jsonb,
  status        text not null default 'pending'
                check (status in ('pending','running','completed','failed','requeued')),
  priority      int not null default 100,
  attempts      int not null default 0,
  max_attempts  int not null default 2,
  result        jsonb,
  error         text,
  locked_by     text,
  locked_at     timestamptz,
  started_at    timestamptz,
  completed_at  timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create index if not exists scan_jobs_scan_id_idx     on public.scan_jobs(scan_id);
create index if not exists scan_jobs_status_prio_idx on public.scan_jobs(status, priority, created_at);
create index if not exists scan_jobs_watchdog_idx    on public.scan_jobs(status, locked_at);

grant select, insert, update, delete on public.scan_jobs to authenticated;
grant all on public.scan_jobs to service_role;
alter table public.scan_jobs enable row level security;

create policy "scan_jobs owner read"   on public.scan_jobs for select to authenticated
  using (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));
create policy "scan_jobs owner write"  on public.scan_jobs for insert to authenticated
  with check (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));
create policy "scan_jobs owner update" on public.scan_jobs for update to authenticated
  using (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));
create policy "scan_jobs owner delete" on public.scan_jobs for delete to authenticated
  using (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));

create table if not exists public.planner_decisions (
  id           uuid primary key default gen_random_uuid(),
  scan_id      uuid not null,
  user_id      uuid default auth.uid(),
  step         int  not null default 0,
  decision     text not null,
  rationale    text,
  tool_call    jsonb,
  tool_result  jsonb,
  created_at   timestamptz not null default now()
);

create index if not exists planner_decisions_scan_idx on public.planner_decisions(scan_id, created_at);

grant select, insert on public.planner_decisions to authenticated;
grant all on public.planner_decisions to service_role;
alter table public.planner_decisions enable row level security;

create policy "planner_decisions owner read"  on public.planner_decisions for select to authenticated
  using (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));
create policy "planner_decisions owner write" on public.planner_decisions for insert to authenticated
  with check (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));

do $$ begin
  perform 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='scan_jobs';
  if not found then execute 'alter publication supabase_realtime add table public.scan_jobs'; end if;
  perform 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='planner_decisions';
  if not found then execute 'alter publication supabase_realtime add table public.planner_decisions'; end if;
end $$;

create or replace function public.claim_next_scan_job(p_worker text, p_batch int default 1)
returns setof public.scan_jobs
language plpgsql
security definer
set search_path = public
as $fn$
begin
  return query
  update public.scan_jobs sj
     set status     = 'running',
         locked_by  = p_worker,
         locked_at  = now(),
         started_at = coalesce(sj.started_at, now()),
         attempts   = sj.attempts + 1,
         updated_at = now()
   where sj.id in (
     select id from public.scan_jobs
      where status in ('pending','requeued')
      order by priority asc, created_at asc
      for update skip locked
      limit p_batch
   )
   returning sj.*;
end $fn$;

revoke all on function public.claim_next_scan_job(text, int) from public, anon, authenticated;
grant execute on function public.claim_next_scan_job(text, int) to service_role;

create or replace function public.requeue_stale_scan_jobs()
returns int
language plpgsql
security definer
set search_path = public
as $fn$
declare n int;
begin
  with stale as (
    update public.scan_jobs
       set status = case when attempts >= max_attempts then 'failed' else 'requeued' end,
           error  = coalesce(error, 'watchdog: worker timed out'),
           locked_by = null,
           locked_at = null,
           updated_at = now()
     where status = 'running'
       and locked_at < now() - interval '180 seconds'
     returning 1
  )
  select count(*) into n from stale;
  return n;
end $fn$;

revoke all on function public.requeue_stale_scan_jobs() from public, anon, authenticated;
grant execute on function public.requeue_stale_scan_jobs() to service_role;

do $$ begin
  perform cron.unschedule('omnisec-scan-worker');
exception when others then null; end $$;
do $$ begin
  perform cron.unschedule('omnisec-scan-watchdog');
exception when others then null; end $$;

select cron.schedule(
  'omnisec-scan-worker',
  '*/1 * * * *',
  $cron$
    select net.http_post(
      url := 'https://pavwekamqfnymbwujyld.supabase.co/functions/v1/scan-worker',
      headers := '{"Content-Type":"application/json","apikey":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBhdndla2FtcWZueW1id3VqeWxkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE1MjE5ODYsImV4cCI6MjA3NzA5Nzk4Nn0.8T102fUmjVBwRceMP4evVmmMcfhGqkSpntORWQYHz7g","Authorization":"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBhdndla2FtcWZueW1id3VqeWxkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE1MjE5ODYsImV4cCI6MjA3NzA5Nzk4Nn0.8T102fUmjVBwRceMP4evVmmMcfhGqkSpntORWQYHz7g"}'::jsonb,
      body := '{"trigger":"cron"}'::jsonb
    );
  $cron$
);

select cron.schedule(
  'omnisec-scan-watchdog',
  '*/1 * * * *',
  $cron$ select public.requeue_stale_scan_jobs(); $cron$
);
