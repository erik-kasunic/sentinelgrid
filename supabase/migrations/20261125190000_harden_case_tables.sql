-- Hardening for direct PostgREST access. Signed-in users can call the Supabase API
-- directly with their own session, bypassing the server functions and their checks,
-- so the limits below live in the database itself.

-- 1. Size limits on saved cases.
alter table public.investigations
  add constraint investigations_result_size check (pg_column_size(result) < 524288),
  add constraint investigations_title_len check (char_length(title) <= 200),
  add constraint investigations_target_len check (char_length(initial_target) <= 2048);

-- 2. Per-user quota: at most 30 new cases per minute and 2000 in total.
create or replace function public.limit_investigations()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if (select count(*) from investigations
      where user_id = new.user_id and created_at > now() - interval '1 minute') >= 30 then
    raise exception 'rate limit' using errcode = 'P0001';
  end if;
  if (select count(*) from investigations where user_id = new.user_id) >= 2000 then
    raise exception 'case quota reached' using errcode = 'P0001';
  end if;
  return new;
end;
$$;
revoke all on function public.limit_investigations() from public, anon, authenticated;

drop trigger if exists investigations_limit on public.investigations;
create trigger investigations_limit before insert on public.investigations
  for each row execute function public.limit_investigations();

-- 3. Child rows may only point at the caller's own case (prevents IDOR writes).
do $$
declare t text;
begin
  foreach t in array array['investigation_iocs', 'evidence', 'relationships', 'provider_results'] loop
    execute format('drop policy if exists %I on public.%I', t || '_own', t);
    execute format(
      $p$create policy %I on public.%I for all to authenticated
        using (auth.uid() = user_id)
        with check (auth.uid() = user_id and exists (
          select 1 from public.investigations i
          where i.id = investigation_id and i.user_id = auth.uid()))$p$,
      t || '_own', t);
  end loop;
end $$;

-- 4. A case may only be filed in the caller's own folder.
drop policy if exists investigations_own on public.investigations;
create policy investigations_own on public.investigations for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id and (folder_id is null or exists (
    select 1 from public.case_folders f where f.id = folder_id and f.user_id = auth.uid())));
