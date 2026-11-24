alter table public.notes disable row level security; -- FINDING supabase-rls-disabled high
create policy "anyone reads posts" on public.posts for select using (true); -- FINDING supabase-policy-always-true low
grant select on public.posts to anon;
create policy "anyone adds leads" on leads for insert to anon with check (true); -- FINDING supabase-policy-always-true critical
create policy "users edit any lead" on leads for update to authenticated using (true); -- FINDING supabase-policy-always-true high
create policy "restrict leads" on leads as restrictive for all using (true); -- negative: restrictive
create policy "update without using" on leads for update to anon with check (true); -- negative: no USING lets nothing through
create policy "staff only" on leads for delete to service_role using (true); -- negative: not an API role
create view public.v_clients as select * from public.clients; -- FINDING supabase-view-bypasses-rls high
create view public.v_invoices as select * from public."Invoices"; -- FINDING supabase-view-bypasses-rls high (RLS on "Invoices" does not apply)
create view public.v_safe with (security_invoker = true) as select * from public."Invoices"; -- negative
create or replace view public.v_replaced with (security_invoker = on) as select 1 as x;
create or replace view public.v_replaced as select 2 as x; -- FINDING supabase-view-bypasses-rls high (replace drops the option)
create view public.v_fixed as select 1 as x;
alter view public.v_fixed set (security_invoker = true); -- negative
create materialized view public.mv_totals as select count(*) from public.posts; -- FINDING supabase-materialized-view-exposed medium
drop table if exists public.gone; -- negative
revoke all on public.hidden from anon, authenticated; -- negative: not reachable
alter table renamed_from rename to renamed_to;
do $$
begin
  create policy "do block delete" on public.posts for delete to anon using ((true)); -- FINDING supabase-policy-always-true critical
end
$$;
create policy "dropped later" on public.posts for insert with check (true);
drop policy "dropped later" on public.posts; -- negative
create policy "anyone uploads" on storage.objects for insert with check (bucket_id = 'avatars'); -- FINDING supabase-storage-policy-open critical
create policy "owner uploads" on storage.objects for insert to authenticated with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid()::text)); -- negative
create policy "public avatars" on storage.objects for select using (bucket_id = 'avatars'); -- negative: public read of a bucket
