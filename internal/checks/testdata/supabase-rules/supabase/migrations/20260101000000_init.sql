-- Known answers for backend-rules' Supabase SQL rules (ADR 0064). Each
-- statement's comment says what it must give; the cases rebuild the planted
-- migration of the Porchlet M0 run (2026-11-23) and add the rest of the
-- rule list. Checked against PostgreSQL 16 and Supabase's linter (splinter).
create table public.clients (id uuid primary key, name text); -- FINDING supabase-table-without-rls high
create table public."Invoices" (id int);
alter table public."Invoices" enable row level security; -- negative control
create table public.notes (id int, owner uuid);
alter table notes enable row level security;
create policy "owner reads" on notes for select to authenticated using (owner = auth.uid()); -- negative
create table public.posts (id int);
alter table public.posts enable row level security;
create table public.leads (id int, email text);
alter table public.leads enable row level security;
create table public.gone (id int);
create table public.hidden (id int);
create table public.renamed_from (id int); -- FINDING supabase-table-without-rls high (as renamed_to)
create table private.audit (id int); -- other schema: not exposed
