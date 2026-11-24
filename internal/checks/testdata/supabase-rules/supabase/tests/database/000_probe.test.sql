begin;
create table public.zz_probe (id int); -- negative: pgTAP test, never deployed (SK-4)
rollback;
