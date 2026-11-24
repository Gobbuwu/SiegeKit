create policy t1 on storage.objects for insert to anon with check (bucket_id = 'files');
create policy t2 on storage.objects for delete to anon using (bucket_id = 'files' and coalesce((metadata->>'size')::bigint, 0) < 5242880);
