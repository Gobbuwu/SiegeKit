create policy t1 on storage.objects for insert to anon with check (bucket_id = 'files');
create policy t2 on storage.objects for select to anon using (bucket_id = 'files');
