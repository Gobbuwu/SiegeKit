create policy t1 on storage.objects for insert to anon with check (bucket_id = 'files');
