create policy t1 on storage.objects for all to authenticated using (bucket_id = 'files') with check (bucket_id = 'files');
