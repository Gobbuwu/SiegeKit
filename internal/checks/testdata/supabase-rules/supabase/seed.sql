insert into auth.users (id, email, encrypted_password)
values ('00000000-0000-0000-0000-000000000001', 'a@example.com', crypt('password123', gen_salt('bf'))); -- weak-passwords FINDING
