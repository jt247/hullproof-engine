create table public.notes (id uuid primary key);
alter table public.notes enable row level security;
create table files (id uuid primary key);
alter table "public"."files" enable row level security;
create table private.audit (id uuid);
