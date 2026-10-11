-- Notes: owned by one user.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text not null
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
grant select, insert, update, delete on public.notes to authenticated;

create table public.profiles (
  id uuid primary key,
  display_name text,
  role text not null default 'member',
  plan text not null default 'free'
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select to authenticated using (auth.uid() = id);
grant update (display_name) on public.profiles to authenticated;

create table public.docs (
  id uuid primary key,
  owner_id uuid not null,
  body text
);
alter table public.docs enable row level security;
create policy "owner reads" on public.docs for select to authenticated using (auth.uid() = owner_id);
create policy "app admin" on public.docs for update to authenticated using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
