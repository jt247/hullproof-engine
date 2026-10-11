-- Notes: owned by one user.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null,
  title text not null
);
grant select on public.notes to anon;

create table public.profiles (
  id uuid primary key,
  display_name text,
  role text not null default 'member',
  plan text not null default 'free'
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select to authenticated using (auth.uid() = id);
grant update on public.profiles to authenticated;

create table public.docs (
  id uuid primary key,
  owner_id uuid not null,
  body text
);
alter table public.docs enable row level security;
create policy "everyone reads" on public.docs for select to anon using (true);
create policy "meta admin" on public.docs for update to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
