-- Moderation, blocking and verification tables.
-- Run once in Supabase SQL Editor.

create table if not exists reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null,
  target_type text not null,          -- 'user' | 'post' | 'comment' | 'story'
  target_id text not null,
  reason text default 'other',
  note text default '',
  link text default '',
  status text default 'open',         -- 'open' | 'resolved'
  created_at timestamptz default now()
);
create index if not exists idx_reports_status on reports (status, created_at desc);

create table if not exists blocks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  blocked_id uuid not null,
  created_at timestamptz default now(),
  unique (user_id, blocked_id)
);
create index if not exists idx_blocks_user on blocks (user_id);

create table if not exists hidden_users (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  hidden_id uuid not null,
  created_at timestamptz default now(),
  unique (user_id, hidden_id)
);
create index if not exists idx_hidden_user on hidden_users (user_id);

create table if not exists verification_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  email text default '',
  wiki text default '',
  info text default '',
  status text default 'pending',      -- 'pending' | 'approved' | 'rejected'
  created_at timestamptz default now()
);
create index if not exists idx_verif_status on verification_requests (status, created_at desc);
