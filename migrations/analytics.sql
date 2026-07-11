-- Story stats + profile analytics tables.
-- Run this once in Supabase: SQL Editor → New query → paste → Run.

create table if not exists story_events (
  id uuid primary key default gen_random_uuid(),
  story_id uuid not null,
  user_id uuid not null,
  type text not null check (type in ('view','like','reply')),
  created_at timestamptz default now(),
  unique (story_id, user_id, type)
);

create table if not exists profile_views (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null,
  viewer_id uuid not null,
  created_at timestamptz default now(),
  unique (profile_id, viewer_id)
);

create index if not exists idx_story_events_story on story_events (story_id);
create index if not exists idx_profile_views_profile on profile_views (profile_id);

-- Daily reward (+5 Aura once a day)
alter table users add column if not exists last_daily date;
