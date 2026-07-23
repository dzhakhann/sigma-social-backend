-- SigmaFit: exercise data lives client-side (bundled, no server/CDN cost) —
-- this table only ever gets tiny rows (a completed-session log), no media.
create table if not exists workouts (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references users(id) on delete cascade,
  routine_id text not null,
  duration_seconds int default 0,
  created_at timestamptz default now()
);

create index if not exists workouts_user_idx on workouts(user_id);

alter table workouts enable row level security;
