-- Goal duels: challenge a friend, race to 100% on the same named goal.
-- Each side tracks its OWN progress independently (no shared state to fight
-- over) — first to reach 100 wins. Deliberately reuses the goals categories
-- rather than a new taxonomy.
create table if not exists duels (
  id uuid default gen_random_uuid() primary key,
  challenger_id uuid references users(id) on delete cascade,
  opponent_id uuid references users(id) on delete cascade,
  title text not null,
  category text default 'personal',
  status text default 'pending', -- pending | active | declined | completed | cancelled
  challenger_progress int default 0,
  opponent_progress int default 0,
  winner_id uuid references users(id) on delete set null,
  created_at timestamptz default now(),
  completed_at timestamptz
);

create index if not exists duels_challenger_idx on duels(challenger_id);
create index if not exists duels_opponent_idx on duels(opponent_id);

alter table duels enable row level security;
