-- Instagram-style Notes: one short text note per user, visible only to
-- mutual follows, auto-expires after 24h (server sweeps expired rows on
-- every read/write — see sweepExpiredNotes in server.js).
create table if not exists notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  text text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists notes_user_id_idx on notes(user_id);
create index if not exists notes_expires_at_idx on notes(expires_at);
