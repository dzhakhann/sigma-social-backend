-- Telegram-style open/closed group chats.
create table if not exists groups (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text default '',
  avatar_url text,
  is_open boolean not null default false,
  creator_id uuid not null references users(id) on delete cascade,
  last_message text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists group_members (
  group_id uuid not null references groups(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  role text not null default 'member', -- 'admin' | 'member'
  joined_at timestamptz not null default now(),
  primary key (group_id, user_id)
);
create index if not exists group_members_user_idx on group_members(user_id);

-- Same device-stored-history model as 1:1 messages, extended to N members:
-- pending_acks holds the member ids that still haven't picked up this
-- message; the row is deleted only once that list empties (see
-- POST /api/groups/:id/messages/ack in server.js), instead of a single ack
-- deleting it like in 1:1 chat.
create table if not exists group_messages (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references groups(id) on delete cascade,
  sender_id uuid not null references users(id) on delete cascade,
  content text default '',
  message_type text not null default 'text',
  media_url text,
  reply_to jsonb,
  pending_acks jsonb not null default '[]'::jsonb,
  is_edited boolean default false,
  created_at timestamptz not null default now()
);
create index if not exists group_messages_group_idx on group_messages(group_id);

-- New tables default to RLS OFF (publicly readable/writable via the REST API)
-- — enable it immediately, same as migrations/enable_rls.sql did for every
-- other table. The backend uses the service_role key everywhere and bypasses
-- RLS, so this has no functional effect on the app.
alter table groups enable row level security;
alter table group_members enable row level security;
alter table group_messages enable row level security;
