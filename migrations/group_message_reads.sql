-- Real read receipts for group messages.
--
-- Until now "who has seen this" was DERIVED from the delivery queue:
-- current members minus pending_acks minus the sender. That answers "whose
-- phone downloaded it", not "who opened the chat" — which is why the seen-by
-- sheet listed effectively everyone. Delivery and reading are different events
-- and need different storage.
--
-- Kept in its own table rather than as a jsonb column on group_messages for two
-- reasons: the row is deleted once fully acked (see group_message_grace.sql), and
-- a per-user timestamp is exactly a relational fact — "Иван read it at 20:54".
create table if not exists group_message_reads (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null,
  message_id uuid not null,
  user_id uuid not null,
  read_at timestamptz default now()
);

-- One receipt per person per message. Enforced in the database so a retry or
-- two devices opening at once can't produce duplicates the client would have to
-- de-duplicate.
create unique index if not exists idx_gmr_once
  on group_message_reads (message_id, user_id);

-- The seen-by sheet asks "who read THIS message".
create index if not exists idx_gmr_message
  on group_message_reads (message_id);

-- Survives the message row. Receipts outlive the group_messages row on purpose:
-- a message stops being queued long before people stop looking at the chat, and
-- the sender should still be able to see who read it.
create index if not exists idx_gmr_group
  on group_message_reads (group_id, read_at desc);
