-- Chat list ordering (Telegram-style: most recently active first). Without
-- this the chat list had no ordering column at all and came back in
-- arbitrary/insertion order, so new conversations didn't bubble to the top.
alter table chats add column if not exists updated_at timestamptz;

-- Backfill using each chat's latest message (falls back to the chat's own
-- creation time if it has none, e.g. all messages were already delivered
-- and dropped per the device-stored-history model) — gives a real ordering
-- immediately instead of bunching every existing chat at "now".
update chats c set updated_at = coalesce(
  (select max(m.created_at) from messages m where m.chat_id = c.id),
  c.created_at
) where updated_at is null;

alter table chats alter column updated_at set default now();
