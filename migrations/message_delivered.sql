-- Three-state message ticks: ✓ sent · ✓✓ delivered · ✓✓ (accent) read.
--
-- Until now the model only had a boolean `is_read`, and `/api/messages/ack`
-- conflated two different events: the recipient's DEVICE picking the message
-- up, and the recipient actually READING it. Those are genuinely distinct here
-- — ChatsScreen acks incoming messages over the socket even when the chat
-- isn't open — so delivery gets its own column and the read flip moves to a
-- separate endpoint (`POST /api/messages/read`).
--
-- `chats.last_delivered` is the chat-LIST counterpart of `last_read`, which
-- already exists (see chat_list_ticks.sql).

alter table messages add column if not exists delivered_at timestamptz;
alter table chats    add column if not exists last_delivered boolean default false;

-- Existing acked rows were, by definition, delivered — backfill so old
-- conversations don't regress to a single ✓ after this ships.
update messages set delivered_at = acked_at
  where delivered_at is null and acked_at is not null;

update messages set delivered_at = coalesce(delivered_at, now())
  where is_read = true and delivered_at is null;
