-- Pinned message, for 1:1 chats and groups.
--
-- Stored as a self-contained jsonb SNAPSHOT on the conversation, not as a
-- foreign key to a message row — exactly like `messages.reply_to`. It has to
-- be: history lives on the phones and the server drops a message row once it
-- has been delivered, so a reference would dangle within seconds. The snapshot
-- keeps rendering after the original is long gone from the queue.
--
-- Shape: {id, sender_id, sender_name, content, message_type, created_at,
--         pinned_by, pinned_at}
-- null = nothing pinned.

alter table chats  add column if not exists pinned_message jsonb;
alter table groups add column if not exists pinned_message jsonb;
