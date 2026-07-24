-- Telegram-style ✓/✓✓ next to the last-message preview in the CHAT LIST.
-- Read receipts already existed INSIDE a chat (messages.is_read), but the
-- list itself had no way to know whose message the preview belongs to or
-- whether the other side has seen it — these two columns carry exactly that,
-- and nothing more.
--
-- Written on every send (/api/messages) and flipped to read when the other
-- side acks or opens the chat. server.js wraps both writes in the usual
-- catch-and-retry-without-the-new-columns fallback, so sending keeps working
-- unchanged until this is applied.
alter table chats add column if not exists last_sender_id uuid;
alter table chats add column if not exists last_read boolean default false;
