-- Emoji reactions on 1:1 messages: {emoji: [userId, ...]}, one emoji per
-- user per message (enforced in server.js, not by a DB constraint) — mirrors
-- group_messages.reactions.
alter table messages add column if not exists reactions jsonb default '{}'::jsonb;

-- An acked message used to be deleted immediately (see /api/messages/ack).
-- Reacting to it moments later — very common, the recipient's app auto-acks
-- within seconds — hit "Not found". Kept a while longer instead; also lets
-- GET /api/messages/:chatId stop re-returning a message both sides already
-- have locally, without physically deleting it yet. sweepAckedMessages() in
-- server.js reaps rows past the grace window (48h).
alter table messages add column if not exists acked_at timestamptz;
