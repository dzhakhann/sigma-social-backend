-- Emoji reactions on group messages: {emoji: [userId, ...]}, one emoji per
-- user per message (enforced in server.js, not by a DB constraint).
alter table group_messages add column if not exists reactions jsonb default '{}'::jsonb;
