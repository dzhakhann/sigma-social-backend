-- AI companion: one Gemini-generated message per user per day, cached here
-- so opening the app repeatedly never re-calls the API (same throttle
-- pattern as aura_day for the daily aura bonus).
alter table users add column if not exists companion_message text;
alter table users add column if not exists companion_message_date date;
