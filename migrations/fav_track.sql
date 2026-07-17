-- Favorite track on the profile (Telegram-style "NF - MISTAKE" row).
-- Stores ONLY a reference into the Rhythm catalog: {url, title, artist, art, dur}.
-- No audio bytes are ever copied per user.
alter table users add column if not exists fav_track jsonb;
