-- Music attached to a post (Bug 5): only a Rhythm catalog reference
-- {url, title, artist, art} — audio files are never copied per post.
alter table posts add column if not exists music jsonb;
