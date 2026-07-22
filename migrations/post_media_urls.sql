-- Instagram-style multi-photo carousel posts. image_url stays the first
-- photo (back-compat for anything that only reads a single image); media_urls
-- holds the FULL ordered list when a post has more than one photo.
alter table posts add column if not exists media_urls jsonb;
