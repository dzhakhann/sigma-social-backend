-- Story publish failed with "value too long for type character varying(...)":
-- stories pack link/music stickers into the media URL's #fragment, which can
-- exceed the old varchar limit. URLs are unbounded — store them as text.
alter table stories alter column image_url type text;
alter table posts   alter column image_url type text;
