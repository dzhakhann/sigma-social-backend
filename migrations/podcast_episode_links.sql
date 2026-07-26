-- Stable shareable ids for podcast episodes.
--
-- Episodes have no id of their own: the catalogue is a live RSS feed, re-parsed
-- by feed URL on every request, and an episode is identified only by its
-- position in that feed. That's fine for browsing but useless for sharing —
-- there's nothing a `sigmacta.pages.dev/podcast/<id>` link could resolve
-- against. This table is that missing id: the first time an episode is
-- shared, it's given a short id keyed to (feed_url, audio_url) — the
-- enclosure URL is, in practice, unique and stable per episode even without a
-- real RSS <guid> — and the episode's playable fields are copied in so a
-- resolve never has to re-fetch or re-parse the feed.
create table if not exists podcast_episode_links (
  id text primary key,
  feed_url text not null,
  audio_url text not null,
  title text,
  artist text,
  artwork text,
  duration text,
  created_at timestamptz not null default now()
);

-- Sharing the same episode twice must return the same id, not mint a new one.
create unique index if not exists idx_pel_feed_audio
  on podcast_episode_links (feed_url, audio_url);
