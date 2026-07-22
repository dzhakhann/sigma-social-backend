-- CRITICAL — run this immediately (Supabase flagged public tables as
-- readable/writable by ANYONE via the project's public REST API, since
-- Row Level Security was never turned on).
--
-- Why this is safe: this backend (server.js) always connects with the
-- SERVICE ROLE key, which BYPASSES Row Level Security entirely — every
-- existing feature keeps working exactly as before. The Flutter app never
-- talks to Supabase directly (no anon/service key is embedded in it; every
-- request goes through this backend, which does its own JWT auth). So
-- enabling RLS with NO policies simply closes the direct public REST door
-- (https://<project>.supabase.co/rest/v1/<table>) that anyone with the
-- project's anon key (public by Supabase design) could otherwise use to
-- read, edit or delete every row of every table — with zero effect on the
-- app itself.
alter table users                  enable row level security;
alter table posts                  enable row level security;
alter table comments                enable row level security;
alter table likes                  enable row level security;
alter table follows                enable row level security;
alter table stories                enable row level security;
alter table story_events           enable row level security;
alter table chats                  enable row level security;
alter table messages               enable row level security;
alter table notifications          enable row level security;
alter table goals                  enable row level security;
alter table reels                  enable row level security;
alter table reel_likes             enable row level security;
alter table blocks                 enable row level security;
alter table hidden_users           enable row level security;
alter table reports                enable row level security;
alter table verification_requests  enable row level security;
alter table profile_views          enable row level security;
