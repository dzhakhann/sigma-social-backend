-- Promo codes: admin-issued codes that grant a Sigmacta Pro subscription.
--
-- Two tables on purpose. `promo_codes` is the definition an admin edits;
-- `promo_redemptions` is the immutable "who used what, when" log the panel
-- shows. Keeping redemptions separate means deactivating or editing a code
-- never rewrites its history.

create table if not exists promo_codes (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,               -- always stored UPPERCASE
  description text default '',
  plan text not null default 'pro',
  duration_days integer not null default 30,
  -- null = unlimited uses. A "one-time" code is simply max_uses = 1, so
  -- there's no separate boolean that could disagree with the counter.
  max_uses integer,
  used_count integer not null default 0,
  expires_at timestamptz,                  -- null = never expires
  active boolean not null default true,
  created_by text default '',              -- admin username snapshot
  created_at timestamptz default now()
);

-- Lookups are always by the typed-in code.
create unique index if not exists idx_promo_code on promo_codes (upper(code));

create table if not exists promo_redemptions (
  id uuid primary key default gen_random_uuid(),
  promo_id uuid not null,
  code text not null,                      -- snapshot: survives a rename
  user_id uuid not null,
  username text default '',                -- snapshot: survives a rename
  granted_days integer not null default 0,
  created_at timestamptz default now()
);
create index if not exists idx_promo_redeem_promo on promo_redemptions (promo_id, created_at desc);

-- One redemption per user per code — enforced in the database, not just in
-- the handler, so two simultaneous requests can't both slip through.
create unique index if not exists idx_promo_redeem_once
  on promo_redemptions (promo_id, user_id);

-- `users.is_pro` already exists but is a plain boolean with no expiry, so a
-- time-limited subscription had nowhere to live. is_pro stays as the flag
-- everything already reads; pro_until is what expires it.
alter table users add column if not exists pro_until timestamptz;
