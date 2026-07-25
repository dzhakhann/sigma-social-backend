-- Google Play subscription state.
--
-- `pro_until` already exists (promo_codes.sql) and stays the single source of
-- truth for "is this user Pro right now" — a purchase and a promo code both just
-- push that date out. What's added here is the audit/reconciliation data a
-- purchase needs and a promo code doesn't.

-- Where the current entitlement came from: 'promo' | 'play' | null.
-- Needed because the two must not clobber each other: a Play subscription
-- renewing should not shorten a promo period and vice versa.
alter table users add column if not exists pro_source text;

-- The Play purchase token. Kept so a renewal/cancel notification can be matched
-- back to a user, and so the same token can never be redeemed by two accounts.
alter table users add column if not exists play_purchase_token text;

-- One token belongs to exactly one account. Without this a purchase token could
-- be replayed from another device to grant Pro to a second user.
create unique index if not exists idx_users_play_token
  on users (play_purchase_token)
  where play_purchase_token is not null;

-- Every verification attempt, successful or not. Payments are the one place
-- where "it didn't work and we don't know why" is unacceptable, and Play's own
-- console gives no view of what OUR server decided.
create table if not exists billing_events (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  product_id text,
  purchase_token text,
  -- 'verified' | 'rejected' | 'error'
  status text not null,
  -- Play's raw subscription state, for debugging a disputed charge.
  detail jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);
create index if not exists idx_billing_events_user
  on billing_events (user_id, created_at desc);
