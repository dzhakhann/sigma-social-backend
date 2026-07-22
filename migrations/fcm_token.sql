-- Firebase Cloud Messaging device token, so the server can wake a
-- killed/backgrounded app with a real push (not just the live socket push,
-- which only reaches an app process that's still alive).
alter table users add column if not exists fcm_token text;
