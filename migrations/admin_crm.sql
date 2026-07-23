-- Admin CRM overhaul: separate admin login system, ban duration, audit log,
-- device/IP session tracking, and a flag for the system/support account.

-- Admin accounts are fully decoupled from the social `users` table — an
-- admin login can never be a discoverable social profile, and a compromised
-- social account can never grant admin access. Bootstrapped once via
-- POST /api/admin/auth/bootstrap (only works while this table is empty),
-- new admins created from inside the panel after that.
create table if not exists admin_users (
  id uuid primary key default gen_random_uuid(),
  username text not null unique,
  password_hash text not null,
  created_at timestamptz default now()
);

-- Time-limited bans (e.g. "blocked for 2 days") — null means permanent,
-- same as today. An expired ban is auto-cleared the next time the user logs
-- in (see /api/auth/login), no cron job needed.
alter table users add column if not exists banned_until timestamptz;

-- Marks the lazily-created "Sigmacta"/"Поддержка" system account used to
-- deliver admin messages through the normal 1:1 chat pipeline — lets other
-- code recognize/protect it (never banned/deleted) without hardcoding a name.
alter table users add column if not exists is_system boolean default false;

-- Which admin did what, when — shown in the panel's Activity Log tab.
-- admin_username is a snapshot (not a live join) so the log stays readable
-- even if that admin account is later renamed or removed.
create table if not exists admin_audit_log (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid not null,
  admin_username text not null,
  action text not null,
  target_type text,
  target_id text,
  detail jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);
create index if not exists idx_audit_created on admin_audit_log (created_at desc);

-- One row per login/app-open; the latest row per user_id is "current".
-- Powers the admin panel's device model / OS version / app version / IP
-- columns (previously only last_seen existed, with no way to see the rest).
create table if not exists user_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  ip text,
  device_model text,
  os_version text,
  app_version text,
  platform text,
  created_at timestamptz default now()
);
create index if not exists idx_sessions_user on user_sessions (user_id, created_at desc);
