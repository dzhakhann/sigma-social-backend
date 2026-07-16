import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { RECOVERY_WORDS } from './wordlist.js';
import { runBots } from './bots.js';

dotenv.config();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/*
  Required Supabase tables (run once in SQL editor):

  create table notifications (
    id uuid default gen_random_uuid() primary key,
    user_id uuid references users(id) on delete cascade,
    from_user_id uuid references users(id) on delete cascade,
    type text,
    post_id uuid references posts(id) on delete cascade,
    message text,
    is_read boolean default false,
    created_at timestamptz default now()
  );

  create table reels (
    id uuid default gen_random_uuid() primary key,
    user_id uuid references users(id) on delete cascade,
    video_url text not null,
    caption text default '',
    likes_count integer default 0,
    created_at timestamptz default now()
  );

  create table reel_likes (
    id uuid default gen_random_uuid() primary key,
    user_id uuid references users(id) on delete cascade,
    reel_id uuid references reels(id) on delete cascade,
    unique(user_id, reel_id)
  );

  -- Recovery phrase support (run once): stores only the sha256 hash of the
  -- 12-word phrase, never the plaintext.
  alter table users add column if not exists recovery_hash text;
  -- email is no longer required for new accounts:
  alter table users alter column email drop not null;

  -- LinkedIn-style profile fields:
  alter table users add column if not exists headline text;
  alter table users add column if not exists about text;
  alter table users add column if not exists location text;
  alter table users add column if not exists work text;
  alter table users add column if not exists website text;
  alter table users add column if not exists education text;
  alter table users add column if not exists birthday text;

  -- Full registration profile (Sigmacta):
  alter table users add column if not exists first_name text;
  alter table users add column if not exists last_name text;
  alter table users add column if not exists middle_name text;
  alter table users add column if not exists gender text;
  alter table users add column if not exists birthplace text;
  alter table users add column if not exists relationship text;
  alter table users add column if not exists skills text;          -- languages, subjects, sports, hobbies
  alter table users add column if not exists hidden_fields jsonb default '[]'::jsonb; -- privacy: field keys the user hides
  alter table users add column if not exists is_pro boolean default false;           -- Sigmacta Pro subscription
  alter table users add column if not exists last_seen timestamptz;                   -- online/last-seen presence
  alter table users add column if not exists aura integer default 0;                  -- Aura activity score
  alter table users add column if not exists aura_day date;                           -- daily-login throttle for Aura
  alter table messages add column if not exists is_read boolean default false;        -- read receipts
  alter table comments add column if not exists is_edited boolean default false;      -- comment editing

  -- Yearly goals (Sigmacta MVP): each user's goals for a given year.
  create table if not exists goals (
    id uuid default gen_random_uuid() primary key,
    user_id uuid references users(id) on delete cascade,
    title text not null,
    category text default 'personal',   -- career | study | health | finance | personal
    progress integer default 0,          -- 0..100
    status text default 'active',        -- active | done
    year integer not null,
    note text default '',
    created_at timestamptz default now(),
    completed_at timestamptz
  );

  -- Admin panel: mark which users are admins, then make YOURSELF admin:
  alter table users add column if not exists is_admin boolean default false;
  alter table users add column if not exists is_verified boolean default false;
  alter table users add column if not exists is_banned boolean default false;
  alter table users add column if not exists ban_reason text;
  update users set is_admin = true where username = 'YOUR_USERNAME';
*/

const app = express();
// Render (and most hosts) sit behind a proxy; needed so rate-limit reads the
// real client IP from X-Forwarded-For instead of bucketing everyone together.
app.set('trust proxy', 1);
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

// CORS origins come from env (comma-separated). Defaults to '*' so nothing
// breaks out of the box; set CORS_ORIGIN in production to lock it down.
const corsOrigins = (process.env.CORS_ORIGIN || '*').split(',').map((s) => s.trim()).filter(Boolean);
const corsOptions = {
  origin: corsOrigins.includes('*') ? '*' : corsOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

// The service_role key is a full-admin secret. It must NEVER be hardcoded or
// shipped to the client — it lives only in an environment variable on the
// server (.env locally, Render dashboard in production).
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://uvbyxkrtyjqrorxnckvw.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || process.env.SUPABASE_SERVICE_ROLE;
if (!SUPABASE_KEY) {
  console.error('❌ FATAL: SUPABASE_KEY env var is not set. Refusing to start.');
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ─── RATE LIMITING ──────────────────────────────────────────────────────────
// Protects against brute-forcing passwords / recovery phrases and upload abuse.
const WINDOW = parseInt(process.env.RATE_LIMIT_WINDOW || '900000', 10); // 15 min
const limiterBase = { windowMs: WINDOW, standardHeaders: true, legacyHeaders: false };
const authLimiter = rateLimit({
  ...limiterBase, max: 40,
  message: { success: false, error: 'Too many attempts. Try again later.' },
});
const recoverLimiter = rateLimit({
  ...limiterBase, max: 10,
  message: { success: false, error: 'Too many recovery attempts. Try again later.' },
});
const uploadLimiter = rateLimit({
  ...limiterBase, max: 100,
  message: { success: false, error: 'Upload limit reached. Try again later.' },
});
// Order matters: the stricter /recover limiter is mounted before the general one.
app.use('/api/auth/recover', recoverLimiter);
app.use('/api/auth', authLimiter);
app.use('/api/upload', uploadLimiter);

// ─── HELPER ───────────────────────────────────────────────────────────────────

async function createNotification(userId, fromUserId, type, message, postId = null) {
  if (!userId || userId === fromUserId) return;
  try {
    await supabase.from('notifications').insert([{
      user_id: userId, from_user_id: fromUserId,
      type, message, post_id: postId, is_read: false
    }]);
  } catch (_) {}
}

// ─── AURA: user activity score (gamification). Small increments per action. ────
async function awardAura(userId, amount) {
  if (!userId || !amount) return;
  try {
    const { data } = await supabase.from('users').select('aura').eq('id', userId);
    const cur = Number(data?.[0]?.aura || 0);
    await supabase.from('users').update({ aura: cur + amount }).eq('id', userId);
  } catch (_) {}
}

// Daily login bonus (once per calendar day), throttled via aura_day.
async function awardDailyAura(userId) {
  if (!userId) return;
  try {
    const today = new Date().toISOString().slice(0, 10);
    const { data } = await supabase.from('users').select('aura_day, aura').eq('id', userId);
    if (data?.[0]?.aura_day === today) return;
    await supabase.from('users').update({
      aura_day: today,
      aura: Number(data?.[0]?.aura || 0) + 5,
    }).eq('id', userId);
  } catch (_) {}
}

// ─── RECOVERY PHRASE HELPERS ────────────────────────────────────────────────
// Generate an N-word recovery phrase using a cryptographically-secure RNG.
function generateRecoveryPhrase(wordCount = 12) {
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    words.push(RECOVERY_WORDS[crypto.randomInt(0, RECOVERY_WORDS.length)]);
  }
  return words.join(' ');
}

// Hash a phrase before storing it. We never keep the plaintext phrase.
// Normalize (lowercase, collapse whitespace) so input formatting doesn't matter.
function hashPhrase(phrase) {
  const normalized = String(phrase).trim().toLowerCase().replace(/\s+/g, ' ');
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

// ─── PASSWORD HELPERS ───────────────────────────────────────────────────────
const BCRYPT_ROUNDS = 10;
// bcrypt hashes start with $2a/$2b/$2y — used to detect legacy plaintext rows.
const looksHashed = (s) => typeof s === 'string' && s.startsWith('$2');

// ─── JWT (HS256, no external dependency) ─────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret-change-me';
const JWT_TTL = parseInt(process.env.JWT_TTL_SECONDS || '2592000', 10); // 30 days
if (JWT_SECRET === 'dev-insecure-secret-change-me' ||
    JWT_SECRET === 'your-super-secret-jwt-key-change-this-in-production') {
  console.warn('⚠️  JWT_SECRET is weak/default. Set a strong JWT_SECRET in env for production.');
}

const b64url = (input) => Buffer.from(input).toString('base64url');

function signToken(payload, ttl = JWT_TTL) {
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + ttl };
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const data = `${head}.${b64url(JSON.stringify(body))}`;
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;
    const data = `${parts[0]}.${parts[1]}`;
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
    const a = Buffer.from(parts[2]);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

// Require a valid Bearer token; exposes the authenticated user id as req.userId.
function authRequired(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  const payload = token ? verifyToken(token) : null;
  if (!payload || !payload.sub) {
    return res.status(401).json({ success: false, error: 'Not authenticated' });
  }
  req.userId = payload.sub;
  // Refresh presence (fire-and-forget) so we can show "в сети / был недавно".
  supabase.from('users').update({ last_seen: new Date().toISOString() })
    .eq('id', payload.sub).then(() => {}, () => {});
  next();
}

// Map a list of user ids -> username in ONE query (avoids slow N+1 lookups).
async function usernameMap(ids) {
  const uniq = [...new Set((ids || []).filter(Boolean))];
  if (uniq.length === 0) return {};
  const { data } = await supabase.from('users').select('id, username').in('id', uniq);
  const m = {};
  (data || []).forEach((u) => { m[u.id] = u.username; });
  return m;
}

// Allow only users with is_admin = true. Chain after authRequired.
async function adminOnly(req, res, next) {
  try {
    const { data } = await supabase.from('users').select('is_admin').eq('id', req.userId);
    if (!data || data[0]?.is_admin !== true) {
      return res.status(403).json({ success: false, error: 'Admin only' });
    }
    next();
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
}

// ─── HEALTH ───────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => res.json({ success: true, message: 'Server is running!' }));

// ─── ADMIN WEB PANEL (separate site, served by the backend) ──────────────────
app.get('/admin', (req, res) => {
  res.set('Cache-Control', 'no-store'); // always serve the latest admin UI
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ─── AUTH ─────────────────────────────────────────────────────────────────────

// ─── Register: username + password only. No email, no phone.
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, error: 'Username and password are required' });
  if (username.length < 3) return res.json({ success: false, error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.json({ success: false, error: 'Password must be at least 6 characters' });
  // Only allow letters, numbers, underscores, dots
  if (!/^[a-zA-Z0-9_.]+$/.test(username)) return res.json({ success: false, error: 'Username can only contain letters, numbers, _ and .' });
  try {
    const { data: existing } = await supabase.from('users').select('id').eq('username', username);
    if (existing && existing.length > 0) return res.json({ success: false, error: 'Username already taken' });
    // Generate a one-time recovery phrase. We store only its hash; the plaintext
    // is returned to the client exactly once and never persisted server-side.
    const recoveryPhrase = generateRecoveryPhrase(12);
    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const { data, error } = await supabase.from('users').insert([{
      username,
      password_hash,
      // email column kept nullable — generate a placeholder so old DB constraints don't break
      email: `${username}@sigma.local`,
      bio: '',
      followers_count: 0,
      following_count: 0,
      recovery_hash: hashPhrase(recoveryPhrase),
    }]).select().single();
    if (error) throw error;
    // recovery_phrase is shown to the user ONCE on this response.
    const token = signToken({ sub: data.id, username: data.username });
    res.json({ success: true, data: { user: data, recovery_phrase: recoveryPhrase, token } });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── Login: username + password only.
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ success: false, error: 'Username and password are required' });
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('username', username);
    if (error) throw error;
    if (!data || data.length === 0) return res.json({ success: false, error: 'Wrong username or password' });
    const user = data[0];
    const stored = user.password_hash || '';
    let ok = false;
    if (looksHashed(stored)) {
      ok = await bcrypt.compare(password, stored);
    } else {
      // Legacy plaintext row: compare directly, then transparently upgrade to bcrypt.
      ok = stored === password;
      if (ok) {
        const upgraded = await bcrypt.hash(password, BCRYPT_ROUNDS);
        await supabase.from('users').update({ password_hash: upgraded }).eq('id', user.id);
      }
    }
    if (!ok) return res.json({ success: false, error: 'Wrong username or password' });
    if (user.is_banned === true) {
      return res.json({
        success: false,
        error: `Account blocked${user.ban_reason ? ': ' + user.ban_reason : ''}`,
      });
    }
    const token = signToken({ sub: user.id, username: user.username });
    awardDailyAura(user.id); // +5 Aura for logging in today
    res.json({ success: true, data: { user, token } });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── Recover: reset password using username + recovery phrase. No email needed.
app.post('/api/auth/recover', async (req, res) => {
  const { username, phrase, new_password } = req.body;
  if (!username || !phrase || !new_password) {
    return res.json({ success: false, error: 'Username, recovery phrase and new password are required' });
  }
  if (new_password.length < 6) {
    return res.json({ success: false, error: 'Password must be at least 6 characters' });
  }
  try {
    const { data: users, error } = await supabase
      .from('users').select('*').eq('username', username);
    if (error) throw error;
    if (!users || users.length === 0) {
      return res.json({ success: false, error: 'Wrong username or recovery phrase' });
    }
    const user = users[0];
    if (!user.recovery_hash || user.recovery_hash !== hashPhrase(phrase)) {
      return res.json({ success: false, error: 'Wrong username or recovery phrase' });
    }
    const new_hash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);
    const { data: updated, error: upErr } = await supabase
      .from('users').update({ password_hash: new_hash }).eq('id', user.id).select().single();
    if (upErr) throw upErr;
    const token = signToken({ sub: updated.id, username: updated.username });
    res.json({ success: true, data: { user: updated, token } });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── MEDIA UPLOAD ───────────────────────────────────────────────────────────
// Generic upload: the client sends base64 bytes, the SERVER (which holds the
// Supabase key) writes to storage and returns a public URL. The client never
// sees the key.
app.post('/api/upload', authRequired, async (req, res) => {
  const { file_base64, folder, ext, content_type } = req.body;
  const user_id = req.userId;
  if (!file_base64) return res.json({ success: false, error: 'No file provided' });
  try {
    const buffer = Buffer.from(file_base64, 'base64');
    const MAX_UPLOAD = parseInt(process.env.UPLOAD_MAX_BYTES || '31457280', 10); // 30 MB
    if (buffer.length > MAX_UPLOAD) {
      return res.json({ success: false, error: 'File too large (max 30 MB)' });
    }
    const safeFolder = (String(folder || 'upload').replace(/[^a-z0-9_-]/gi, '').slice(0, 24)) || 'upload';
    const safeExt = (String(ext || 'jpg').replace(/[^a-z0-9]/gi, '').slice(0, 5)) || 'jpg';
    const fileName = `${safeFolder}_${user_id || 'anon'}_${Date.now()}.${safeExt}`;
    const { error } = await supabase.storage.from('avatars').upload(fileName, buffer, {
      contentType: content_type || 'image/jpeg',
      upsert: true,
    });
    if (error) throw error;
    const { data } = supabase.storage.from('avatars').getPublicUrl(fileName);
    res.json({ success: true, url: data.publicUrl });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── USERS ────────────────────────────────────────────────────────────────────

app.get('/api/users', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*');
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Resolve a username → user id (for deep links sigmacta.app/@username).
app.get('/api/users/by-username/:username', async (req, res) => {
  try {
    const { data } = await supabase.from('users')
      .select('id, username').ilike('username', req.params.username).limit(1);
    if (!data?.[0]) return res.json({ success: false, error: 'not_found' });
    res.json({ success: true, data: data[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/users/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').eq('id', req.params.userId);
    if (error) throw error;
    if (!data || data.length === 0) return res.json({ success: false, error: 'User not found' });
    const user = data[0];
    // Live counts for the profile header (🎯 goals · 📝 posts).
    const { count: postsCount } = await supabase.from('posts')
      .select('*', { count: 'exact', head: true }).eq('user_id', user.id);
    const year = new Date().getFullYear();
    const { count: goalsCount } = await supabase.from('goals')
      .select('*', { count: 'exact', head: true }).eq('user_id', user.id).eq('year', year);
    const { count: goalsDone } = await supabase.from('goals')
      .select('*', { count: 'exact', head: true })
      .eq('user_id', user.id).eq('year', year).eq('status', 'done');
    res.json({
      success: true,
      data: {
        ...user,
        posts_count: postsCount || 0,
        goals_count: goalsCount || 0,
        goals_done_count: goalsDone || 0,
      },
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/users/:userId/update', authRequired, async (req, res) => {
  if (req.params.userId !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
  const {
    username, bio, avatar_url, headline, about, location, work, website,
    education, birthday, first_name, last_name, middle_name, gender,
    birthplace, relationship, skills, hidden_fields,
  } = req.body;
  try {
    // Only update fields that were actually sent (partial updates supported).
    const update = {};
    if (username !== undefined) update.username = username;
    if (bio !== undefined) update.bio = bio;
    if (avatar_url) update.avatar_url = avatar_url;
    if (headline !== undefined) update.headline = headline;
    if (about !== undefined) update.about = about;
    if (location !== undefined) update.location = location;
    if (work !== undefined) update.work = work;
    if (website !== undefined) update.website = website;
    if (education !== undefined) update.education = education;
    if (birthday !== undefined) update.birthday = birthday;
    if (first_name !== undefined) update.first_name = first_name;
    if (last_name !== undefined) update.last_name = last_name;
    if (middle_name !== undefined) update.middle_name = middle_name;
    if (gender !== undefined) update.gender = gender;
    if (birthplace !== undefined) update.birthplace = birthplace;
    if (relationship !== undefined) update.relationship = relationship;
    if (skills !== undefined) update.skills = skills;
    if (hidden_fields !== undefined) update.hidden_fields = hidden_fields;
    const { data, error } = await supabase.from('users').update(update).eq('id', req.params.userId).select();
    if (error) throw error;
    res.json({ success: true, data: data[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/users/:userId/follow/:targetUserId', authRequired, async (req, res) => {
  const userId = req.userId;
  const { targetUserId } = req.params;
  try {
    if (userId === targetUserId) return res.json({ success: false, error: 'Cannot follow yourself' });
    const { data: ex } = await supabase.from('follows').select('id').eq('follower_id', userId).eq('following_id', targetUserId);
    if (ex && ex.length > 0) return res.json({ success: false, error: 'Already following' });
    await supabase.from('follows').insert([{ follower_id: userId, following_id: targetUserId }]);
    const { data: target } = await supabase.from('users').select('followers_count').eq('id', targetUserId);
    const { data: current } = await supabase.from('users').select('following_count, username').eq('id', userId);
    if (target) await supabase.from('users').update({ followers_count: (target[0].followers_count || 0) + 1 }).eq('id', targetUserId);
    if (current) await supabase.from('users').update({ following_count: (current[0].following_count || 0) + 1 }).eq('id', userId);
    await createNotification(targetUserId, userId, 'follow', `${current?.[0]?.username || 'Someone'} started following you`);
    awardAura(targetUserId, 5); // gaining a follower
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/users/:userId/unfollow/:targetUserId', authRequired, async (req, res) => {
  const userId = req.userId;
  const { targetUserId } = req.params;
  try {
    await supabase.from('follows').delete().eq('follower_id', userId).eq('following_id', targetUserId);
    const { data: target } = await supabase.from('users').select('followers_count').eq('id', targetUserId);
    const { data: current } = await supabase.from('users').select('following_count').eq('id', userId);
    if (target) await supabase.from('users').update({ followers_count: Math.max(0, (target[0].followers_count || 1) - 1) }).eq('id', targetUserId);
    if (current) await supabase.from('users').update({ following_count: Math.max(0, (current[0].following_count || 1) - 1) }).eq('id', userId);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/users/:userId/following/:targetUserId', async (req, res) => {
  try {
    const { data } = await supabase.from('follows').select('id').eq('follower_id', req.params.userId).eq('following_id', req.params.targetUserId);
    res.json({ isFollowing: !!(data && data.length > 0) });
  } catch (_) { res.json({ isFollowing: false }); }
});

// ─── SEARCH ───────────────────────────────────────────────────────────────────

app.get('/api/search/users', async (req, res) => {
  const { q } = req.query;
  if (!q || q.trim().length === 0) return res.json({ success: true, data: [] });
  try {
    const { data, error } = await supabase.from('users').select('*').ilike('username', `%${q}%`).limit(20);
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/search/posts', async (req, res) => {
  const { q, userId } = req.query;
  if (!q || q.trim().length === 0) return res.json({ success: true, data: [] });
  try {
    const { data: posts, error } = await supabase.from('posts').select('*').ilike('content', `%${q}%`).order('created_at', { ascending: false }).limit(30);
    if (error) throw error;
    const enriched = await Promise.all((posts || []).map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url, is_verified').eq('id', post.user_id);
      let isLiked = false;
      if (userId) {
        const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
        isLiked = !!(like && like.length > 0);
      }
      return { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_verified: user?.[0]?.is_verified === true, is_liked: isLiked };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── CHANNELS (content bots you can subscribe to) ──────────────────────────────
app.get('/api/channels', async (req, res) => {
  const { userId } = req.query;
  try {
    const { data: bots, error } = await supabase
      .from('users')
      .select('id, username, bio, avatar_url, is_verified, followers_count')
      .like('email', '%@bots.local')
      .order('followers_count', { ascending: false });
    if (error) throw error;
    let following = new Set();
    if (userId) {
      const { data: f } = await supabase.from('follows').select('following_id').eq('follower_id', userId);
      following = new Set((f || []).map((x) => x.following_id));
    }
    res.json({
      success: true,
      data: (bots || []).map((b) => ({ ...b, is_following: following.has(b.id) })),
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── GOALS (Sigmacta MVP: yearly goals + Wrapped) ──────────────────────────────
app.get('/api/goals', authRequired, async (req, res) => {
  const userId = req.userId;
  const { year } = req.query;
  try {
    let q = supabase.from('goals').select('*').eq('user_id', userId);
    if (year) q = q.eq('year', Number(year));
    const { data, error } = await q.order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/goals', authRequired, async (req, res) => {
  const { title, category, year, note } = req.body;
  if (!title || !title.trim()) return res.json({ success: false, error: 'Title required' });
  try {
    const { data, error } = await supabase.from('goals').insert([{
      user_id: req.userId,
      title: title.trim(),
      category: category || 'personal',
      year: Number(year) || new Date().getFullYear(),
      note: note || '',
      progress: 0,
      status: 'active',
    }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/goals/:id/update', authRequired, async (req, res) => {
  const { title, category, note, progress, status } = req.body;
  try {
    const { data: g } = await supabase.from('goals').select('user_id, status').eq('id', req.params.id).single();
    if (!g || g.user_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    const wasDone = g.status === 'done';
    const update = {};
    if (title !== undefined) update.title = title;
    if (category !== undefined) update.category = category;
    if (note !== undefined) update.note = note;
    if (progress !== undefined) {
      const p = Math.max(0, Math.min(100, Number(progress)));
      update.progress = p;
      if (p >= 100) { update.status = 'done'; update.completed_at = new Date().toISOString(); }
      else { update.status = 'active'; update.completed_at = null; }
    }
    if (status !== undefined) {
      update.status = status;
      if (status === 'done') { update.progress = 100; update.completed_at = new Date().toISOString(); }
    }
    const { data, error } = await supabase.from('goals').update(update).eq('id', req.params.id).select().single();
    if (error) throw error;
    if (!wasDone && update.status === 'done') awardAura(req.userId, 50); // completing a goal
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/goals/:id', authRequired, async (req, res) => {
  try {
    const { data: g } = await supabase.from('goals').select('user_id').eq('id', req.params.id).single();
    if (!g || g.user_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    await supabase.from('goals').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Wrapped / Year-in-Review stats built from this year's goals.
app.get('/api/goals/wrapped', async (req, res) => {
  const { userId } = req.query;
  const year = Number(req.query.year) || new Date().getFullYear();
  if (!userId) return res.json({ success: false, error: 'userId required' });
  try {
    const { data: goals } = await supabase.from('goals').select('*').eq('user_id', userId).eq('year', year);
    const list = goals || [];
    const done = list.filter((g) => g.status === 'done');
    const byCat = {};
    for (const g of list) byCat[g.category] = (byCat[g.category] || 0) + 1;
    let topCategory = null, topCount = 0;
    for (const k of Object.keys(byCat)) if (byCat[k] > topCount) { topCount = byCat[k]; topCategory = k; }
    const avgProgress = list.length
      ? Math.round(list.reduce((s, g) => s + (g.progress || 0), 0) / list.length) : 0;
    res.json({
      success: true,
      data: {
        year,
        total: list.length,
        completed: done.length,
        completionRate: list.length ? Math.round((done.length / list.length) * 100) : 0,
        avgProgress,
        topCategory,
        byCategory: byCat,
        highlights: done.map((g) => ({ title: g.title, category: g.category })).slice(0, 8),
      },
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── AI (Google Gemini — key stays on the server, never in the app) ───────────
const GEMINI_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-2.5-flash';
const GEMINI_URL =
  `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

async function callGemini(system, messages) {
  if (!GEMINI_KEY) return null;
  const contents = (messages || []).map((m) => ({
    role: m.role === 'model' ? 'model' : 'user',
    parts: [{ text: String(m.text || '') }],
  }));
  const body = {
    contents,
    ...(system ? { systemInstruction: { parts: [{ text: system }] } } : {}),
    // thinkingBudget:0 stops gemini-2.5-flash from spending the token budget on
    // hidden "thinking" (which was truncating the visible answer).
    generationConfig: {
      temperature: 0.8,
      maxOutputTokens: 1024,
      thinkingConfig: { thinkingBudget: 0 },
    },
  };
  const r = await fetch(`${GEMINI_URL}?key=${GEMINI_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  return (j?.candidates?.[0]?.content?.parts || []).map((p) => p.text).join('') || null;
}

// Chat with the Sigmacta AI assistant.
async function buildUserContext(uid) {
  try {
    const { data: rows } = await supabase.from('users')
      .select('username, first_name, last_name, gender, birthday, birthplace, education, work, skills, about, location')
      .eq('id', uid);
    const u = rows && rows[0];
    const year = new Date().getFullYear();
    const { data: goals } = await supabase.from('goals')
      .select('title, category, progress, status').eq('user_id', uid).eq('year', year);
    const profile = u ? [
      u.first_name ? `имя: ${u.first_name}` : `ник: ${u.username}`,
      u.gender && `пол: ${u.gender}`,
      u.birthday && `дата рождения: ${u.birthday}`,
      u.location && `город: ${u.location}`,
      u.work && `работа: ${u.work}`,
      u.education && `учёба: ${u.education}`,
      u.skills && `навыки/хобби: ${u.skills}`,
      u.about && `о себе: ${u.about}`,
    ].filter(Boolean).join('; ') : 'не заполнен';
    const goalsText = (goals || []).map((g) =>
      `- ${g.title} (${g.category}, ${g.progress}%${g.status === 'done' ? ', выполнено' : ''})`).join('\n') || 'целей пока нет';
    return { profile, goalsText, year };
  } catch (_) {
    return { profile: 'не заполнен', goalsText: 'целей пока нет', year: new Date().getFullYear() };
  }
}

app.post('/api/ai/chat', authRequired, async (req, res) => {
  try {
    const { profile, goalsText, year } = await buildUserContext(req.userId);
    const identity =
      'Ты — ИИ-ассистент и коуч приложения Sigmacta. Тебя создала компания Sigmacta. ' +
      'Основатель компании и приложения — JO. Если спрашивают, кто тебя создал/разработал, ' +
      'кто твой автор, на чём ты работаешь — отвечай только: «Меня создала компания Sigmacta, ' +
      'основатель — JO». СТРОГО ЗАПРЕЩЕНО упоминать Google, Gemini, OpenAI, ChatGPT, любые ' +
      'сторонние компании, модели или технологии, и говорить, что ты языковая модель. ' +
      'Ты — просто ИИ Sigmacta. ';
    const system = identity +
      'Ты знаешь этого пользователя и подстраиваешься под него.\n' +
      `Профиль: ${profile}.\n` +
      `Цели на ${year}:\n${goalsText}\n` +
      'Помогай ставить и достигать личные цели, мотивируй, давай конкретные шаги. ' +
      'Обращайся по имени, если оно известно. Отвечай коротко, тепло, на языке пользователя.';
    const lang = req.body.lang === 'ru' ? 'ru' : 'en';
    const langRule = lang === 'ru'
      ? ' Отвечай ТОЛЬКО по-русски.'
      : ' Reply ONLY in English.';
    const reply = await callGemini(system + langRule, req.body.messages);
    res.json({
      success: true,
      reply: reply || (lang === 'ru'
        ? 'ИИ временно недоступен. Попробуй чуть позже.'
        : 'AI is temporarily unavailable. Try again later.'),
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Personalized recommendations built from the user's goals.
app.get('/api/ai/recommend', authRequired, async (req, res) => {
  try {
    const uid = req.userId;
    const lang = req.query.lang === 'ru' ? 'ru' : 'en';
    const year = new Date().getFullYear();
    const { data: goals } = await supabase.from('goals')
      .select('title, category, progress, status').eq('user_id', uid).eq('year', year);
    const list = goals || [];
    if (list.length === 0) {
      return res.json({
        success: true,
        text: lang === 'ru'
          ? 'Поставь первую цель на год — и я подскажу, с чего начать двигаться к ней.'
          : 'Set your first yearly goal — and I\'ll suggest where to start.',
      });
    }
    const goalsText = list.map((g) =>
      `- ${g.title} (${g.category}, ${g.progress}%${g.status === 'done' ? ', done' : ''})`).join('\n');
    const system = lang === 'ru'
      ? 'Ты — персональный коуч Sigmacta. На основе целей пользователя дай ровно 3 ' +
        'конкретных совета на сегодня — что сделать, чтобы двигаться к целям. ' +
        'Каждый совет — одно короткое законченное предложение с новой строки, начинай с "- ". ' +
        'Без приветствий, без вступления, без markdown и без звёздочек. Отвечай ТОЛЬКО по-русски.'
      : 'You are the personal coach of Sigmacta. Based on the user\'s goals, give exactly 3 ' +
        'concrete tips for today — what to do to move toward the goals. ' +
        'Each tip is one short complete sentence on a new line, starting with "- ". ' +
        'No greetings, no intro, no markdown, no asterisks. Reply ONLY in English.';
    const reply = await callGemini(system, [
      { role: 'user', text: lang === 'ru'
          ? `Мои цели на год:\n${goalsText}\n\nДай рекомендации.`
          : `My goals for the year:\n${goalsText}\n\nGive recommendations.` },
    ]);
    res.json({
      success: true,
      text: reply || (lang === 'ru'
        ? 'Совет: выбери одну цель и сделай сегодня один маленький шаг к ней.'
        : 'Tip: pick one goal and take one small step toward it today.'),
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Zodiac sign from a birthday string (supports DD.MM.YYYY and YYYY-MM-DD).
function zodiacFromBirthday(bd) {
  if (!bd) return null;
  const s = String(bd).trim();
  let d, m;
  const iso = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  const dm = s.match(/^(\d{1,2})[.\/-](\d{1,2})/);
  if (iso) { m = +iso[2]; d = +iso[3]; }
  else if (dm) { d = +dm[1]; m = +dm[2]; }
  if (!d || !m || m < 1 || m > 12 || d < 1 || d > 31) return null;
  const z = [
    ['Козерог','♑','Capricorn'],['Водолей','♒','Aquarius'],['Рыбы','♓','Pisces'],
    ['Овен','♈','Aries'],['Телец','♉','Taurus'],['Близнецы','♊','Gemini'],
    ['Рак','♋','Cancer'],['Лев','♌','Leo'],['Дева','♍','Virgo'],
    ['Весы','♎','Libra'],['Скорпион','♏','Scorpio'],['Стрелец','♐','Sagittarius'],
    ['Козерог','♑','Capricorn'],
  ];
  const cutoff = [19,18,20,19,20,20,22,22,21,22,21,21]; // last day of prev sign, per month
  const idx = d <= cutoff[m - 1] ? m - 1 : m;
  return { name: z[idx][0], emoji: z[idx][1], nameEn: z[idx][2] };
}

app.get('/api/ai/horoscope', authRequired, async (req, res) => {
  try {
    const lang = req.query.lang === 'ru' ? 'ru' : 'en';
    const { data } = await supabase.from('users').select('birthday').eq('id', req.userId);
    const sign = zodiacFromBirthday(data?.[0]?.birthday);
    if (!sign) return res.json({ success: true, sign: null, emoji: null, text: '' });
    const signName = lang === 'ru' ? sign.name : (sign.nameEn || sign.name);
    const system = lang === 'ru'
      ? 'Ты — добрый астролог Sigmacta. Дай короткий тёплый позитивный прогноз ' +
        'на эту неделю для знака ' + sign.name + ' и один интересный факт про этот знак. ' +
        'Отвечай ТОЛЬКО по-русски, без markdown и звёздочек, 3-4 предложения.'
      : 'You are the kind astrologer of Sigmacta. Give a short warm positive forecast ' +
        'for this week for the sign ' + (sign.nameEn || sign.name) + ' and one interesting fact about this sign. ' +
        'Reply ONLY in English, no markdown or asterisks, 3-4 sentences.';
    const reply = await callGemini(system, [
      { role: 'user', text: lang === 'ru'
          ? `Знак: ${sign.name}. Прогноз на неделю и факт.`
          : `Sign: ${signName}. Weekly forecast and a fact.` },
    ]);
    res.json({ success: true, sign: signName, emoji: sign.emoji, text: reply || '' });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── GIF SEARCH (Giphy proxy — key stays on the server) ───────────────────────
// Tenor was shut down by Google on 2026-06-30, so we use Giphy instead.
const GIPHY_KEY = process.env.GIPHY_API_KEY || '';
app.get('/api/gifs', async (req, res) => {
  const q = (req.query.q || '').toString().trim();
  if (!GIPHY_KEY) return res.json({ success: true, data: [] });
  try {
    const url = q
      ? `https://api.giphy.com/v1/gifs/search?api_key=${GIPHY_KEY}&q=${encodeURIComponent(q)}&limit=24&rating=pg-13&bundle=fixed_width_downsampled`
      : `https://api.giphy.com/v1/gifs/trending?api_key=${GIPHY_KEY}&limit=24&rating=pg-13&bundle=fixed_width_downsampled`;
    const r = await fetch(url);
    const j = await r.json();
    const gifs = (j.data || []).map((g) => ({
      preview: g.images?.fixed_width_downsampled?.url ||
        g.images?.fixed_width?.url || g.images?.original?.url,
      full: g.images?.original?.url,
    })).filter((x) => x.full);
    res.json({ success: true, data: gifs });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── LINK PREVIEW (Open Graph unfurl — Telegram-style) ────────────────────────
const _linkCache = new Map();
app.get('/api/link-preview', async (req, res) => {
  const url = (req.query.url || '').toString();
  if (!/^https?:\/\//.test(url)) return res.json({ success: false });
  if (_linkCache.has(url)) return res.json({ success: true, data: _linkCache.get(url) });
  try {
    const r = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SigmactaBot/1.0; +https://sigmacta.app)' },
      redirect: 'follow',
    });
    const html = (await r.text()).slice(0, 300000); // cap
    const pick = (prop) => {
      const a = html.match(new RegExp(`<meta[^>]+(?:property|name)=["']${prop}["'][^>]+content=["']([^"']*)["']`, 'i'));
      const b = html.match(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+(?:property|name)=["']${prop}["']`, 'i'));
      return (a && a[1]) || (b && b[1]) || null;
    };
    const dec = (s) => s ? s.replace(/&amp;/g, '&').replace(/&quot;/g, '"')
      .replace(/&#0?39;/g, "'").replace(/&#x27;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>') : s;
    const data = {
      title: dec(pick('og:title') || (html.match(/<title>([^<]*)<\/title>/i) || [])[1] || ''),
      description: dec(pick('og:description') || pick('description') || ''),
      image: dec(pick('og:image') || pick('twitter:image')),
      siteName: dec(pick('og:site_name')) || (() => { try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; } })(),
      url,
    };
    if (_linkCache.size > 500) _linkCache.clear();
    _linkCache.set(url, data);
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── PODCASTS (proxy iTunes search + RSS parse; nothing stored) ───────────────
app.get('/api/podcast/search', async (req, res) => {
  const term = (req.query.term || 'подкаст').toString();
  try {
    const url = `https://itunes.apple.com/search?media=podcast&limit=40&term=${encodeURIComponent(term)}`;
    const r = await fetch(url);
    const j = await r.json();
    const data = (j.results || [])
      .map((x) => ({
        title: x.collectionName || x.trackName || 'Подкаст',
        artist: x.artistName || '',
        artwork: x.artworkUrl600 || x.artworkUrl100 || '',
        feedUrl: x.feedUrl || '',
        genre: x.primaryGenreName || '',
      }))
      .filter((p) => p.feedUrl);
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Audiobooks — LibriVox catalog (public domain, free for commercial apps).
// Each book maps to the same "show" shape as podcasts, so the existing
// episodes screen (RSS parser) plays the chapters.
app.get('/api/audiobooks/search', async (req, res) => {
  const term = (req.query.term || '').toString().trim();
  const genre = (req.query.genre || '').toString().trim();
  const language = (req.query.language || '').toString().trim();
  try {
    let base = 'https://librivox.org/api/feed/audiobooks/?format=json&extended=1&limit=40';
    if (genre) base += `&genre=${encodeURIComponent(genre)}`;
    if (language) base += `&language=${encodeURIComponent(language)}`;
    const url = term
      ? `${base}&title=${encodeURIComponent(term)}`
      : `${base}&sort_order=id`;
    const r = await fetch(url, { headers: { 'User-Agent': 'Sigmacta/1.0' } });
    const j = await r.json();
    const data = (j.books || [])
      .map((b) => ({
        title: b.title || 'Audiobook',
        artist: (b.authors || [])
          .map((a) => `${a.first_name || ''} ${a.last_name || ''}`.trim())
          .filter(Boolean)
          .join(', '),
        artwork: b.coverart_jpg || b.coverart_thumbnail || '',
        feedUrl: b.url_rss || '',
        genre: b.language || '',
        duration: b.totaltime || '',
      }))
      .filter((b) => b.feedUrl);
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/podcast/episodes', async (req, res) => {
  const feed = (req.query.feed || '').toString();
  if (!/^https?:\/\//.test(feed)) return res.json({ success: false, error: 'bad feed' });
  try {
    const r = await fetch(feed, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SigmactaBot/1.0)' },
      redirect: 'follow',
    });
    const xml = await r.text();
    const strip = (s) => (s || '')
      .replace(/<!\[CDATA\[|\]\]>/g, '')
      .replace(/<[^>]+>/g, '')
      .replace(/&amp;/g, '&').replace(/&quot;/g, '"')
      .replace(/&#0?39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .trim();
    const tag = (block, name) => {
      const m = block.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
      return m ? strip(m[1]) : '';
    };
    const items = xml.match(/<item[\s\S]*?<\/item>/gi) || [];
    const data = [];
    for (const block of items) {
      let audio = (block.match(/<enclosure[^>]*url="([^"]+)"/i) || [])[1]
        || (block.match(/<media:content[^>]*url="([^"]+)"/i) || [])[1];
      if (!audio) continue;
      audio = audio.replace(/&amp;/g, '&');
      data.push({
        title: tag(block, 'title'),
        audio,
        date: tag(block, 'pubDate'),
        duration: tag(block, 'itunes:duration'),
      });
      if (data.length >= 80) break;
    }
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── REPORTS · BLOCK · HIDE · VERIFICATION ───────────────────────────────────
// Requires the moderation tables (see migrations/moderation.sql).

// Submit a report on any object (user / post / comment / story).
app.post('/api/reports', authRequired, async (req, res) => {
  try {
    const { target_type, target_id, reason, note, link } = req.body || {};
    if (!target_type || !target_id) {
      return res.json({ success: false, error: 'Missing target' });
    }
    await supabase.from('reports').insert([{
      reporter_id: req.userId,
      target_type, target_id,
      reason: reason || 'other',
      note: note || '',
      link: link || '',
      status: 'open',
    }]);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Block / unblock a user (mutual invisibility + no messaging).
app.post('/api/block/:id', authRequired, async (req, res) => {
  try {
    await supabase.from('blocks').upsert([
      { user_id: req.userId, blocked_id: req.params.id },
    ], { onConflict: 'user_id,blocked_id', ignoreDuplicates: true });
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});
app.delete('/api/block/:id', authRequired, async (req, res) => {
  try {
    await supabase.from('blocks').delete()
      .eq('user_id', req.userId).eq('blocked_id', req.params.id);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Hide a user's content from my feed (soft, one-directional).
app.post('/api/hide/:id', authRequired, async (req, res) => {
  try {
    await supabase.from('hidden_users').upsert([
      { user_id: req.userId, hidden_id: req.params.id },
    ], { onConflict: 'user_id,hidden_id', ignoreDuplicates: true });
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Am I blocked by / did I block this user? (for profile visibility gate)
app.get('/api/block/status/:id', authRequired, async (req, res) => {
  try {
    const { data } = await supabase.from('blocks')
      .select('user_id, blocked_id')
      .or(`and(user_id.eq.${req.userId},blocked_id.eq.${req.params.id}),and(user_id.eq.${req.params.id},blocked_id.eq.${req.userId})`);
    const iBlocked = (data || []).some((b) => b.user_id === req.userId);
    const blockedMe = (data || []).some((b) => b.blocked_id === req.userId);
    res.json({ success: true, i_blocked: iBlocked, blocked_me: blockedMe });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Verification (blue check) application — once per 365 days.
app.post('/api/verification', authRequired, async (req, res) => {
  try {
    const { email, wiki, info } = req.body || {};
    const { data: last } = await supabase.from('verification_requests')
      .select('created_at').eq('user_id', req.userId)
      .order('created_at', { ascending: false }).limit(1);
    if (last?.[0]) {
      const days = (Date.now() - new Date(last[0].created_at)) / 86400000;
      if (days < 365) {
        return res.json({ success: false, error: 'already_applied',
          days_left: Math.ceil(365 - days) });
      }
    }
    await supabase.from('verification_requests').insert([{
      user_id: req.userId,
      email: email || '', wiki: wiki || '', info: info || '',
      status: 'pending',
    }]);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── NEWS v2 (publisher RSS with IMAGES — Tinder-deck cards) ─────────────────
// Standard aggregator model: headline + photo from the public RSS feed +
// attribution + link to the source. Nothing is stored in our DB; the server
// only proxies/parses and keeps a 15-minute in-memory cache.
// "Газета" — ONE mixed stream per language (no categories): several article
// feeds interleaved + YouTube news videos (official embeds, ToS-compliant).
const NEWS_FEEDS = {
  en: [
    'https://www.theguardian.com/world/rss',
    'https://www.theguardian.com/technology/rss',
    'https://www.theguardian.com/business/rss',
    'https://www.theguardian.com/sport/rss',
    'https://www.theguardian.com/science/rss',
    'https://www.theguardian.com/culture/rss',
  ],
  ru: [
    'https://lenta.ru/rss/news/world',
    'https://lenta.ru/rss/news/science',
    'https://lenta.ru/rss/news/economics',
    'https://lenta.ru/rss/news/sport',
    'https://lenta.ru/rss/news/culture',
    'https://lenta.ru/rss/news/motor',
  ],
};

// YouTube news channels (handles → channelId resolved at runtime & cached).
// Playback happens ONLY through the official YouTube player in the app.
const NEWS_YT = {
  en: ['@BBCNews', '@DWNews', '@aljazeeraenglish'],
  // @bbcrussian no longer exists (BBC closed it); use the current handle. Real
  // news channels only — handles are resolved reliably via the Data API below.
  ru: ['@bbcnewsrussian', '@dwrussian', '@euronewsru', '@meduzalive', '@tvrain', '@rtvi'],
};
const _ytChannelCache = new Map(); // handle → channelId | null

// Free YouTube Data API key (Google Cloud → "YouTube Data API v3"). Used ONLY to
// check which videos will actually play in the app's embedded player. Cost is
// 1 quota unit per 50 ids, so effectively free. Without it the filter is a
// no-op and videos pass through unchecked (some may fail to embed).
const YOUTUBE_API_KEY = process.env.YOUTUBE_API_KEY || '';
let _ytFilterWarned = false;

// Keep only videos that will actually play inside the in-app YouTube player:
// embeddable + public + fully processed + NOT a live/upcoming stream + not
// age-restricted. Offline live streams (LIVE_STREAM_OFFLINE) and premieres are
// the main cause of the "This video is unavailable" error, so they're dropped.
async function filterPlayableVideos(videos) {
  if (videos.length === 0) return videos;
  if (!YOUTUBE_API_KEY) {
    if (!_ytFilterWarned) {
      console.warn('[news] YOUTUBE_API_KEY not set — video embeddability filter disabled');
      _ytFilterWarned = true;
    }
    return videos;
  }
  const ids = videos.map((v) => v.videoId);
  const ok = new Set();
  for (let i = 0; i < ids.length; i += 50) {
    const batch = ids.slice(i, i + 50);
    try {
      const r = await fetch(
        'https://www.googleapis.com/youtube/v3/videos'
        + '?part=status,snippet,contentDetails'
        + `&id=${batch.join(',')}&key=${YOUTUBE_API_KEY}`);
      const j = await r.json();
      if (j.error) throw new Error(j.error.message || 'yt api error');
      for (const item of (j.items || [])) {
        const s = item.status || {};
        const sn = item.snippet || {};
        const cd = item.contentDetails || {};
        const ageRestricted =
          cd.contentRating && cd.contentRating.ytRating === 'ytAgeRestricted';
        // Any regionRestriction (allowed OR blocked list) is risky for a mixed
        // audience — drop it rather than serve a video that's blocked for some.
        const regionRestricted = !!cd.regionRestriction;
        if (
          s.embeddable === true &&
          s.privacyStatus === 'public' &&
          s.uploadStatus === 'processed' &&
          sn.liveBroadcastContent === 'none' &&
          !ageRestricted &&
          !regionRestricted
        ) {
          ok.add(item.id);
        }
      }
    } catch (e) {
      // Fail open on a transient API error: better to show a maybe-broken video
      // (the app has a "Watch on YouTube" fallback) than an empty feed.
      console.warn('[news] embeddability check failed:', e.message);
      for (const id of batch) ok.add(id);
    }
  }
  return videos.filter((v) => ok.has(v.videoId));
}

async function resolveYtChannel(handle) {
  if (_ytChannelCache.has(handle)) return _ytChannelCache.get(handle);
  // Preferred: YouTube Data API forHandle — exact & reliable. The old HTML
  // scrape sometimes grabbed a *recommended* channel's id (e.g. a breakdance
  // channel instead of the news one), so only fall back to it without a key.
  if (YOUTUBE_API_KEY) {
    try {
      const h = handle.replace(/^@/, '');
      const r = await fetch(
        'https://www.googleapis.com/youtube/v3/channels'
        + `?part=id&forHandle=${encodeURIComponent(h)}&key=${YOUTUBE_API_KEY}`);
      const j = await r.json();
      const id = j.items?.[0]?.id || null;
      if (id) { _ytChannelCache.set(handle, id); return id; }
      // If the handle genuinely doesn't resolve, cache null (skip it).
      if (!j.error) { _ytChannelCache.set(handle, null); return null; }
    } catch { /* fall through to scrape */ }
  }
  try {
    const r = await fetch(`https://www.youtube.com/${handle}`, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36' },
    });
    const html = await r.text();
    const id = (html.match(/"channelId":"(UC[\w-]{22})"/) || [])[1] || null;
    _ytChannelCache.set(handle, id);
    return id;
  } catch {
    _ytChannelCache.set(handle, null);
    return null;
  }
}

async function fetchYtVideos(handle, limit = 4) {
  const channelId = await resolveYtChannel(handle);
  if (!channelId) return [];
  try {
    const r = await fetch(
      `https://www.youtube.com/feeds/videos.xml?channel_id=${channelId}`);
    const xml = await r.text();
    const entries = xml.match(/<entry>[\s\S]*?<\/entry>/gi) || [];
    const chName = stripXml((xml.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || handle);
    const out = [];
    for (const e of entries) {
      const vid = (e.match(/<yt:videoId>([\w-]+)<\/yt:videoId>/i) || [])[1];
      if (!vid) continue;
      out.push({
        id: 'yt_' + vid,
        type: 'video',
        videoId: vid,
        title: stripXml((e.match(/<title>([\s\S]*?)<\/title>/i) || [])[1] || ''),
        link: `https://www.youtube.com/watch?v=${vid}`,
        // HD thumbnail; client falls back to hqdefault if maxres is missing.
        image: `https://i.ytimg.com/vi/${vid}/maxresdefault.jpg`,
        thumb: `https://i.ytimg.com/vi/${vid}/hqdefault.jpg`,
        desc: '',
        source: chName,
        date: stripXml((e.match(/<published>([\s\S]*?)<\/published>/i) || [])[1] || ''),
      });
      if (out.length >= limit) break;
    }
    return out;
  } catch {
    return [];
  }
}

const _newsCache = new Map(); // key → { ts, data }
const NEWS_CACHE_MS = 15 * 60 * 1000;

function stripXml(s) {
  let t = (s || '').replace(/<!\[CDATA\[|\]\]>/g, '');
  // Decode entities FIRST (feeds ship entity-encoded HTML like &lt;p&gt;),
  // then strip the real tags — twice, to survive double-encoded content.
  for (let i = 0; i < 2; i++) {
    t = t
      .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&apos;/g, "'")
      .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
    t = t.replace(/<[^>]+>/g, ' ');
  }
  return t.replace(/\s+/g, ' ').trim();
}

function parseArticleFeed(xml, limit = 15) {
  const tag = (block, name) => {
    const m = block.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
    return m ? stripXml(m[1]) : '';
  };
  const items = xml.match(/<item[\s\S]*?<\/item>/gi) || [];
  const out = [];
  for (const block of items) {
    const title = tag(block, 'title');
    const link = tag(block, 'link');
    if (!title || !link) continue;
    // Image: media:content (pick the widest — width may appear before OR
    // after the url attribute, e.g. Guardian puts width first).
    let image = '';
    const medias = [...block.matchAll(/<media:content\b[^>]*>/gi)]
      .map((m) => {
        const tag = m[0];
        const url = (tag.match(/url="([^"]+)"/i) || [])[1] || '';
        const w = parseInt((tag.match(/width="(\d+)"/i) || [])[1] || '0', 10);
        return { url, w };
      })
      .filter((x) => x.url)
      .sort((a, b) => b.w - a.w);
    if (medias.length) image = medias[0].url;
    if (!image) image = (block.match(/<media:thumbnail[^>]*url="([^"]+)"/i) || [])[1] || '';
    if (!image) {
      const enc = block.match(/<enclosure[^>]*url="([^"]+)"[^>]*type="image[^"]*"/i)
        || block.match(/<enclosure[^>]*type="image[^"]*"[^>]*url="([^"]+)"/i);
      if (enc) image = enc[1];
    }
    image = (image || '').replace(/&amp;/g, '&');
    // NOTE: Guardian image URLs are signed (s=… hash). Changing width/quality
    // invalidates the signature → 403, so we use them verbatim and pick the
    // widest <media:content> (700px) the feed offers.
    // Skip imageless stories (opinion/late-night) — every card must have a photo.
    if (!image) continue;
    let desc = tag(block, 'description');
    if (desc.length > 220) desc = desc.slice(0, 217).trimEnd() + '…';
    let source = '';
    try { source = new URL(link).hostname.replace(/^www\./, ''); } catch {}
    out.push({
      id: Buffer.from(link).toString('base64').slice(0, 32),
      title, link, image, desc, source,
      date: tag(block, 'pubDate'),
    });
    if (out.length >= limit) break;
  }
  return out;
}

// Fetch a page's og:image (HD, ~1200px) — RSS images are tiny (Lenta 420px,
// Guardian 700px). Cached so each article is fetched at most once / 15 min.
const _ogCache = new Map();
async function ogImage(url) {
  if (_ogCache.has(url)) return _ogCache.get(url);
  try {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 5000);
    const r = await fetch(url, {
      signal: ac.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Sigmacta/1.1)' },
    });
    clearTimeout(t);
    const html = (await r.text()).slice(0, 60000); // og tags live in <head>
    const m = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    const img = m ? m[1].replace(/&amp;/g, '&') : '';
    if (_ogCache.size > 500) _ogCache.clear();
    _ogCache.set(url, img);
    return img;
  } catch {
    _ogCache.set(url, '');
    return '';
  }
}

app.get('/api/news', async (req, res) => {
  const lang = req.query.lang === 'ru' ? 'ru' : 'en';
  const key = `mix:${lang}`;
  const cached = _newsCache.get(key);
  if (cached && Date.now() - cached.ts < NEWS_CACHE_MS) {
    return res.json({ success: true, data: cached.data });
  }
  try {
    const feeds = NEWS_FEEDS[lang] || NEWS_FEEDS.en;
    const ytHandles = NEWS_YT[lang] || NEWS_YT.en;
    // Fetch all article feeds + video channels in parallel.
    const [feedResults, ...videoLists] = await Promise.all([
      Promise.all(feeds.map(async (u) => {
        try {
          const r = await fetch(u, {
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Sigmacta/1.1)' },
          });
          return parseArticleFeed(await r.text(), 12);
        } catch { return []; }
      })),
      ...ytHandles.map((h) => fetchYtVideos(h, 10)),
    ]);
    // Interleave article feeds round-robin, dedupe by link.
    const seen = new Set();
    const articles = [];
    for (let i = 0; i < 12; i++) {
      for (const list of feedResults) {
        const it = list[i];
        if (it && !seen.has(it.link)) {
          seen.add(it.link);
          articles.push(it);
        }
      }
    }
    // Upgrade each article to its HD og:image (1200px) in parallel; keep the
    // small RSS image as fallback. Runs once per 15-min cache window.
    await Promise.all(articles.map(async (a) => {
      const og = await ogImage(a.link);
      if (og) { a.thumb = a.image; a.image = og; }
    }));
    // Shuffle videos from all channels together (newest first-ish), then keep
    // only the ones that will really play in the app's embedded player.
    const videos = await filterPlayableVideos(videoLists.flat());
    // Weave: a video every 4th card while videos remain.
    const data = [];
    let vi = 0;
    for (let i = 0; i < articles.length && data.length < 48; i++) {
      data.push(articles[i]);
      if ((data.length + 1) % 4 === 0 && vi < videos.length) {
        data.push(videos[vi++]);
      }
    }
    while (vi < videos.length && data.length < 48) data.push(videos[vi++]);
    if (_newsCache.size > 10) _newsCache.clear();
    _newsCache.set(key, { ts: Date.now(), data });
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── POSTS ────────────────────────────────────────────────────────────────────

// Following feed
app.get('/api/posts/following', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.json({ success: true, data: [] });
  try {
    const { data: follows } = await supabase.from('follows').select('following_id').eq('follower_id', userId);
    const ids = (follows || []).map(f => f.following_id);
    ids.push(userId); // include the user's own posts in their feed
    // Reposts never appear in the feed — only in profiles + as a notification.
    const { data: posts, error } = await supabase.from('posts').select('*').in('user_id', ids).is('repost_of', null).order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all(posts.map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url, is_verified').eq('id', post.user_id);
      const { data: comments } = await supabase.from('comments').select('id').eq('post_id', post.id);
      const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
      return { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_verified: user?.[0]?.is_verified === true, is_liked: !!(like && like.length > 0), comments_count: comments?.length || 0 };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Trending: top posts by likes in last 24h
app.get('/api/posts/trending', async (req, res) => {
  const { userId } = req.query;
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: posts, error } = await supabase
      .from('posts')
      .select('*')
      .is('repost_of', null)
      .gte('created_at', since)
      .order('likes_count', { ascending: false })
      .limit(20);
    if (error) throw error;
    const enriched = await Promise.all(posts.map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url, is_verified').eq('id', post.user_id);
      let isLiked = false;
      if (userId) {
        const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
        isLiked = !!(like && like.length > 0);
      }
      return { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_verified: user?.[0]?.is_verified === true, is_liked: isLiked };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/posts', async (req, res) => {
  const { userId } = req.query;
  try {
    // Main feed excludes reposts (they only live on profiles + notifications).
    const { data: posts, error } = await supabase.from('posts').select('*').is('repost_of', null).order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all(posts.map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url, is_verified').eq('id', post.user_id);
      const { data: comments } = await supabase.from('comments').select('id').eq('post_id', post.id);
      let isLiked = false;
      if (userId) {
        const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
        isLiked = !!(like && like.length > 0);
      }
      return { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_verified: user?.[0]?.is_verified === true, is_liked: isLiked, comments_count: comments?.length || 0 };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// A single user's posts INCLUDING their reposts — used by the profile.
app.get('/api/users/:userId/posts', async (req, res) => {
  const targetId = req.params.userId;
  const { userId } = req.query; // viewer (for is_liked)
  try {
    const { data: posts, error } = await supabase.from('posts').select('*').eq('user_id', targetId).order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all(posts.map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url, is_verified').eq('id', post.user_id);
      const { data: comments } = await supabase.from('comments').select('id').eq('post_id', post.id);
      let isLiked = false;
      if (userId) {
        const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
        isLiked = !!(like && like.length > 0);
      }
      return { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_verified: user?.[0]?.is_verified === true, is_liked: isLiked, comments_count: comments?.length || 0 };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// A single post by id (enriched) — used when opening a post from a notification.
app.get('/api/posts/:postId', async (req, res) => {
  const { userId } = req.query;
  try {
    const { data: rows, error } = await supabase.from('posts').select('*').eq('id', req.params.postId).limit(1);
    if (error) throw error;
    const post = rows && rows[0];
    if (!post) return res.json({ success: false, error: 'Not found' });
    const { data: user } = await supabase.from('users').select('username, avatar_url, is_verified').eq('id', post.user_id);
    const { data: comments } = await supabase.from('comments').select('id').eq('post_id', post.id);
    let isLiked = false;
    if (userId) {
      const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
      isLiked = !!(like && like.length > 0);
    }
    res.json({ success: true, data: { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_verified: user?.[0]?.is_verified === true, is_liked: isLiked, comments_count: comments?.length || 0 } });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Repost: creates a repost row (denormalized) + notifies the reposter's followers.
app.post('/api/posts/:postId/repost', authRequired, async (req, res) => {
  const reposter = req.userId;
  const origId = req.params.postId;
  try {
    const { data: rows } = await supabase.from('posts').select('*').eq('id', origId).limit(1);
    const orig = rows && rows[0];
    if (!orig) return res.json({ success: false, error: 'Post not found' });
    const { data: origUser } = await supabase.from('users').select('username').eq('id', orig.user_id);
    const origName = origUser?.[0]?.username || 'user';
    const { data: created, error } = await supabase.from('posts').insert([{
      user_id: reposter,
      content: orig.content || '',
      image_url: orig.image_url || null,
      repost_of: origId,
      repost_username: origName,
      likes_count: 0,
    }]).select().single();
    if (error) throw error;
    // Notify all followers of the reposter.
    const { data: me } = await supabase.from('users').select('username').eq('id', reposter);
    const myName = me?.[0]?.username || 'Someone';
    const { data: followers } = await supabase.from('follows').select('follower_id').eq('following_id', reposter);
    await Promise.all((followers || []).map((f) =>
      createNotification(f.follower_id, reposter, 'repost', `${myName} сделал репост`, origId)));
    res.json({ success: true, data: created });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/posts', authRequired, async (req, res) => {
  const user_id = req.userId;
  const { content, image_url } = req.body;
  try {
    const { data, error } = await supabase.from('posts').insert([{ user_id, content: content || '', image_url: image_url || null, likes_count: 0 }]).select().single();
    if (error) throw error;
    awardAura(user_id, 10); // publishing a post
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Delete your own post (with its comments + likes).
app.delete('/api/posts/:postId', authRequired, async (req, res) => {
  try {
    const { data: rows } = await supabase.from('posts').select('user_id').eq('id', req.params.postId);
    const post = rows && rows[0];
    if (!post) return res.json({ success: false, error: 'Not found' });
    if (post.user_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    await supabase.from('comments').delete().eq('post_id', req.params.postId);
    await supabase.from('likes').delete().eq('post_id', req.params.postId);
    await supabase.from('posts').delete().eq('id', req.params.postId);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── LIKES ────────────────────────────────────────────────────────────────────

app.post('/api/posts/:postId/like', authRequired, async (req, res) => {
  const { postId } = req.params;
  const user_id = req.userId;
  try {
    const { data: existing } = await supabase.from('likes').select('id').eq('user_id', user_id).eq('post_id', postId);
    const { data: post } = await supabase.from('posts').select('likes_count, user_id').eq('id', postId);
    if (!post || post.length === 0) return res.json({ success: false, error: 'Post not found' });
    if (existing && existing.length > 0) {
      await supabase.from('likes').delete().eq('user_id', user_id).eq('post_id', postId);
      const newCount = Math.max(0, (post[0].likes_count || 1) - 1);
      await supabase.from('posts').update({ likes_count: newCount }).eq('id', postId);
      return res.json({ success: true, liked: false, likes_count: newCount });
    }
    await supabase.from('likes').insert([{ user_id, post_id: postId }]);
    const newCount = (post[0].likes_count || 0) + 1;
    await supabase.from('posts').update({ likes_count: newCount }).eq('id', postId);
    const { data: liker } = await supabase.from('users').select('username').eq('id', user_id);
    await createNotification(post[0].user_id, user_id, 'like', `${liker?.[0]?.username || 'Someone'} liked your post`, postId);
    awardAura(post[0].user_id, 2); // receiving a like
    res.json({ success: true, liked: true, likes_count: newCount });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── COMMENTS ─────────────────────────────────────────────────────────────────

app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const { data: comments, error } = await supabase.from('comments').select('*').eq('post_id', req.params.postId).order('created_at', { ascending: true });
    if (error) throw error;
    const enriched = await Promise.all((comments || []).map(async (c) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', c.user_id);
      return { ...c, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/posts/:postId/comments', authRequired, async (req, res) => {
  const { postId } = req.params;
  const user_id = req.userId;
  const { content } = req.body;
  try {
    const { data, error } = await supabase.from('comments').insert([{ post_id: postId, user_id, content }]).select().single();
    if (error) throw error;
    awardAura(user_id, 3); // writing a comment
    const { data: post } = await supabase.from('posts').select('user_id').eq('id', postId);
    const { data: commenter } = await supabase.from('users').select('username').eq('id', user_id);
    if (post?.[0]) {
      await createNotification(post[0].user_id, user_id, 'comment', `${commenter?.[0]?.username || 'Someone'} commented on your post`, postId);
    }
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/comments/:commentId', authRequired, async (req, res) => {
  try {
    const { data: existing } = await supabase.from('comments').select('user_id').eq('id', req.params.commentId);
    if (!existing || existing.length === 0) return res.json({ success: false, error: 'Not found' });
    if (existing[0].user_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    const { error } = await supabase.from('comments').delete().eq('id', req.params.commentId);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Edit your own comment.
app.put('/api/comments/:commentId', authRequired, async (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.json({ success: false, error: 'Empty comment' });
  try {
    const { data: existing } = await supabase.from('comments').select('user_id').eq('id', req.params.commentId);
    if (!existing || existing.length === 0) return res.json({ success: false, error: 'Not found' });
    if (existing[0].user_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    // Try with is_edited; if that column doesn't exist yet, fall back.
    let { data, error } = await supabase.from('comments')
      .update({ content: content.trim(), is_edited: true }).eq('id', req.params.commentId).select().single();
    if (error) {
      ({ data, error } = await supabase.from('comments')
        .update({ content: content.trim() }).eq('id', req.params.commentId).select().single());
    }
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── STORIES ──────────────────────────────────────────────────────────────────

app.get('/api/stories', async (req, res) => {
  try {
    const { data: stories, error } = await supabase.from('stories').select('*').gt('expires_at', new Date().toISOString()).order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all((stories || []).map(async (s) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', s.user_id);
      return { ...s, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/stories/upload', authRequired, async (req, res) => {
  const { image_base64 } = req.body;
  const user_id = req.userId;
  try {
    const buffer = Buffer.from(image_base64, 'base64');
    const fileName = `${user_id}_story_${Date.now()}.jpg`;
    const { error: uploadError } = await supabase.storage.from('avatars').upload(fileName, buffer, { contentType: 'image/jpeg', upsert: true });
    if (uploadError) throw uploadError;
    const { data: urlData } = supabase.storage.from('avatars').getPublicUrl(fileName);
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const { data, error } = await supabase.from('stories').insert([{ user_id, image_url: urlData.publicUrl, expires_at: expiresAt }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/stories/:storyId', authRequired, async (req, res) => {
  try {
    const { data: s } = await supabase.from('stories').select('user_id').eq('id', req.params.storyId);
    if (!s || s.length === 0) return res.json({ success: false, error: 'Not found' });
    if (s[0].user_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    const { error } = await supabase.from('stories').delete().eq('id', req.params.storyId);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// All stories by a user (including expired) — for the profile "History" archive.
app.get('/api/stories/user/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('stories')
      .select('*').eq('user_id', req.params.userId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── STORY STATS (views / likes / replies — Instagram-style) ─────────────────
// Requires the story_events + profile_views tables (see migrations/analytics.sql).

async function recordStoryEvent(storyId, userId, type) {
  try {
    await supabase.from('story_events')
      .upsert([{ story_id: storyId, user_id: userId, type }],
        { onConflict: 'story_id,user_id,type', ignoreDuplicates: true });
  } catch (_) {}
}

app.post('/api/stories/:id/view', authRequired, async (req, res) => {
  await recordStoryEvent(req.params.id, req.userId, 'view');
  res.json({ success: true });
});
app.post('/api/stories/:id/like-stat', authRequired, async (req, res) => {
  await recordStoryEvent(req.params.id, req.userId, 'like');
  res.json({ success: true });
});
app.post('/api/stories/:id/reply-stat', authRequired, async (req, res) => {
  await recordStoryEvent(req.params.id, req.userId, 'reply');
  res.json({ success: true });
});

// Full stats for one story — only its author can see them.
app.get('/api/stories/:id/stats', authRequired, async (req, res) => {
  try {
    const { data: st } = await supabase.from('stories')
      .select('user_id').eq('id', req.params.id);
    if (!st?.[0] || st[0].user_id !== req.userId) {
      return res.json({ success: false, error: 'Not your story' });
    }
    const { data: events } = await supabase.from('story_events')
      .select('user_id, type').eq('story_id', req.params.id);
    const byUser = {};
    for (const ev of events || []) {
      byUser[ev.user_id] = byUser[ev.user_id] || { view: false, like: false, reply: false };
      byUser[ev.user_id][ev.type] = true;
    }
    const ids = Object.keys(byUser);
    let viewers = [];
    if (ids.length > 0) {
      const { data: users } = await supabase.from('users')
        .select('id, username, avatar_url').in('id', ids);
      viewers = (users || []).map((u) => ({
        id: u.id, username: u.username, avatar_url: u.avatar_url,
        liked: byUser[u.id].like, replied: byUser[u.id].reply,
      }));
    }
    const count = (t) => (events || []).filter((e) => e.type === t).length;
    res.json({
      success: true,
      views: count('view'), likes: count('like'), replies: count('reply'),
      viewers,
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── HOME FEED: friends activity (last events from people you follow) ────────
app.get('/api/feed/activity', authRequired, async (req, res) => {
  try {
    const { data: follows } = await supabase.from('follows')
      .select('following_id').eq('follower_id', req.userId).limit(50);
    const ids = (follows || []).map((f) => f.following_id);
    if (ids.length === 0) return res.json({ success: true, data: [] });
    const [posts, stories] = await Promise.all([
      supabase.from('posts').select('user_id, created_at')
        .in('user_id', ids).order('created_at', { ascending: false }).limit(6),
      supabase.from('stories').select('user_id, created_at')
        .in('user_id', ids).order('created_at', { ascending: false }).limit(6),
    ]);
    const events = [
      ...((posts.data || []).map((p) => ({ ...p, type: 'post' }))),
      ...((stories.data || []).map((s) => ({ ...s, type: 'story' }))),
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 8);
    const uids = [...new Set(events.map((e) => e.user_id))];
    const { data: users } = await supabase.from('users')
      .select('id, username, avatar_url').in('id', uids);
    const byId = Object.fromEntries((users || []).map((u) => [u.id, u]));
    res.json({
      success: true,
      data: events.map((e) => ({
        type: e.type,
        created_at: e.created_at,
        username: byId[e.user_id]?.username || '',
        avatar_url: byId[e.user_id]?.avatar_url || null,
      })),
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── WEEKLY AI PLAN ("Неделя для тебя" — cached client-side per week) ────────
app.get('/api/ai/week', authRequired, async (req, res) => {
  const lang = req.query.lang === 'ru' ? 'ru' : 'en';
  try {
    const year = new Date().getFullYear();
    const { data: goals } = await supabase.from('goals')
      .select('title, category, progress, status')
      .eq('user_id', req.userId).eq('year', year);
    const list = goals || [];
    const goalsText = list.length
      ? list.map((g) => `- ${g.title} (${g.progress}%${g.status === 'done' ? ', done' : ''})`).join('\n')
      : (lang === 'ru' ? 'нет целей' : 'no goals');
    const system = lang === 'ru'
      ? 'Ты — коуч Sigmacta. Составь короткий персональный план на эту неделю: ' +
        '1) главная цель недели, 2) челлендж недели, 3) полезная привычка, 4) короткий мотивирующий совет. ' +
        'Каждый пункт с новой строки, начинай с "- ". Без markdown и звёздочек. Максимум 4 строки. Отвечай ТОЛЬКО по-русски.'
      : 'You are the Sigmacta coach. Build a short personal plan for this week: ' +
        '1) main goal of the week, 2) weekly challenge, 3) useful habit, 4) short motivating tip. ' +
        'Each item on a new line starting with "- ". No markdown or asterisks. Max 4 lines. Reply ONLY in English.';
    const reply = await callGemini(system, [
      { role: 'user', text: lang === 'ru'
          ? `Мои цели:\n${goalsText}\n\nСоставь план недели.`
          : `My goals:\n${goalsText}\n\nBuild my weekly plan.` },
    ]);
    res.json({
      success: true,
      text: reply || (lang === 'ru'
        ? '- Выбери одну цель и продвинь её на 10% на этой неделе.\n- Челлендж: 3 дня подряд без пропуска.\n- Привычка: 10 минут в день на главное.\n- Маленькие шаги каждый день сильнее рывков.'
        : '- Pick one goal and push it 10% forward this week.\n- Challenge: 3 days in a row without skipping.\n- Habit: 10 focused minutes a day.\n- Small daily steps beat big bursts.'),
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── DAILY REWARD (+5 Aura, once per day; needs users.last_daily column) ─────
app.post('/api/daily-reward', authRequired, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const { data } = await supabase.from('users')
      .select('aura, last_daily').eq('id', req.userId);
    const u = data?.[0];
    if (!u) return res.json({ success: false, error: 'User not found' });
    if ((u.last_daily || '').toString().slice(0, 10) === today) {
      return res.json({ success: true, claimed: false, aura: u.aura || 0 });
    }
    const newAura = (u.aura || 0) + 5;
    const { error } = await supabase.from('users')
      .update({ aura: newAura, last_daily: today }).eq('id', req.userId);
    if (error) throw error;
    res.json({ success: true, claimed: true, aura: newAura, bonus: 5 });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── PROFILE ANALYTICS ────────────────────────────────────────────────────────

// Record a profile visit (unique per visitor).
app.post('/api/users/:id/visit', authRequired, async (req, res) => {
  if (req.params.id !== req.userId) {
    try {
      await supabase.from('profile_views')
        .upsert([{ profile_id: req.params.id, viewer_id: req.userId }],
          { onConflict: 'profile_id,viewer_id', ignoreDuplicates: true });
    } catch (_) {}
  }
  res.json({ success: true });
});

// Aggregated analytics for the current user's own profile.
app.get('/api/me/analytics', authRequired, async (req, res) => {
  const uid = req.userId;
  try {
    const { count: visits } = await supabase.from('profile_views')
      .select('id', { count: 'exact', head: true }).eq('profile_id', uid);
    const { data: posts } = await supabase.from('posts')
      .select('id, likes_count').eq('user_id', uid);
    const postIds = (posts || []).map((p) => p.id);
    const postLikes = (posts || []).reduce((s, p) => s + (p.likes_count || 0), 0);
    let comments = 0;
    if (postIds.length > 0) {
      const { count } = await supabase.from('comments')
        .select('id', { count: 'exact', head: true }).in('post_id', postIds);
      comments = count || 0;
    }
    const { data: stories } = await supabase.from('stories')
      .select('id').eq('user_id', uid);
    const storyIds = (stories || []).map((s) => s.id);
    let storyViews = 0, storyLikes = 0;
    if (storyIds.length > 0) {
      const { count: v } = await supabase.from('story_events')
        .select('id', { count: 'exact', head: true })
        .in('story_id', storyIds).eq('type', 'view');
      const { count: l } = await supabase.from('story_events')
        .select('id', { count: 'exact', head: true })
        .in('story_id', storyIds).eq('type', 'like');
      storyViews = v || 0;
      storyLikes = l || 0;
    }
    res.json({
      success: true,
      data: {
        profile_visits: visits || 0,
        post_likes: postLikes,
        comments,
        story_views: storyViews,
        story_likes: storyLikes,
        reach: postLikes + comments + storyViews + (visits || 0),
      },
    });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

app.get('/api/notifications', authRequired, async (req, res) => {
  const userId = req.userId;
  try {
    const { data, error } = await supabase.from('notifications').select('*').eq('user_id', userId).order('created_at', { ascending: false }).limit(50);
    if (error) throw error;
    const enriched = await Promise.all((data || []).map(async (n) => {
      const { data: from } = await supabase.from('users').select('username, avatar_url').eq('id', n.from_user_id);
      return { ...n, from_username: from?.[0]?.username, from_avatar: from?.[0]?.avatar_url };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/notifications/:notifId/read', authRequired, async (req, res) => {
  try {
    const { error } = await supabase.from('notifications').update({ is_read: true }).eq('id', req.params.notifId).eq('user_id', req.userId);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/notifications/read-all', authRequired, async (req, res) => {
  try {
    const { error } = await supabase.from('notifications').update({ is_read: true }).eq('user_id', req.userId);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── REELS ────────────────────────────────────────────────────────────────────

app.get('/api/reels', async (req, res) => {
  const { userId } = req.query;
  try {
    const { data: reels, error } = await supabase.from('reels').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all((reels || []).map(async (reel) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', reel.user_id);
      let isLiked = false;
      if (userId) {
        const { data: like } = await supabase.from('reel_likes').select('id').eq('user_id', userId).eq('reel_id', reel.id);
        isLiked = !!(like && like.length > 0);
      }
      return { ...reel, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_liked: isLiked };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/reels', authRequired, async (req, res) => {
  const user_id = req.userId;
  const { video_url, caption } = req.body;
  if (!video_url) return res.json({ success: false, error: 'Missing fields' });
  try {
    const { data, error } = await supabase.from('reels').insert([{ user_id, video_url, caption: caption || '', likes_count: 0 }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/reels/:reelId/like', authRequired, async (req, res) => {
  const { reelId } = req.params;
  const user_id = req.userId;
  try {
    const { data: existing } = await supabase.from('reel_likes').select('id').eq('user_id', user_id).eq('reel_id', reelId);
    const { data: reel } = await supabase.from('reels').select('likes_count').eq('id', reelId);
    if (!reel || reel.length === 0) return res.json({ success: false, error: 'Reel not found' });
    if (existing && existing.length > 0) {
      await supabase.from('reel_likes').delete().eq('user_id', user_id).eq('reel_id', reelId);
      const newCount = Math.max(0, (reel[0].likes_count || 1) - 1);
      await supabase.from('reels').update({ likes_count: newCount }).eq('id', reelId);
      return res.json({ success: true, liked: false, likes_count: newCount });
    }
    await supabase.from('reel_likes').insert([{ user_id, reel_id: reelId }]);
    const newCount = (reel[0].likes_count || 0) + 1;
    await supabase.from('reels').update({ likes_count: newCount }).eq('id', reelId);
    res.json({ success: true, liked: true, likes_count: newCount });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── CHATS ────────────────────────────────────────────────────────────────────

app.get('/api/chats', authRequired, async (req, res) => {
  const userId = req.userId;
  try {
    const { data: chats, error } = await supabase.from('chats').select('*').or(`user1_id.eq.${userId},user2_id.eq.${userId}`);
    if (error) throw error;
    const enriched = await Promise.all((chats || []).map(async (chat) => {
      const otherId = chat.user1_id === userId ? chat.user2_id : chat.user1_id;
      const { data: other } = await supabase.from('users').select('username, avatar_url').eq('id', otherId);
      return { ...chat, name: other?.[0]?.username || 'User', avatar: other?.[0]?.avatar_url || null, other_user_id: otherId };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/chats/get-or-create', authRequired, async (req, res) => {
  const user1_id = req.userId;
  const { user2_id } = req.body;
  if (!user2_id) return res.json({ success: false, error: 'Missing user ids' });
  try {
    const { data: existing } = await supabase.from('chats').select('*').or(`and(user1_id.eq.${user1_id},user2_id.eq.${user2_id}),and(user1_id.eq.${user2_id},user2_id.eq.${user1_id})`);
    if (existing && existing.length > 0) return res.json({ success: true, data: existing[0] });
    const { data, error } = await supabase.from('chats').insert([{ user1_id, user2_id }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── MESSAGES ─────────────────────────────────────────────────────────────────

app.get('/api/messages/:chatId', authRequired, async (req, res) => {
  try {
    // Only participants of the chat may read its messages.
    const { data: chat } = await supabase.from('chats').select('user1_id, user2_id').eq('id', req.params.chatId);
    if (!chat || chat.length === 0) return res.json({ success: false, error: 'Chat not found' });
    if (chat[0].user1_id !== req.userId && chat[0].user2_id !== req.userId) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }
    // Opening the chat = reading the other person's messages (Telegram ✓✓).
    await supabase.from('messages')
      .update({ is_read: true })
      .eq('chat_id', req.params.chatId)
      .neq('sender_id', req.userId)
      .eq('is_read', false);
    io.emit('messages_read', { chatId: req.params.chatId, reader: req.userId });
    const { data, error } = await supabase.from('messages').select('*').eq('chat_id', req.params.chatId).order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/messages', authRequired, async (req, res) => {
  const { chat_id, content, message_type, media_url } = req.body;
  const sender_id = req.userId;
  try {
    // The sender must be a participant of the chat.
    const { data: chat } = await supabase.from('chats').select('user1_id, user2_id').eq('id', chat_id);
    if (!chat || chat.length === 0) return res.json({ success: false, error: 'Chat not found' });
    if (chat[0].user1_id !== sender_id && chat[0].user2_id !== sender_id) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }
    const { data, error } = await supabase.from('messages').insert([{
      chat_id, sender_id, content: content || '',
      message_type: message_type || 'text',
      media_url: media_url || null
    }]).select().single();
    if (error) throw error;
    await supabase.from('chats').update({ last_message: content }).eq('id', chat_id);
    io.emit('receive_message', data);
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/messages/:messageId', authRequired, async (req, res) => {
  try {
    const { data: m } = await supabase.from('messages').select('sender_id').eq('id', req.params.messageId);
    if (!m || m.length === 0) return res.json({ success: false, error: 'Not found' });
    if (m[0].sender_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    const { error } = await supabase.from('messages').delete().eq('id', req.params.messageId);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.put('/api/messages/:messageId', authRequired, async (req, res) => {
  const { content } = req.body;
  try {
    const { data: m } = await supabase.from('messages').select('sender_id').eq('id', req.params.messageId);
    if (!m || m.length === 0) return res.json({ success: false, error: 'Not found' });
    if (m[0].sender_id !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
    const { data, error } = await supabase.from('messages').update({ content, is_edited: true }).eq('id', req.params.messageId).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── ADMIN ────────────────────────────────────────────────────────────────────
// All admin routes require a valid token AND is_admin = true.

app.get('/api/admin/stats', authRequired, adminOnly, async (req, res) => {
  try {
    const out = { online: onlineCount() };
    for (const t of ['users', 'posts', 'comments', 'messages', 'stories', 'reels']) {
      const { count } = await supabase.from(t).select('*', { count: 'exact', head: true });
      out[t] = count || 0;
    }
    res.json({ success: true, data: out });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/admin/users', authRequired, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, username, email, is_admin, is_verified, is_banned, ban_reason, followers_count, created_at')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Remove a user and all dependent rows (some tables lack ON DELETE CASCADE).
async function deleteUserCascade(id) {
  await supabase.from('messages').delete().eq('sender_id', id);
  await supabase.from('chats').delete().or(`user1_id.eq.${id},user2_id.eq.${id}`);
  await supabase.from('follows').delete().or(`follower_id.eq.${id},following_id.eq.${id}`);
  await supabase.from('likes').delete().eq('user_id', id);
  await supabase.from('reel_likes').delete().eq('user_id', id);
  await supabase.from('comments').delete().eq('user_id', id);
  await supabase.from('stories').delete().eq('user_id', id);
  await supabase.from('reels').delete().eq('user_id', id);
  await supabase.from('posts').delete().eq('user_id', id);
  await supabase.from('goals').delete().eq('user_id', id);
  await supabase.from('notifications').delete().or(`user_id.eq.${id},from_user_id.eq.${id}`);
  const { error } = await supabase.from('users').delete().eq('id', id);
  if (error) throw error;
}

app.delete('/api/admin/users/:id', authRequired, adminOnly, async (req, res) => {
  const id = req.params.id;
  try {
    if (id === req.userId) {
      return res.json({ success: false, error: 'You cannot delete your own admin account' });
    }
    await deleteUserCascade(id);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Self-service account deletion (required by Google Play for apps with
// account creation). Deletes the caller's account and all their content.
app.delete('/api/account', authRequired, async (req, res) => {
  try {
    await deleteUserCascade(req.userId);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Ban / unban (with reason → the user gets a notification)
app.post('/api/admin/users/:id/ban', authRequired, adminOnly, async (req, res) => {
  try {
    const reason = (req.body && req.body.reason) || '';
    const { error } = await supabase.from('users')
      .update({ is_banned: true, ban_reason: reason }).eq('id', req.params.id);
    if (error) throw error;
    await createNotification(req.params.id, req.userId, 'admin',
      `Your account has been blocked.${reason ? ' Reason: ' + reason : ''}`);
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/admin/users/:id/unban', authRequired, adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from('users')
      .update({ is_banned: false, ban_reason: null }).eq('id', req.params.id);
    if (error) throw error;
    await createNotification(req.params.id, req.userId, 'admin', 'Your account has been unblocked.');
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Verification checkmark (toggle → notify)
app.post('/api/admin/users/:id/verify', authRequired, adminOnly, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('is_verified').eq('id', req.params.id);
    const next = !(data?.[0]?.is_verified === true);
    const { error } = await supabase.from('users').update({ is_verified: next }).eq('id', req.params.id);
    if (error) throw error;
    await createNotification(req.params.id, req.userId, 'admin',
      next ? 'Your account has been verified ✓' : 'Your verification was removed.');
    res.json({ success: true, is_verified: next });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/admin/users/:id/toggle-admin', authRequired, adminOnly, async (req, res) => {
  try {
    const { data } = await supabase.from('users').select('is_admin').eq('id', req.params.id);
    const next = !(data?.[0]?.is_admin === true);
    const { error } = await supabase.from('users').update({ is_admin: next }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true, is_admin: next });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/admin/posts', authRequired, adminOnly, async (req, res) => {
  try {
    const { data: posts, error } = await supabase
      .from('posts').select('*').order('created_at', { ascending: false }).limit(200);
    if (error) throw error;
    const m = await usernameMap((posts || []).map((p) => p.user_id));
    res.json({ success: true, data: (posts || []).map((p) => ({ ...p, username: m[p.user_id] || 'Unknown' })) });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/admin/posts/:id', authRequired, adminOnly, async (req, res) => {
  try {
    const reason = (req.body && req.body.reason) || '';
    const { data: post } = await supabase.from('posts').select('user_id').eq('id', req.params.id);
    if (post?.[0]) {
      // No post_id on the notification — it would cascade-delete with the post.
      await createNotification(post[0].user_id, req.userId, 'admin',
        `Your post was removed by an admin.${reason ? ' Reason: ' + reason : ''}`);
    }
    const { error } = await supabase.from('posts').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/admin/comments', authRequired, adminOnly, async (req, res) => {
  try {
    const { data: comments, error } = await supabase
      .from('comments').select('*').order('created_at', { ascending: false }).limit(200);
    if (error) throw error;
    const m = await usernameMap((comments || []).map((c) => c.user_id));
    res.json({ success: true, data: (comments || []).map((c) => ({ ...c, username: m[c.user_id] || 'Unknown' })) });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/admin/stories', authRequired, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('stories').select('*').order('created_at', { ascending: false }).limit(200);
    if (error) throw error;
    const m = await usernameMap((data || []).map((s) => s.user_id));
    res.json({ success: true, data: (data || []).map((s) => ({ ...s, username: m[s.user_id] || 'Unknown' })) });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/admin/stories/:id', authRequired, adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from('stories').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/admin/reels', authRequired, adminOnly, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('reels').select('*').order('created_at', { ascending: false }).limit(200);
    if (error) throw error;
    const m = await usernameMap((data || []).map((r) => r.user_id));
    res.json({ success: true, data: (data || []).map((r) => ({ ...r, username: m[r.user_id] || 'Unknown' })) });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/admin/reels/:id', authRequired, adminOnly, async (req, res) => {
  try {
    const { error } = await supabase.from('reels').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// Manually trigger the content bots (also runs automatically on a schedule).
app.post('/api/admin/run-bots', authRequired, adminOnly, async (req, res) => {
  try {
    const posted = await runBots(supabase);
    res.json({ success: true, posted });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/admin/comments/:id', authRequired, adminOnly, async (req, res) => {
  try {
    const reason = (req.body && req.body.reason) || '';
    const { data: cm } = await supabase.from('comments').select('user_id').eq('id', req.params.id);
    if (cm?.[0]) {
      await createNotification(cm[0].user_id, req.userId, 'admin',
        `Your comment was removed by an admin.${reason ? ' Reason: ' + reason : ''}`);
    }
    const { error } = await supabase.from('comments').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── WEBSOCKET + ONLINE PRESENCE ──────────────────────────────────────────────

const onlineSockets = new Map(); // socket.id -> userId
function onlineCount() {
  return new Set([...onlineSockets.values()].filter(Boolean)).size;
}

io.on('connection', (socket) => {
  socket.on('user_connect', (data) => {
    const uid = data && (data.userId || data.id) ? (data.userId || data.id) : data;
    if (uid) onlineSockets.set(socket.id, String(uid));
    io.emit('user_online', data);
  });
  socket.on('send_message', (data) => io.emit('receive_message', data));
  socket.on('disconnect', () => onlineSockets.delete(socket.id));
});

// ─── KEEP-ALIVE (anti-sleep for free Render) ─────────────────────────────────
// Render's free instance sleeps after ~15 min without inbound traffic, which
// causes a ~50s cold start. We ping our own public URL every 10 min so it
// never goes idle. No external service or card needed.
const SELF_URL = process.env.SELF_URL || 'https://sigma-social-backend.onrender.com';
setInterval(() => {
  fetch(`${SELF_URL}/api/health`).catch(() => {});
}, 10 * 60 * 1000);

// ─── CONTENT BOTS (disabled — channels/bots removed for the Sigmacta app) ─────
// setTimeout(() => { runBots(supabase).then((n) => console.log(`🤖 bots posted ${n}`)).catch(() => {}); }, 25 * 1000);
// setInterval(() => { runBots(supabase).catch(() => {}); }, 6 * 60 * 60 * 1000);

// ─── START ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => console.log(`✅ SIGMA SOCIAL SERVER on port ${PORT}`));
