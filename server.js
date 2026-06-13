import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import rateLimit from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { RECOVERY_WORDS } from './wordlist.js';

dotenv.config();

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
  next();
}

// ─── HEALTH ───────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => res.json({ success: true, message: 'Server is running!' }));

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
    const token = signToken({ sub: user.id, username: user.username });
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

app.get('/api/users/:userId', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*').eq('id', req.params.userId);
    if (error) throw error;
    if (!data || data.length === 0) return res.json({ success: false, error: 'User not found' });
    res.json({ success: true, data: data[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/users/:userId/update', authRequired, async (req, res) => {
  if (req.params.userId !== req.userId) return res.status(403).json({ success: false, error: 'Forbidden' });
  const { username, bio, avatar_url, headline, about, location, work, website } = req.body;
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
    const { data, error } = await supabase.from('users').update(update).eq('id', req.params.userId).select();
    if (error) throw error;
    res.json({ success: true, data: data[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/users/:userId/follow/:targetUserId', authRequired, async (req, res) => {
  const userId = req.userId;
  const { targetUserId } = req.params;
  try {
    const { data: ex } = await supabase.from('follows').select('id').eq('follower_id', userId).eq('following_id', targetUserId);
    if (ex && ex.length > 0) return res.json({ success: false, error: 'Already following' });
    await supabase.from('follows').insert([{ follower_id: userId, following_id: targetUserId }]);
    const { data: target } = await supabase.from('users').select('followers_count').eq('id', targetUserId);
    const { data: current } = await supabase.from('users').select('following_count, username').eq('id', userId);
    if (target) await supabase.from('users').update({ followers_count: (target[0].followers_count || 0) + 1 }).eq('id', targetUserId);
    if (current) await supabase.from('users').update({ following_count: (current[0].following_count || 0) + 1 }).eq('id', userId);
    await createNotification(targetUserId, userId, 'follow', `${current?.[0]?.username || 'Someone'} started following you`);
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

// ─── POSTS ────────────────────────────────────────────────────────────────────

// Following feed
app.get('/api/posts/following', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.json({ success: true, data: [] });
  try {
    const { data: follows } = await supabase.from('follows').select('following_id').eq('follower_id', userId);
    const ids = (follows || []).map(f => f.following_id);
    if (ids.length === 0) return res.json({ success: true, data: [] });
    const { data: posts, error } = await supabase.from('posts').select('*').in('user_id', ids).order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all(posts.map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', post.user_id);
      const { data: comments } = await supabase.from('comments').select('id').eq('post_id', post.id);
      const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
      return { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_liked: !!(like && like.length > 0), comments_count: comments?.length || 0 };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.get('/api/posts', async (req, res) => {
  const { userId } = req.query;
  try {
    const { data: posts, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all(posts.map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', post.user_id);
      const { data: comments } = await supabase.from('comments').select('id').eq('post_id', post.id);
      let isLiked = false;
      if (userId) {
        const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
        isLiked = !!(like && like.length > 0);
      }
      return { ...post, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null, is_liked: isLiked, comments_count: comments?.length || 0 };
    }));
    res.json({ success: true, data: enriched });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/posts', authRequired, async (req, res) => {
  const user_id = req.userId;
  const { content, image_url } = req.body;
  try {
    const { data, error } = await supabase.from('posts').insert([{ user_id, content: content || '', image_url: image_url || null, likes_count: 0 }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
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

// ─── NOTIFICATIONS ────────────────────────────────────────────────────────────

app.get('/api/notifications', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.json({ success: false, error: 'Missing userId' });
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

app.get('/api/chats', async (req, res) => {
  const { userId } = req.query;
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

app.get('/api/messages/:chatId', async (req, res) => {
  try {
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

// ─── WEBSOCKET ────────────────────────────────────────────────────────────────

io.on('connection', (socket) => {
  socket.on('user_connect', (data) => io.emit('user_online', data));
  socket.on('send_message', (data) => io.emit('receive_message', data));
  socket.on('disconnect', () => {});
});

// ─── START ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => console.log(`✅ SIGMA SOCIAL SERVER on port ${PORT}`));
