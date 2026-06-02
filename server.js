import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { createServer } from 'http';
import { Server } from 'socket.io';

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
*/

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.options('*', cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

const SUPABASE_URL = 'https://uvbyxkrtyjqrorxnckvw.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV2Ynl4a3J0eWpxcm9yeG5ja3Z3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3OTg5MDM4NiwiZXhwIjoyMDk1NDY2Mzg2fQ.oP8PhoIqP8F6QJnKM4p-gujW_nfe12ZWsePg_Scc_8A';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

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

// ─── HEALTH ───────────────────────────────────────────────────────────────────

app.get('/api/health', (req, res) => res.json({ success: true, message: 'Server is running!' }));

// ─── AUTH ─────────────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;
  try {
    const { data: existing } = await supabase.from('users').select('id').eq('email', email);
    if (existing && existing.length > 0) return res.json({ success: false, error: 'User already exists' });
    const { data, error } = await supabase.from('users').insert([{
      email, username, password_hash: password, bio: '', followers_count: 0, following_count: 0
    }]).select().single();
    if (error) throw error;
    res.json({ success: true, data: { user: data } });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.from('users').select('*').eq('email', email).eq('password_hash', password);
    if (error) throw error;
    if (!data || data.length === 0) return res.json({ success: false, error: 'Invalid credentials' });
    res.json({ success: true, data: { user: data[0] } });
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

app.post('/api/users/:userId/update', async (req, res) => {
  const { username, bio, avatar_url } = req.body;
  try {
    const update = { username, bio };
    if (avatar_url) update.avatar_url = avatar_url;
    const { data, error } = await supabase.from('users').update(update).eq('id', req.params.userId).select();
    if (error) throw error;
    res.json({ success: true, data: data[0] });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/users/:userId/follow/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;
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

app.post('/api/users/:userId/unfollow/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;
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

app.post('/api/posts', async (req, res) => {
  const { user_id, content } = req.body;
  if (!content || !user_id) return res.json({ success: false, error: 'Missing fields' });
  try {
    const { data, error } = await supabase.from('posts').insert([{ user_id, content, likes_count: 0 }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

// ─── LIKES ────────────────────────────────────────────────────────────────────

app.post('/api/posts/:postId/like', async (req, res) => {
  const { postId } = req.params;
  const { user_id } = req.body;
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

app.post('/api/posts/:postId/comments', async (req, res) => {
  const { postId } = req.params;
  const { user_id, content } = req.body;
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

app.delete('/api/comments/:commentId', async (req, res) => {
  try {
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

app.post('/api/stories/upload', async (req, res) => {
  const { user_id, image_base64 } = req.body;
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

app.delete('/api/stories/:storyId', async (req, res) => {
  try {
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

app.post('/api/notifications/:notifId/read', async (req, res) => {
  try {
    const { error } = await supabase.from('notifications').update({ is_read: true }).eq('id', req.params.notifId);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/notifications/read-all', async (req, res) => {
  const { user_id } = req.body;
  try {
    const { error } = await supabase.from('notifications').update({ is_read: true }).eq('user_id', user_id);
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

app.post('/api/reels', async (req, res) => {
  const { user_id, video_url, caption } = req.body;
  if (!user_id || !video_url) return res.json({ success: false, error: 'Missing fields' });
  try {
    const { data, error } = await supabase.from('reels').insert([{ user_id, video_url, caption: caption || '', likes_count: 0 }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.post('/api/reels/:reelId/like', async (req, res) => {
  const { reelId } = req.params;
  const { user_id } = req.body;
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

app.post('/api/chats/get-or-create', async (req, res) => {
  const { user1_id, user2_id } = req.body;
  if (!user1_id || !user2_id) return res.json({ success: false, error: 'Missing user ids' });
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

app.post('/api/messages', async (req, res) => {
  const { chat_id, sender_id, content } = req.body;
  try {
    const { data, error } = await supabase.from('messages').insert([{ chat_id, sender_id, content }]).select().single();
    if (error) throw error;
    await supabase.from('chats').update({ last_message: content }).eq('id', chat_id);
    io.emit('receive_message', data);
    res.json({ success: true, data });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.delete('/api/messages/:messageId', async (req, res) => {
  try {
    const { error } = await supabase.from('messages').delete().eq('id', req.params.messageId);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { res.json({ success: false, error: e.message }); }
});

app.put('/api/messages/:messageId', async (req, res) => {
  const { content } = req.body;
  try {
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
