import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { createServer } from 'http';
import { Server } from 'socket.io';

dotenv.config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.options('*', cors());
app.use(express.json());

const SUPABASE_URL = 'https://uvbyxkrtyjqrorxnckvw.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV2Ynl4a3J0eWpxcm9yeG5ja3Z3Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3OTg5MDM4NiwiZXhwIjoyMDk1NDY2Mzg2fQ.oP8PhoIqP8F6QJnKM4p-gujW_nfe12ZWsePg_Scc_8A';
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

app.get('/api/health', (req, res) => res.json({ success: true, message: 'Server is running!' }));

// AUTH
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;
  try {
    const { data: existingUsers } = await supabase.from('users').select('id').eq('email', email);
    if (existingUsers && existingUsers.length > 0) return res.json({ success: false, error: 'User already exists' });
    const { data, error } = await supabase.from('users').insert([{ email, username, password_hash: password, bio: '', followers_count: 0, following_count: 0 }]).select().single();
    if (error) throw error;
    res.json({ success: true, data: { user: data } });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.from('users').select('*').eq('email', email).eq('password_hash', password);
    if (error) throw error;
    if (!data || data.length === 0) return res.json({ success: false, error: 'Invalid credentials' });
    res.json({ success: true, data: { user: data[0] } });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

// USERS
app.get('/api/users', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('*');
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.get('/api/users/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    const { data, error } = await supabase.from('users').select('*').eq('id', userId);
    if (error) throw error;
    if (!data || data.length === 0) return res.json({ success: false, error: 'User not found' });
    res.json({ success: true, data: data[0] });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/users/:userId/update', async (req, res) => {
  const { userId } = req.params;
  const { username, bio, avatar_url } = req.body;
  try {
    const updateData = { username, bio };
    if (avatar_url) updateData.avatar_url = avatar_url;
    const { data, error } = await supabase.from('users').update(updateData).eq('id', userId).select();
    if (error) throw error;
    res.json({ success: true, data: data[0] });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/users/:userId/follow/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;
  try {
    const { data: existingFollow } = await supabase.from('follows').select('id').eq('follower_id', userId).eq('following_id', targetUserId);
    if (existingFollow && existingFollow.length > 0) return res.json({ success: false, error: 'Already following' });
    await supabase.from('follows').insert([{ follower_id: userId, following_id: targetUserId }]);
    const { data: targetUser } = await supabase.from('users').select('followers_count').eq('id', targetUserId);
    if (targetUser) await supabase.from('users').update({ followers_count: (targetUser[0].followers_count || 0) + 1 }).eq('id', targetUserId);
    const { data: currentUser } = await supabase.from('users').select('following_count').eq('id', userId);
    if (currentUser) await supabase.from('users').update({ following_count: (currentUser[0].following_count || 0) + 1 }).eq('id', userId);
    res.json({ success: true, message: 'Followed!' });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/users/:userId/unfollow/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;
  try {
    await supabase.from('follows').delete().eq('follower_id', userId).eq('following_id', targetUserId);
    const { data: targetUser } = await supabase.from('users').select('followers_count').eq('id', targetUserId);
    if (targetUser) await supabase.from('users').update({ followers_count: Math.max(0, (targetUser[0].followers_count || 1) - 1) }).eq('id', targetUserId);
    const { data: currentUser } = await supabase.from('users').select('following_count').eq('id', userId);
    if (currentUser) await supabase.from('users').update({ following_count: Math.max(0, (currentUser[0].following_count || 1) - 1) }).eq('id', userId);
    res.json({ success: true, message: 'Unfollowed!' });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.get('/api/users/:userId/following/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;
  try {
    const { data } = await supabase.from('follows').select('id').eq('follower_id', userId).eq('following_id', targetUserId);
    res.json({ isFollowing: !!(data && data.length > 0) });
  } catch (error) { res.json({ isFollowing: false }); }
});

// POSTS
app.get('/api/posts', async (req, res) => {
  const { userId } = req.query;
  try {
    const { data: posts, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    const enrichedPosts = await Promise.all(posts.map(async (post) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', post.user_id);
      const { data: comments } = await supabase.from('comments').select('id').eq('post_id', post.id);
      let isLiked = false;
      if (userId) {
        const { data: like } = await supabase.from('likes').select('id').eq('user_id', userId).eq('post_id', post.id);
        isLiked = !!(like && like.length > 0);
      }
      return {
        ...post,
        username: user?.[0]?.username || 'Unknown',
        user_avatar: user?.[0]?.avatar_url || null,
        is_liked: isLiked,
        comments_count: comments?.length || 0,
      };
    }));
    res.json({ success: true, data: enrichedPosts });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/posts', async (req, res) => {
  const { user_id, content } = req.body;
  if (!content || !user_id) return res.json({ success: false, error: 'Missing required fields' });
  try {
    const { data, error } = await supabase.from('posts').insert([{ user_id, content, likes_count: 0 }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

// LIKES
app.post('/api/posts/:postId/like', async (req, res) => {
  const { postId } = req.params;
  const { user_id } = req.body;
  try {
    const { data: existingLike } = await supabase.from('likes').select('id').eq('user_id', user_id).eq('post_id', postId);
    if (existingLike && existingLike.length > 0) {
      await supabase.from('likes').delete().eq('user_id', user_id).eq('post_id', postId);
      const { data: post } = await supabase.from('posts').select('likes_count').eq('id', postId);
      const newCount = Math.max(0, (post[0].likes_count || 1) - 1);
      await supabase.from('posts').update({ likes_count: newCount }).eq('id', postId);
      res.json({ success: true, liked: false, likes_count: newCount });
    } else {
      await supabase.from('likes').insert([{ user_id, post_id: postId }]);
      const { data: post } = await supabase.from('posts').select('likes_count').eq('id', postId);
      const newCount = (post[0].likes_count || 0) + 1;
      await supabase.from('posts').update({ likes_count: newCount }).eq('id', postId);
      res.json({ success: true, liked: true, likes_count: newCount });
    }
  } catch (error) { res.json({ success: false, error: error.message }); }
});

// COMMENTS
app.get('/api/posts/:postId/comments', async (req, res) => {
  const { postId } = req.params;
  try {
    const { data: comments, error } = await supabase.from('comments').select('*').eq('post_id', postId).order('created_at', { ascending: true });
    if (error) throw error;
    const enriched = await Promise.all((comments || []).map(async (comment) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', comment.user_id);
      return { ...comment, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null };
    }));
    res.json({ success: true, data: enriched });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/posts/:postId/comments', async (req, res) => {
  const { postId } = req.params;
  const { user_id, content } = req.body;
  try {
    const { data, error } = await supabase.from('comments').insert([{ post_id: postId, user_id, content }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.delete('/api/comments/:commentId', async (req, res) => {
  const { commentId } = req.params;
  try {
    const { error } = await supabase.from('comments').delete().eq('id', commentId);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

// STORIES
app.get('/api/stories', async (req, res) => {
  try {
    const { data: stories, error } = await supabase.from('stories').select('*').gt('expires_at', new Date().toISOString()).order('created_at', { ascending: false });
    if (error) throw error;
    const enriched = await Promise.all((stories || []).map(async (story) => {
      const { data: user } = await supabase.from('users').select('username, avatar_url').eq('id', story.user_id);
      return { ...story, username: user?.[0]?.username || 'Unknown', user_avatar: user?.[0]?.avatar_url || null };
    }));
    res.json({ success: true, data: enriched });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/stories', async (req, res) => {
  const { user_id, image_url } = req.body;
  try {
    const { data, error } = await supabase.from('stories').insert([{ user_id, image_url }]).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.delete('/api/stories/:storyId', async (req, res) => {
  const { storyId } = req.params;
  try {
    const { error } = await supabase.from('stories').delete().eq('id', storyId);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

// CHATS
app.get('/api/chats', async (req, res) => {
  const { userId } = req.query;
  try {
    const { data: chats, error } = await supabase.from('chats').select('*').or(`user1_id.eq.${userId},user2_id.eq.${userId}`);
    if (error) throw error;
    const enrichedChats = await Promise.all((chats || []).map(async (chat) => {
      const otherUserId = chat.user1_id === userId ? chat.user2_id : chat.user1_id;
      const { data: otherUser } = await supabase.from('users').select('username, avatar_url').eq('id', otherUserId);
      return { ...chat, name: otherUser?.[0]?.username || 'User', avatar: otherUser?.[0]?.avatar_url || null, other_user_id: otherUserId };
    }));
    res.json({ success: true, data: enrichedChats });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/chats/get-or-create', async (req, res) => {
  const { user1_id, user2_id } = req.body;
  if (!user1_id || !user2_id) return res.json({ success: false, error: 'Missing user ids' });
  try {
    const { data: existingChats } = await supabase.from('chats').select('*').or(`and(user1_id.eq.${user1_id},user2_id.eq.${user2_id}),and(user1_id.eq.${user2_id},user2_id.eq.${user1_id})`);
    if (existingChats && existingChats.length > 0) return res.json({ success: true, data: existingChats[0] });
    const { data: newChat, error } = await supabase.from('chats').insert([{ user1_id, user2_id }]).select().single();
    if (error) throw error;
    res.json({ success: true, data: newChat });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

// MESSAGES
app.get('/api/messages/:chatId', async (req, res) => {
  const { chatId } = req.params;
  try {
    const { data, error } = await supabase.from('messages').select('*').eq('chat_id', chatId).order('created_at', { ascending: true });
    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.post('/api/messages', async (req, res) => {
  const { chat_id, sender_id, content } = req.body;
  try {
    const { data, error } = await supabase.from('messages').insert([{ chat_id, sender_id, content }]).select().single();
    if (error) throw error;
    await supabase.from('chats').update({ last_message: content }).eq('id', chat_id);
    io.emit('receive_message', data);
    res.json({ success: true, data });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.delete('/api/messages/:messageId', async (req, res) => {
  const { messageId } = req.params;
  try {
    const { error } = await supabase.from('messages').delete().eq('id', messageId);
    if (error) throw error;
    res.json({ success: true });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

app.put('/api/messages/:messageId', async (req, res) => {
  const { messageId } = req.params;
  const { content } = req.body;
  try {
    const { data, error } = await supabase.from('messages').update({ content, is_edited: true }).eq('id', messageId).select().single();
    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) { res.json({ success: false, error: error.message }); }
});

// WEBSOCKET
io.on('connection', (socket) => {
  socket.on('user_connect', (data) => { io.emit('user_online', data); });
  socket.on('send_message', (data) => { io.emit('receive_message', data); });
  socket.on('disconnect', () => {});
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => { console.log(`✅ ΣIGMA SOCIAL SERVER running on port ${PORT}`); });