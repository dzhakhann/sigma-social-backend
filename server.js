import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';
import { createServer } from 'http';
import { Server } from 'socket.io';

dotenv.config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: '*' },
});

// ===== CORS FIX =====
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.options('*', cors());

app.use(express.json());

// ===== SUPABASE CONFIG (ИСПРАВЛЕННЫЙ URL) =====
const SUPABASE_URL = 'https://uvbyxkrtyjqrorxnckvw.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InV2Ynl4a3J0eWpxcm9yeG5ja3Z3Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzk4OTAzODYsImV4cCI6MjA5NTQ2NjM4Nn0.IOiYaLIkV4d3fjFKRn0CdFI-Sg3gFsoVfwFhqhDL5P8';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: '✅ Server with PostgreSQL is running!' });
});

// ===== AUTH ENDPOINTS =====
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password } = req.body;

  try {
    const { data: existingUsers } = await supabase
      .from('users')
      .select('id')
      .eq('email', email);

    if (existingUsers && existingUsers.length > 0) {
      return res.json({ success: false, error: 'User already exists' });
    }

    const { data, error } = await supabase
      .from('users')
      .insert([
        {
          email,
          username,
          password_hash: password,
          bio: '',
          followers_count: 0,
          following_count: 0,
        },
      ])
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, data: { user: data } });
  } catch (error) {
    console.error('Register error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .eq('password_hash', password);

    if (error) throw error;

    if (!data || data.length === 0) {
      return res.json({ success: false, error: 'Invalid credentials' });
    }

    res.json({ success: true, data: { user: data[0] } });
  } catch (error) {
    console.error('Login error:', error);
    res.json({ success: false, error: error.message });
  }
});

// ===== USERS ENDPOINTS =====
app.get('/api/users', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*');

    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    console.error('Get users error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/users/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId);

    if (error) throw error;

    if (!data || data.length === 0) {
      return res.json({ success: false, error: 'User not found' });
    }

    res.json({ success: true, data: data[0] });
  } catch (error) {
    console.error('Get user error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/users/:userId/update', async (req, res) => {
  const { userId } = req.params;
  const { username, bio } = req.body;

  try {
    const { data, error } = await supabase
      .from('users')
      .update({ username, bio })
      .eq('id', userId)
      .select();

    if (error) throw error;

    res.json({ success: true, data: data[0] });
  } catch (error) {
    console.error('Update user error:', error);
    res.json({ success: false, error: error.message });
  }
});

// ===== FOLLOW ENDPOINTS =====
app.post('/api/users/:userId/follow/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;

  try {
    const { data: existingFollow } = await supabase
      .from('follows')
      .select('id')
      .eq('follower_id', userId)
      .eq('following_id', targetUserId);

    if (existingFollow && existingFollow.length > 0) {
      return res.json({ success: false, error: 'Already following' });
    }

    await supabase
      .from('follows')
      .insert([{ follower_id: userId, following_id: targetUserId }]);

    const { data: targetUser } = await supabase
      .from('users')
      .select('followers_count')
      .eq('id', targetUserId);

    if (targetUser) {
      await supabase
        .from('users')
        .update({ followers_count: (targetUser[0].followers_count || 0) + 1 })
        .eq('id', targetUserId);
    }

    const { data: currentUser } = await supabase
      .from('users')
      .select('following_count')
      .eq('id', userId);

    if (currentUser) {
      await supabase
        .from('users')
        .update({ following_count: (currentUser[0].following_count || 0) + 1 })
        .eq('id', userId);
    }

    res.json({ success: true, message: 'Followed!' });
  } catch (error) {
    console.error('Follow error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/users/:userId/unfollow/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;

  try {
    await supabase
      .from('follows')
      .delete()
      .eq('follower_id', userId)
      .eq('following_id', targetUserId);

    const { data: targetUser } = await supabase
      .from('users')
      .select('followers_count')
      .eq('id', targetUserId);

    if (targetUser) {
      await supabase
        .from('users')
        .update({ followers_count: Math.max(0, (targetUser[0].followers_count || 1) - 1) })
        .eq('id', targetUserId);
    }

    const { data: currentUser } = await supabase
      .from('users')
      .select('following_count')
      .eq('id', userId);

    if (currentUser) {
      await supabase
        .from('users')
        .update({ following_count: Math.max(0, (currentUser[0].following_count || 1) - 1) })
        .eq('id', userId);
    }

    res.json({ success: true, message: 'Unfollowed!' });
  } catch (error) {
    console.error('Unfollow error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.get('/api/users/:userId/following/:targetUserId', async (req, res) => {
  const { userId, targetUserId } = req.params;

  try {
    const { data } = await supabase
      .from('follows')
      .select('id')
      .eq('follower_id', userId)
      .eq('following_id', targetUserId);

    res.json({ isFollowing: !!(data && data.length > 0) });
  } catch (error) {
    res.json({ isFollowing: false });
  }
});

// ===== POSTS ENDPOINTS =====
app.get('/api/posts', async (req, res) => {
  try {
    const { data: posts, error } = await supabase
      .from('posts')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    const enrichedPosts = await Promise.all(
      posts.map(async (post) => {
        const { data: user } = await supabase
          .from('users')
          .select('username')
          .eq('id', post.user_id);
        return { ...post, username: user?.[0]?.username || 'Unknown' };
      })
    );

    res.json({ success: true, data: enrichedPosts });
  } catch (error) {
    console.error('Get posts error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/posts', async (req, res) => {
  const { user_id, content } = req.body;

  if (!content || !user_id) {
    return res.json({ success: false, error: 'Missing required fields' });
  }

  try {
    const { data, error } = await supabase
      .from('posts')
      .insert([{ user_id, content, likes_count: 0 }])
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    console.error('Create post error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/posts/:postId/like', async (req, res) => {
  const { postId } = req.params;

  try {
    const { data: post, error: fetchError } = await supabase
      .from('posts')
      .select('likes_count')
      .eq('id', postId);

    if (fetchError) throw fetchError;

    if (!post || post.length === 0) {
      return res.json({ success: false, error: 'Post not found' });
    }

    const { data, error } = await supabase
      .from('posts')
      .update({ likes_count: (post[0].likes_count || 0) + 1 })
      .eq('id', postId)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, data });
  } catch (error) {
    console.error('Like post error:', error);
    res.json({ success: false, error: error.message });
  }
});

// ===== CHATS ENDPOINTS =====
app.get('/api/chats', async (req, res) => {
  const { userId } = req.query;

  try {
    const { data, error } = await supabase
      .from('chats')
      .select('*')
      .or(`user1_id.eq.${userId},user2_id.eq.${userId}`);

    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) {
    console.error('Get chats error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/chats/get-or-create', async (req, res) => {
  const { user1_id, user2_id } = req.body;

  try {
    const { data: existingChats } = await supabase
      .from('chats')
      .select('*')
      .or(`and(user1_id.eq.${user1_id},user2_id.eq.${user2_id}),and(user1_id.eq.${user2_id},user2_id.eq.${user1_id})`);

    if (existingChats && existingChats.length > 0) {
      return res.json({ success: true, data: existingChats[0] });
    }

    const { data: newChat, error } = await supabase
      .from('chats')
      .insert([{ user1_id, user2_id }])
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, data: newChat });
  } catch (error) {
    console.error('Create chat error:', error);
    res.json({ success: false, error: error.message });
  }
});

// ===== MESSAGES ENDPOINTS =====
app.get('/api/messages/:chatId', async (req, res) => {
  const { chatId } = req.params;

  try {
    const { data, error } = await supabase
      .from('messages')
      .select('*')
      .eq('chat_id', chatId)
      .order('created_at', { ascending: true });

    if (error) throw error;
    res.json({ success: true, data: data || [] });
  } catch (error) {
    console.error('Get messages error:', error);
    res.json({ success: false, error: error.message });
  }
});

app.post('/api/messages', async (req, res) => {
  const { chat_id, sender_id, content } = req.body;

  try {
    const { data, error } = await supabase
      .from('messages')
      .insert([{ chat_id, sender_id, content }])
      .select()
      .single();

    if (error) throw error;

    await supabase
      .from('chats')
      .update({ last_message: content })
      .eq('id', chat_id);

    io.emit('receive_message', data);
    res.json({ success: true, data });
  } catch (error) {
    console.error('Send message error:', error);
    res.json({ success: false, error: error.message });
  }
});

// ===== WEBSOCKET =====
io.on('connection', (socket) => {
  console.log('✅ User connected:', socket.id);

  socket.on('user_connect', (data) => {
    console.log('👤 User:', data.username, 'connected');
    io.emit('user_online', data);
  });

  socket.on('send_message', (data) => {
    console.log('💬 Message:', data.content);
    io.emit('receive_message', data);
  });

  socket.on('disconnect', () => {
    console.log('🔴 User disconnected:', socket.id);
  });
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  console.log(`\n✅ ΣIGMA SOCIAL SERVER WITH POSTGRESQL`);
  console.log(`🌐 Running on http://localhost:${PORT}`);
  console.log(`📡 WebSocket: ws://localhost:${PORT}`);
  console.log(`🗄️  Database: Supabase PostgreSQL\n`);
});
