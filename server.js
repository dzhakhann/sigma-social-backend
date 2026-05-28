import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { Server } from 'socket.io';

dotenv.config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: '*' },
});

app.use(cors());
app.use(express.json());

// ===== IN-MEMORY DATABASE =====
const users = new Map();
const posts = new Map();
const chats = new Map();
const messages = new Map();
const follows = new Set(); // user1_user2 format

let userIdCounter = 1;
let postIdCounter = 1;
let chatIdCounter = 1;
let messageIdCounter = 1;

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: '✅ Server is running!' });
});

// ===== AUTH ENDPOINTS =====
app.post('/api/auth/register', (req, res) => {
  const { email, username, password } = req.body;

  if (users.get(email)) {
    return res.json({ success: false, error: 'User already exists' });
  }

  const userId = `user_${userIdCounter++}`;
  users.set(email, {
    id: userId,
    email,
    username,
    password,
    bio: '',
    followers_count: 0,
    following_count: 0,
  });

  res.json({
    success: true,
    data: { user: users.get(email) },
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email);

  if (!user || user.password !== password) {
    return res.json({ success: false, error: 'Invalid credentials' });
  }

  res.json({
    success: true,
    data: { user },
  });
});

// ===== USERS ENDPOINTS =====
app.get('/api/users', (req, res) => {
  const allUsers = Array.from(users.values());
  res.json({ success: true, data: allUsers });
});

app.get('/api/users/:userId', (req, res) => {
  const { userId } = req.params;
  let user = null;

  for (const u of users.values()) {
    if (u.id === userId) {
      user = u;
      break;
    }
  }

  if (!user) {
    return res.json({ success: false, error: 'User not found' });
  }

  res.json({ success: true, data: user });
});

app.post('/api/users/:userId/update', (req, res) => {
  const { userId } = req.params;
  const { username, bio } = req.body;

  let user = null;
  for (const u of users.values()) {
    if (u.id === userId) {
      user = u;
      break;
    }
  }

  if (!user) {
    return res.json({ success: false, error: 'User not found' });
  }

  user.username = username || user.username;
  user.bio = bio || user.bio;

  res.json({ success: true, data: user });
});

// ===== FOLLOW ENDPOINTS =====
app.post('/api/users/:userId/follow/:targetUserId', (req, res) => {
  const { userId, targetUserId } = req.params;

  let user = null;
  let targetUser = null;

  for (const u of users.values()) {
    if (u.id === userId) user = u;
    if (u.id === targetUserId) targetUser = u;
  }

  if (!user || !targetUser) {
    return res.json({ success: false, error: 'User not found' });
  }

  const followKey = `${userId}_${targetUserId}`;

  if (!follows.has(followKey)) {
    follows.add(followKey);
    user.following_count = (user.following_count || 0) + 1;
    targetUser.followers_count = (targetUser.followers_count || 0) + 1;

    res.json({ success: true, message: 'Followed!' });
  } else {
    res.json({ success: false, error: 'Already following' });
  }
});

app.post('/api/users/:userId/unfollow/:targetUserId', (req, res) => {
  const { userId, targetUserId } = req.params;

  let user = null;
  let targetUser = null;

  for (const u of users.values()) {
    if (u.id === userId) user = u;
    if (u.id === targetUserId) targetUser = u;
  }

  if (!user || !targetUser) {
    return res.json({ success: false, error: 'User not found' });
  }

  const followKey = `${userId}_${targetUserId}`;

  if (follows.has(followKey)) {
    follows.delete(followKey);
    user.following_count = Math.max(0, (user.following_count || 1) - 1);
    targetUser.followers_count = Math.max(0, (targetUser.followers_count || 1) - 1);

    res.json({ success: true, message: 'Unfollowed!' });
  } else {
    res.json({ success: false, error: 'Not following' });
  }
});

app.get('/api/users/:userId/following/:targetUserId', (req, res) => {
  const { userId, targetUserId } = req.params;
  const followKey = `${userId}_${targetUserId}`;
  const isFollowing = follows.has(followKey);

  res.json({ isFollowing });
});

// ===== POSTS ENDPOINTS =====
app.get('/api/posts', (req, res) => {
  const allPosts = Array.from(posts.values())
    .sort((a, b) => b.created_at - a.created_at)
    .map(post => ({
      ...post,
      username: (() => {
        for (const user of users.values()) {
          if (user.id === post.user_id) return user.username;
        }
        return 'Anonymous';
      })(),
    }));

  res.json({ success: true, data: allPosts });
});

app.post('/api/posts', (req, res) => {
  const { user_id, content } = req.body;

  if (!content || !user_id) {
    return res.json({ success: false, error: 'Missing required fields' });
  }

  const postId = `post_${postIdCounter++}`;
  const post = {
    id: postId,
    user_id,
    content,
    likes_count: 0,
    created_at: Date.now(),
  };

  posts.set(postId, post);

  res.json({
    success: true,
    data: post,
  });
});

app.post('/api/posts/:postId/like', (req, res) => {
  const { postId } = req.params;
  const post = posts.get(postId);

  if (!post) {
    return res.json({ success: false, error: 'Post not found' });
  }

  post.likes_count++;
  res.json({ success: true, data: post });
});

// ===== CHATS ENDPOINTS =====
app.get('/api/chats', (req, res) => {
  const { userId } = req.query;
  const userChats = Array.from(chats.values()).filter(
    chat => chat.user1_id === userId || chat.user2_id === userId
  );

  res.json({ success: true, data: userChats });
});

app.post('/api/chats/get-or-create', (req, res) => {
  const { user1_id, user2_id } = req.body;

  let chat = null;
  for (const c of chats.values()) {
    if ((c.user1_id === user1_id && c.user2_id === user2_id) ||
        (c.user1_id === user2_id && c.user2_id === user1_id)) {
      chat = c;
      break;
    }
  }

  if (!chat) {
    const chatId = `chat_${chatIdCounter++}`;
    chat = {
      id: chatId,
      user1_id,
      user2_id,
      created_at: Date.now(),
    };
    chats.set(chatId, chat);
  }

  res.json({ success: true, data: chat });
});

// ===== MESSAGES ENDPOINTS =====
app.get('/api/messages/:chatId', (req, res) => {
  const { chatId } = req.params;
  const chatMessages = Array.from(messages.values())
    .filter(msg => msg.chat_id === chatId)
    .sort((a, b) => a.created_at - b.created_at);

  res.json({ success: true, data: chatMessages });
});

app.post('/api/messages', (req, res) => {
  const { chat_id, sender_id, content } = req.body;

  const messageId = `msg_${messageIdCounter++}`;
  const message = {
    id: messageId,
    chat_id,
    sender_id,
    content,
    created_at: Date.now(),
  };

  messages.set(messageId, message);

  // Update chat last message
  const chat = chats.get(chat_id);
  if (chat) {
    chat.lastMessage = content;
  }

  // Emit via WebSocket
  io.emit('receive_message', message);

  res.json({ success: true, data: message });
});

// ===== ONLINE USERS =====
app.get('/api/online-users', (req, res) => {
  const onlineUsers = Array.from(users.values()).map(u => ({
    id: u.id,
    username: u.username,
    online: true,
  }));

  res.json({ success: true, data: onlineUsers });
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
  console.log(`\n✅ ΣIGMA SOCIAL SERVER WITH WEBSOCKET STARTED`);
  console.log(`🌐 Running on http://localhost:${PORT}`);
  console.log(`📡 WebSocket: ws://localhost:${PORT}\n`);
});