import express from 'express';
import http from 'http';
import { Server } from 'socket.io';

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});

const PORT = 3000;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Mock Database
const users = new Map();
const posts = [];
const messages = [];
const chats = new Map();
const onlineUsers = new Map();

// ===== WEBSOCKET EVENTS =====
io.on('connection', (socket) => {
  console.log(`✅ User connected: ${socket.id}`);

  // User comes online
  socket.on('user_connect', (data) => {
    onlineUsers.set(socket.id, { userId: data.userId, username: data.username });
    io.emit('user_online', { userId: data.userId, username: data.username });
    console.log(`🟢 ${data.username} is online`);
  });

  // Send message
  socket.on('send_message', (data) => {
    const message = {
      id: 'msg-' + Math.random().toString(36).substr(2, 9),
      chat_id: data.chat_id,
      sender_id: data.sender_id,
      content: data.content,
      created_at: new Date().toISOString(),
    };
    messages.push(message);
    io.emit('receive_message', message);
    console.log(`💬 Message from ${data.sender_id}: ${data.content}`);
  });

  // Typing indicator
  socket.on('user_typing', (data) => {
    socket.broadcast.emit('user_typing', { userId: data.userId, chatId: data.chat_id });
  });

  socket.on('user_stop_typing', (data) => {
    socket.broadcast.emit('user_stop_typing', { userId: data.userId, chatId: data.chat_id });
  });

  // Haptic feedback
  socket.on('send_haptic', (data) => {
    io.emit('haptic_received', { userId: data.userId, intensity: data.intensity });
    console.log(`📳 Haptic from ${data.userId}: ${data.intensity}`);
  });

  socket.on('disconnect', () => {
    const user = onlineUsers.get(socket.id);
    if (user) {
      onlineUsers.delete(socket.id);
      io.emit('user_offline', { userId: user.userId, username: user.username });
      console.log(`🔴 ${user.username} is offline`);
    }
  });
});

// ===== AUTH =====
app.post('/api/auth/register', (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username) {
    return res.status(400).json({ success: false, error: 'Missing fields' });
  }
  const userId = 'user-' + Math.random().toString(36).substr(2, 9);
  users.set(userId, { 
    id: userId, 
    email, 
    username, 
    password, 
    bio: '', 
    avatar_url: '',
    created_at: new Date().toISOString()
  });
  res.json({ 
    success: true, 
    data: { 
      user: users.get(userId), 
      token: 'fake-token-' + userId 
    } 
  });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = Array.from(users.values()).find((u) => u.email === email);
  if (!user || user.password !== password) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }
  res.json({ success: true, data: { user, token: 'fake-token-' + user.id } });
});

// ===== POSTS =====
app.get('/api/posts', (req, res) => {
  res.json({ success: true, data: posts });
});

app.post('/api/posts', (req, res) => {
  const { user_id, content } = req.body;
  const post = {
    id: 'post-' + Math.random().toString(36).substr(2, 9),
    user_id,
    content,
    likes_count: 0,
    created_at: new Date().toISOString(),
  };
  posts.push(post);
  io.emit('new_post', post);
  res.status(201).json({ success: true, data: post });
});

app.post('/api/posts/:postId/like', (req, res) => {
  const post = posts.find((p) => p.id === req.params.postId);
  if (!post) return res.status(404).json({ success: false, error: 'Post not found' });
  post.likes_count += 1;
  io.emit('post_liked', { postId: post.id, likes: post.likes_count });
  res.json({ success: true, data: post });
});

// ===== CHATS =====
app.get('/api/chats', (req, res) => {
  const userId = req.query.userId;
  const userChats = Array.from(chats.values()).filter(
    (c) => c.user_1_id === userId || c.user_2_id === userId
  );
  res.json({ success: true, data: userChats });
});

app.post('/api/chats/get-or-create', (req, res) => {
  const { user1, user2 } = req.body;
  let chat = Array.from(chats.values()).find(
    (c) => (c.user_1_id === user1 && c.user_2_id === user2) || 
           (c.user_1_id === user2 && c.user_2_id === user1)
  );
  if (!chat) {
    const chatId = 'chat-' + Math.random().toString(36).substr(2, 9);
    chat = { 
      id: chatId, 
      user_1_id: user1, 
      user_2_id: user2, 
      created_at: new Date().toISOString() 
    };
    chats.set(chatId, chat);
  }
  res.json({ success: true, data: chat });
});

app.get('/api/messages/:chatId', (req, res) => {
  const chatMessages = messages.filter((m) => m.chat_id === req.params.chatId);
  res.json({ success: true, data: chatMessages });
});

app.post('/api/messages', (req, res) => {
  const { chat_id, sender_id, content } = req.body;
  const message = {
    id: 'msg-' + Math.random().toString(36).substr(2, 9),
    chat_id,
    sender_id,
    content,
    created_at: new Date().toISOString(),
  };
  messages.push(message);
  io.emit('new_message', message);
  res.json({ success: true, data: message });
});

// ===== USERS =====
app.get('/api/users', (req, res) => {
  res.json({ success: true, data: Array.from(users.values()) });
});

app.get('/api/users/:userId', (req, res) => {
  const user = users.get(req.params.userId);
  if (!user) return res.status(404).json({ success: false, error: 'User not found' });
  res.json({ success: true, data: user });
});

app.get('/api/online-users', (req, res) => {
  res.json({ success: true, data: Array.from(onlineUsers.values()) });
});

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'OK',
    message: 'Sigma Social Server is running!',
    timestamp: new Date().toISOString(),
    onlineUsers: onlineUsers.size,
    totalUsers: users.size,
    totalPosts: posts.length,
    totalMessages: messages.length,
  });
});

// ===== 404 =====
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

// ===== START SERVER =====
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ ΣIGMA SOCIAL SERVER WITH WEBSOCKET STARTED`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`📡 API: http://localhost:${PORT}/api`);
  console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
  console.log(`💰 Health: http://localhost:${PORT}/api/health\n`);
});