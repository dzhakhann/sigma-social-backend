# 🔥 SIGMA SOCIAL NETWORK

Production-ready backend for Sigma Social Network.

## Quick Start

```bash
# Install dependencies
npm install

# Create .env file and fill in your Supabase credentials
cp .env.example .env

# Run in development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## API Documentation

### Auth
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user

### Posts
- `GET /api/posts` - Get feed
- `POST /api/posts` - Create post
- `POST /api/posts/:postId/like` - Like post

### Chats
- `GET /api/chats` - Get user chats
- `POST /api/chats/get-or-create` - Get or create chat
- `GET /api/messages/:chatId` - Get messages

### Health
- `GET /api/health` - Server health check

## WebSocket Events

- `user_connect` - Register user
- `send_message` - Send message
- `send_haptic` - Send haptic
- `chess_move` - Make chess move

## License

MIT