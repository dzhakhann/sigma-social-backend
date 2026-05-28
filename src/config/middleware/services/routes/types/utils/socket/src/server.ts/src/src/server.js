import express from 'express';
import http from 'http';

const app = express();
const server = http.createServer(app);
const PORT = 3000;

app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Server is running!',
    timestamp: new Date().toISOString()
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ SERVER STARTED ON http://localhost:${PORT}`);
});