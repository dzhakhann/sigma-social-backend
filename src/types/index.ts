// USER
export interface User {
  id: string;
  email: string;
  username: string;
  bio: string;
  avatar_url?: string;
  created_at: string;
}

// POST
export interface Post {
  id: string;
  user_id: string;
  content: string;
  image_url?: string;
  voice_url?: string;
  likes_count: number;
  created_at: string;
}

// MESSAGE
export interface Message {
  id: string;
  chat_id: string;
  sender_id: string;
  content: string;
  created_at: string;
}

// CHAT
export interface Chat {
  id: string;
  user_1_id: string;
  user_2_id: string;
  created_at: string;
}

// API RESPONSE
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
}