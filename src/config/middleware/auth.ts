export const authMiddleware = (req: any, res: any, next: any) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'No token provided',
        code: 'AUTH_ERROR',
      });
    }

    // Простая проверка токена (в production нужна реальная проверка)
    req.userId = 'user-from-token';
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      error: 'Invalid token',
      code: 'AUTH_ERROR',
    });
  }
};