const requestCounts = new Map<string, number[]>();

export const rateLimitMiddleware = (req: any, res: any, next: any) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 100;

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, []);
  }

  const timestamps = requestCounts.get(ip)!;
  const recentRequests = timestamps.filter((t) => now - t < windowMs);

  if (recentRequests.length >= maxRequests) {
    return res.status(429).json({
      success: false,
      error: 'Too many requests',
    });
  }

  recentRequests.push(now);
  requestCounts.set(ip, recentRequests);
  next();
};