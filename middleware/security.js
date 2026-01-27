const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

// Allowed origins for CORS
const allowedOrigins = [
  "https://moderateai-frontend.vercel.app",
  "http://localhost:3000",
  "http://localhost:5173",
  process.env.FRONTEND_URL,
].filter(Boolean);

// Rate limiting configuration
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// General API rate limiter
const apiLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  100, // 100 requests per window
  "Too many requests, please try again later",
);

// Strict limiter for auth endpoints
const authLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutes
  5, // 5 attempts per window
  "Too many login attempts, please try again later",
);

// Moderation endpoint limiter
const moderationLimiter = createRateLimiter(
  60 * 1000, // 1 minute
  30, // 30 requests per minute
  "Rate limit exceeded for moderation requests",
);

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Key"],
  exposedHeaders: ["Content-Range", "X-Content-Range"],
  maxAge: 600, // 10 minutes
};

// Security headers configuration
const helmetConfig = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", ...allowedOrigins],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false, // Allows external resources
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  frameguard: {
    action: "deny",
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: {
    policy: "strict-origin-when-cross-origin",
  },
};

// Additional security headers
const additionalSecurityHeaders = (req, res, next) => {
  // Prevent MIME type sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Prevent clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // Control referrer information
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Permissions policy (restrict browser features)
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), payment=()",
  );

  // Remove powered-by header
  res.removeHeader("X-Powered-By");

  next();
};

// Cache control for API responses
const noCacheForAPI = (req, res, next) => {
  if (req.path.startsWith("/api")) {
    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate, private",
    );
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
};

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
  if (req.body) {
    Object.keys(req.body).forEach((key) => {
      if (typeof req.body[key] === "string") {
        // Remove potential XSS payloads
        req.body[key] = req.body[key]
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
          .replace(/javascript:/gi, "")
          .replace(/on\w+\s*=/gi, "");
      }
    });
  }
  next();
};

module.exports = {
  corsOptions,
  helmetConfig,
  apiLimiter,
  authLimiter,
  moderationLimiter,
  additionalSecurityHeaders,
  noCacheForAPI,
  sanitizeInput,
  helmet,
};
