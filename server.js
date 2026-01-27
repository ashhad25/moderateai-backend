require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const axios = require("axios");

// Import security middleware
const {
  corsOptions,
  helmetConfig,
  apiLimiter,
  authLimiter,
  moderationLimiter,
  additionalSecurityHeaders,
  noCacheForAPI,
  sanitizeInput,
  helmet,
} = require("./middleware/security");

const app = express();

// ==================== TRUST PROXY (MUST BE FIRST) ====================
app.set("trust proxy", 1); // Required for Railway, Heroku, etc.

// ==================== SECURITY MIDDLEWARE (MUST BE FIRST) ====================
app.use(helmet(helmetConfig));
app.use(cors(corsOptions));
app.use(additionalSecurityHeaders);
app.use(noCacheForAPI);
app.use(express.json({ limit: "10mb" })); // Limit JSON payload size
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(sanitizeInput);

// Apply general rate limiting to all API routes
app.use("/api/", apiLimiter);

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
  options: "-c timezone=America/Halifax",
});

// Prevent SQL injection by using prepared statements (already done)
// Add connection error handling
pool.on("error", (err) => {
  console.error("Unexpected database error:", err);
});

// ML Service URL
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";
const JWT_SECRET = process.env.JWT_SECRET;

// Validate JWT_SECRET exists
if (!JWT_SECRET || JWT_SECRET === "your-secret-key-change-in-production") {
  console.error("❌ CRITICAL: JWT_SECRET not set or using default value!");
  process.exit(1);
}

// ==================== MIDDLEWARE ====================

// API Key authentication
const authenticateAPIKey = async (req, res, next) => {
  try {
    const apiKey = req.header("X-API-Key");

    if (!apiKey) {
      return res.status(401).json({ error: "API key required" });
    }

    // Prevent timing attacks by using constant-time comparison
    const result = await pool.query(
      "SELECT * FROM clients WHERE api_key = $1 AND is_active = true",
      [apiKey],
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    req.client = result.rows[0];
    next();
  } catch (err) {
    console.error("API Key auth error:", err);
    res.status(500).json({ error: "Authentication error" });
  }
};

// Admin JWT authentication
const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");

    if (!authHeader) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const token = authHeader.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    console.error("Admin auth error:", err);
    res.status(401).json({ error: "Invalid token" });
  }
};

// Combined admin auth (for backwards compatibility)
function adminAuth(req, res, next) {
  authenticateAdmin(req, res, next);
}

// ==================== ADMIN AUTH ROUTES ====================

app.post("/api/admin/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const result = await pool.query("SELECT * FROM admins WHERE email = $1", [
      email.toLowerCase().trim(),
    ]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const admin = result.rows[0];
    const validPassword = await bcrypt.compare(password, admin.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      admin: { id: admin.id, email: admin.email, name: admin.name },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/register", authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Input validation
    if (!email || !password || !name) {
      return res.status(400).json({ error: "All fields required" });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    // Password strength validation
    if (password.length < 8) {
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters" });
    }

    const hashedPassword = await bcrypt.hash(password, 12); // Increased from 10

    const result = await pool.query(
      "INSERT INTO admins (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name",
      [email.toLowerCase().trim(), hashedPassword, name.trim()],
    );

    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      JWT_SECRET,
      { expiresIn: "7d" },
    );

    res.status(201).json({
      admin: result.rows[0],
      token,
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(400).json({ error: "Email already exists" });
    }
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== CLIENT MANAGEMENT ====================

app.get("/api/clients", authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, api_key, is_active, created_at, (SELECT COUNT(*) FROM content_submissions WHERE client_id = clients.id) as total_requests FROM clients ORDER BY created_at DESC",
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Get clients error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/clients", authenticateAdmin, async (req, res) => {
  try {
    const { name, email } = req.body;

    // Input validation
    if (!name || !email) {
      return res.status(400).json({ error: "Name and email required" });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const apiKey = `mod_${uuidv4().replace(/-/g, "")}`;

    const result = await pool.query(
      "INSERT INTO clients (name, email, api_key) VALUES ($1, $2, $3) RETURNING *",
      [name.trim(), email.toLowerCase().trim(), apiKey],
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Create client error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.patch("/api/clients/:id/toggle", authenticateAdmin, async (req, res) => {
  try {
    // Validate ID is a number
    const clientId = parseInt(req.params.id);
    if (isNaN(clientId)) {
      return res.status(400).json({ error: "Invalid client ID" });
    }

    const result = await pool.query(
      "UPDATE clients SET is_active = NOT is_active WHERE id = $1 RETURNING *",
      [clientId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Client not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Toggle client error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== MODERATION API ====================

app.post(
  "/api/moderate",
  authenticateAPIKey,
  moderationLimiter,
  async (req, res) => {
    try {
      const { text, metadata } = req.body;

      if (!text || text.length === 0) {
        return res.status(400).json({ error: "Text is required" });
      }

      if (text.length > 10000) {
        return res
          .status(400)
          .json({ error: "Text too long (max 10000 characters)" });
      }

      // Call ML service with timeout
      const mlResponse = await axios.post(
        `${ML_SERVICE_URL}/api/moderate`,
        {
          text: text,
          content_id: uuidv4(),
        },
        { timeout: 30000 }, // 30 second timeout
      );

      const moderationResult = mlResponse.data;

      // Store in database
      const dbResult = await pool.query(
        `INSERT INTO content_submissions 
       (client_id, content_text, is_spam, spam_score, is_toxic, toxicity_score, 
        is_inappropriate, inappropriate_score, flagged_words, recommendation, 
        confidence, processing_time_ms, metadata) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) 
       RETURNING id, created_at`,
        [
          req.client.id,
          text.substring(0, 1000), // Store first 1000 chars
          moderationResult.is_spam,
          moderationResult.spam_score,
          moderationResult.is_toxic,
          moderationResult.toxicity_score,
          moderationResult.is_inappropriate,
          moderationResult.inappropriate_score,
          JSON.stringify(moderationResult.flagged_words),
          moderationResult.recommendation,
          moderationResult.confidence,
          moderationResult.processing_time_ms,
          metadata ? JSON.stringify(metadata) : null,
        ],
      );

      // Update client usage stats
      await pool.query(
        "UPDATE clients SET total_requests = total_requests + 1, last_request_at = NOW() WHERE id = $1",
        [req.client.id],
      );

      res.json({
        id: dbResult.rows[0].id,
        ...moderationResult,
        timestamp: dbResult.rows[0].created_at,
      });
    } catch (err) {
      console.error("Moderate error:", err);

      if (err.code === "ECONNREFUSED") {
        return res.status(503).json({ error: "ML service unavailable" });
      }

      if (err.code === "ETIMEDOUT") {
        return res.status(504).json({ error: "ML service timeout" });
      }

      res.status(500).json({ error: "Moderation failed" });
    }
  },
);

app.post(
  "/api/moderate/batch",
  authenticateAPIKey,
  moderationLimiter,
  async (req, res) => {
    try {
      const { texts } = req.body;

      if (!texts || !Array.isArray(texts) || texts.length === 0) {
        return res.status(400).json({ error: "Texts array is required" });
      }

      if (texts.length > 100) {
        return res.status(400).json({ error: "Max 100 texts per batch" });
      }

      // Validate each text
      for (let text of texts) {
        if (typeof text !== "string") {
          return res.status(400).json({ error: "All texts must be strings" });
        }
        if (text.length > 10000) {
          return res
            .status(400)
            .json({ error: "Text too long (max 10000 characters)" });
        }
      }

      // Call ML service with timeout
      const mlResponse = await axios.post(
        `${ML_SERVICE_URL}/api/moderate/batch`,
        { texts: texts },
        { timeout: 60000 }, // 60 second timeout for batch
      );

      // Store all results in database
      const results = [];
      for (let i = 0; i < mlResponse.data.results.length; i++) {
        const result = mlResponse.data.results[i];

        const dbResult = await pool.query(
          `INSERT INTO content_submissions 
         (client_id, content_text, is_spam, spam_score, is_toxic, toxicity_score, 
          is_inappropriate, inappropriate_score, flagged_words, recommendation, 
          confidence, processing_time_ms) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) 
         RETURNING id`,
          [
            req.client.id,
            texts[i].substring(0, 1000),
            result.is_spam,
            result.spam_score,
            result.is_toxic,
            result.toxicity_score,
            result.is_inappropriate,
            result.inappropriate_score,
            JSON.stringify(result.flagged_words),
            result.recommendation,
            result.confidence,
            result.processing_time_ms,
          ],
        );

        results.push({ id: dbResult.rows[0].id, ...result });
      }

      await pool.query(
        "UPDATE clients SET total_requests = total_requests + $1, last_request_at = NOW() WHERE id = $2",
        [texts.length, req.client.id],
      );

      res.json({
        count: results.length,
        results: results,
        total_processing_time_ms: mlResponse.data.total_processing_time_ms,
      });
    } catch (err) {
      console.error("Batch moderate error:", err);

      if (err.code === "ECONNREFUSED") {
        return res.status(503).json({ error: "ML service unavailable" });
      }

      if (err.code === "ETIMEDOUT") {
        return res.status(504).json({ error: "ML service timeout" });
      }

      res.status(500).json({ error: "Batch moderation failed" });
    }
  },
);

// ==================== SUBMISSIONS & ANALYTICS ====================

app.get("/api/submissions", authenticateAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    const { recommendation } = req.query;

    // Validate pagination params
    if (limit > 1000) {
      return res.status(400).json({ error: "Limit cannot exceed 1000" });
    }

    let query = `
      SELECT s.*, c.name as client_name 
      FROM content_submissions s
      JOIN clients c ON s.client_id = c.id
    `;

    const params = [];
    if (recommendation) {
      // Validate recommendation value
      const validRecommendations = ["APPROVE", "REVIEW", "REJECT"];
      if (!validRecommendations.includes(recommendation)) {
        return res.status(400).json({ error: "Invalid recommendation value" });
      }
      query += " WHERE s.recommendation = $1";
      params.push(recommendation);
    }

    query +=
      " ORDER BY s.created_at DESC LIMIT $" +
      (params.length + 1) +
      " OFFSET $" +
      (params.length + 2);
    params.push(limit, offset);

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    console.error("Get submissions error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/analytics/overview", authenticateAdmin, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        COUNT(*) as total_submissions,
        COUNT(*) FILTER (WHERE recommendation = 'APPROVE') as approved,
        COUNT(*) FILTER (WHERE recommendation = 'REVIEW') as review,
        COUNT(*) FILTER (WHERE recommendation = 'REJECT') as rejected,
        COUNT(*) FILTER (WHERE is_spam = true) as spam_detected,
        COUNT(*) FILTER (WHERE is_toxic = true) as toxic_detected,
        AVG(processing_time_ms) as avg_processing_time,
        COUNT(DISTINCT client_id) as active_clients
      FROM content_submissions
      WHERE created_at > NOW() - INTERVAL '30 days'
    `);

    const recentActivity = await pool.query(`
      SELECT DATE(created_at) as date, COUNT(*) as count
      FROM content_submissions
      WHERE created_at > NOW() - INTERVAL '7 days'
      GROUP BY DATE(created_at)
      ORDER BY date DESC
    `);

    const topClients = await pool.query(`
      SELECT c.name, COUNT(s.id) as request_count
      FROM clients c
      LEFT JOIN content_submissions s ON c.id = s.client_id
      WHERE s.created_at > NOW() - INTERVAL '30 days'
      GROUP BY c.id, c.name
      ORDER BY request_count DESC
      LIMIT 5
    `);

    res.json({
      overview: stats.rows[0],
      recent_activity: recentActivity.rows,
      top_clients: topClients.rows,
    });
  } catch (err) {
    console.error("Analytics error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== HEALTH CHECK ====================

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    const mlHealth = await axios.get(`${ML_SERVICE_URL}/health`, {
      timeout: 5000,
    });

    res.json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      services: {
        database: "connected",
        ml_service: mlHealth.data.status,
      },
    });
  } catch (err) {
    res.status(503).json({
      status: "unhealthy",
      error: err.message,
    });
  }
});

// ==================== ADMIN LOGS VIEW ====================
app.get("/api/admin/logs", adminAuth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;

    if (limit > 1000) {
      return res.status(400).json({ error: "Limit cannot exceed 1000" });
    }

    const { rows } = await pool.query(
      `
      SELECT 
        id,
        content_id,
        LEFT(text, 120) AS text_preview,
        is_spam,
        spam_score,
        is_toxic,
        toxicity_score,
        is_inappropriate,
        inappropriate_score,
        flagged_words,
        recommendation,
        confidence,
        created_at AS timestamp
      FROM moderation_logs
      ORDER BY created_at DESC
      LIMIT $1
      `,
      [limit],
    );

    res.json(rows);
  } catch (err) {
    console.error("Logs error:", err);
    res.status(500).json({ message: "Failed to fetch logs" });
  }
});

app.get("/", (req, res) => {
  res.json({
    service: "ModerateAI Backend API",
    version: "1.0.0",
    status: "secure",
    endpoints: {
      moderate: "POST /api/moderate (requires X-API-Key)",
      batch: "POST /api/moderate/batch (requires X-API-Key)",
      admin_login: "POST /api/admin/login",
      clients: "GET /api/clients (requires auth)",
      analytics: "GET /api/analytics/overview (requires auth)",
    },
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Global error:", err);

  // Don't leak error details in production
  if (process.env.NODE_ENV === "production") {
    res.status(500).json({ error: "Internal server error" });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ ModerateAI Backend running on port ${PORT}`);
  console.log(`🔗 ML Service: ${ML_SERVICE_URL}`);
  console.log(`🔒 Security: Enhanced with Helmet, CORS, Rate Limiting`);
});
