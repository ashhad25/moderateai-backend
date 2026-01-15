require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
  options: "-c timezone=America/Halifax", // Atlantic Time (New Brunswick)
});

// ML Service URL
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-in-production";

// ==================== MIDDLEWARE ====================

// API Key authentication
const authenticateAPIKey = async (req, res, next) => {
  try {
    const apiKey = req.header("X-API-Key");

    if (!apiKey) {
      return res.status(401).json({ error: "API key required" });
    }

    const result = await pool.query(
      "SELECT * FROM clients WHERE api_key = $1 AND is_active = true",
      [apiKey]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    req.client = result.rows[0];
    next();
  } catch (err) {
    res.status(500).json({ error: "Authentication error" });
  }
};

// Simple admin auth middleware
function adminAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// Admin JWT authentication
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ==================== ADMIN AUTH ROUTES ====================

app.post("/api/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query("SELECT * FROM admins WHERE email = $1", [
      email,
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

app.post("/api/admin/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO admins (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name",
      [email, hashedPassword, name]
    );

    const token = jwt.sign(
      { id: result.rows[0].id, email: result.rows[0].email },
      JWT_SECRET,
      { expiresIn: "7d" }
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
      "SELECT id, name, email, api_key, is_active, created_at, (SELECT COUNT(*) FROM content_submissions WHERE client_id = clients.id) as total_requests FROM clients ORDER BY created_at DESC"
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
    const apiKey = `mod_${uuidv4().replace(/-/g, "")}`;

    const result = await pool.query(
      "INSERT INTO clients (name, email, api_key) VALUES ($1, $2, $3) RETURNING *",
      [name, email, apiKey]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Create client error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.patch("/api/clients/:id/toggle", authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE clients SET is_active = NOT is_active WHERE id = $1 RETURNING *",
      [req.params.id]
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

app.post("/api/moderate", authenticateAPIKey, async (req, res) => {
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

    // Call ML service
    const mlResponse = await axios.post(`${ML_SERVICE_URL}/api/moderate`, {
      text: text,
      content_id: uuidv4(),
    });

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
      ]
    );

    // Update client usage stats
    await pool.query(
      "UPDATE clients SET total_requests = total_requests + 1, last_request_at = NOW() WHERE id = $1",
      [req.client.id]
    );

    res.json({
      id: dbResult.rows[0].id,
      ...moderationResult,
      timestamp: dbResult.rows[0].created_at,
    });
  } catch (err) {
    console.error("Moderate error:", err);
    res.status(500).json({ error: "Moderation failed", details: err.message });
  }
});

app.post("/api/moderate/batch", authenticateAPIKey, async (req, res) => {
  try {
    const { texts } = req.body;

    if (!texts || !Array.isArray(texts) || texts.length === 0) {
      return res.status(400).json({ error: "Texts array is required" });
    }

    if (texts.length > 100) {
      return res.status(400).json({ error: "Max 100 texts per batch" });
    }

    // Call ML service
    const mlResponse = await axios.post(
      `${ML_SERVICE_URL}/api/moderate/batch`,
      {
        texts: texts,
      }
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
        ]
      );

      results.push({ id: dbResult.rows[0].id, ...result });
    }

    await pool.query(
      "UPDATE clients SET total_requests = total_requests + $1, last_request_at = NOW() WHERE id = $2",
      [texts.length, req.client.id]
    );

    res.json({
      count: results.length,
      results: results,
      total_processing_time_ms: mlResponse.data.total_processing_time_ms,
    });
  } catch (err) {
    console.error("Batch moderate error:", err);
    res.status(500).json({ error: "Batch moderation failed" });
  }
});

// ==================== SUBMISSIONS & ANALYTICS ====================

app.get("/api/submissions", authenticateAdmin, async (req, res) => {
  try {
    const { limit = 50, offset = 0, recommendation } = req.query;

    let query = `
      SELECT s.*, c.name as client_name 
      FROM content_submissions s
      JOIN clients c ON s.client_id = c.id
    `;

    const params = [];
    if (recommendation) {
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
    const mlHealth = await axios.get(`${ML_SERVICE_URL}/health`);

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
    const { rows } = await pool.query(`
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
      LIMIT 100
    `);

    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch logs" });
  }
});

app.get("/", (req, res) => {
  res.json({
    service: "ModerateAI Backend API",
    version: "1.0.0",
    endpoints: {
      moderate: "POST /api/moderate (requires X-API-Key)",
      batch: "POST /api/moderate/batch (requires X-API-Key)",
      admin_login: "POST /api/admin/login",
      clients: "GET /api/clients (requires auth)",
      analytics: "GET /api/analytics/overview (requires auth)",
    },
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ ModerateAI Backend running on port ${PORT}`);
  console.log(`🔗 ML Service: ${ML_SERVICE_URL}`);
});
