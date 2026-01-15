-- ModerateAI Database Schema

-- Admins table (for dashboard access)
CREATE TABLE IF NOT EXISTS admins (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Clients table (API key holders)
CREATE TABLE IF NOT EXISTS clients (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  api_key VARCHAR(255) UNIQUE NOT NULL,
  is_active BOOLEAN DEFAULT true,
  total_requests INTEGER DEFAULT 0,
  last_request_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Content submissions table
CREATE TABLE IF NOT EXISTS content_submissions (
  id SERIAL PRIMARY KEY,
  client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
  content_text TEXT NOT NULL,
  is_spam BOOLEAN NOT NULL,
  spam_score DECIMAL(5, 3) NOT NULL,
  is_toxic BOOLEAN NOT NULL,
  toxicity_score DECIMAL(5, 3) NOT NULL,
  is_inappropriate BOOLEAN NOT NULL,
  inappropriate_score DECIMAL(5, 3) NOT NULL,
  flagged_words JSONB,
  recommendation VARCHAR(20) NOT NULL CHECK (recommendation IN ('APPROVE', 'REVIEW', 'REJECT')),
  confidence DECIMAL(5, 3) NOT NULL,
  processing_time_ms DECIMAL(10, 2),
  metadata JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_submissions_client_id ON content_submissions(client_id);
CREATE INDEX IF NOT EXISTS idx_submissions_recommendation ON content_submissions(recommendation);
CREATE INDEX IF NOT EXISTS idx_submissions_created_at ON content_submissions(created_at);
CREATE INDEX IF NOT EXISTS idx_clients_api_key ON clients(api_key);

-- Create default admin (password: admin123)
INSERT INTO admins (email, password, name) 
VALUES ('admin@moderateai.com', '$2a$10$rKZvMvL8d8VnH8J5qN5qPeXfY.5xY5xY5xY5xY5xY5xY5xY5xY5xY', 'Admin User')
ON CONFLICT (email) DO NOTHING;

-- Create sample client for testing
INSERT INTO clients (name, email, api_key) 
VALUES ('Test Client', 'test@example.com', 'mod_test_key_12345678901234567890')
ON CONFLICT (email) DO NOTHING;