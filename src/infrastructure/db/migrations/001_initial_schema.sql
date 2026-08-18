-- CyberVault Initial Schema Migration
-- Creates all tables with proper constraints

-- Vaults table
CREATE TABLE IF NOT EXISTS vaults (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  encrypted_data TEXT NOT NULL,
  encryption_key_id VARCHAR(255) NOT NULL,
  owner_id VARCHAR(255),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vaults_owner_id ON vaults(owner_id);

-- Credentials table
CREATE TABLE IF NOT EXISTS credentials (
  id VARCHAR(255) PRIMARY KEY,
  vault_id VARCHAR(255) NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  username VARCHAR(255) NOT NULL,
  encrypted_password TEXT NOT NULL,
  url TEXT,
  notes TEXT,
  tags TEXT[] DEFAULT '{}',
  favorite BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  last_used TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_credentials_vault_id ON credentials(vault_id);

-- Users table
CREATE TABLE IF NOT EXISTS users (
  user_id VARCHAR(255) PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  hash VARCHAR(255) NOT NULL,
  salt VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Trust store table (for domain validation)
CREATE TABLE IF NOT EXISTS trust_store (
  domain VARCHAR(255) PRIMARY KEY,
  trusted BOOLEAN DEFAULT TRUE,
  added_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  fingerprint TEXT
);
