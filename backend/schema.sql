-- Workers Club schema (MySQL / Dolt). SQLAlchemy also creates these on boot.
CREATE TABLE IF NOT EXISTS members (
  id VARCHAR(36) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(120) NOT NULL,
  password_hash VARCHAR(255) NULL,
  role VARCHAR(32) NOT NULL DEFAULT 'member',
  email_verified BOOLEAN NOT NULL DEFAULT 0,
  is_active BOOLEAN NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS member_identities (
  id VARCHAR(36) PRIMARY KEY,
  member_id VARCHAR(36) NOT NULL,
  provider VARCHAR(32) NOT NULL,
  subject VARCHAR(128) NOT NULL,
  email VARCHAR(255) NULL,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uq_member_identities_provider_subject (provider, subject),
  FOREIGN KEY (member_id) REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id VARCHAR(36) PRIMARY KEY,
  member_id VARCHAR(36) NOT NULL,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  user_agent VARCHAR(512) NULL,
  ip_address VARCHAR(64) NULL,
  created_at DATETIME NOT NULL,
  FOREIGN KEY (member_id) REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS verification_codes (
  id VARCHAR(36) PRIMARY KEY,
  member_id VARCHAR(36) NOT NULL,
  purpose VARCHAR(32) NOT NULL,
  code_hash VARCHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  FOREIGN KEY (member_id) REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(120) NOT NULL,
  secret_hash VARCHAR(255) NULL,
  redirect_uris TEXT NOT NULL,
  is_confidential BOOLEAN NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
  id VARCHAR(36) PRIMARY KEY,
  code_hash VARCHAR(64) NOT NULL UNIQUE,
  client_id VARCHAR(64) NOT NULL,
  member_id VARCHAR(36) NOT NULL,
  redirect_uri VARCHAR(512) NOT NULL,
  code_challenge VARCHAR(128) NOT NULL,
  code_challenge_method VARCHAR(16) NOT NULL,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(id),
  FOREIGN KEY (member_id) REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
  id VARCHAR(36) PRIMARY KEY,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  client_id VARCHAR(64) NOT NULL,
  member_id VARCHAR(36) NOT NULL,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(id),
  FOREIGN KEY (member_id) REFERENCES members(id)
);

CREATE TABLE IF NOT EXISTS club_resources (
  id VARCHAR(36) PRIMARY KEY,
  slug VARCHAR(120) NOT NULL UNIQUE,
  title VARCHAR(200) NOT NULL,
  summary TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at DATETIME NOT NULL
);
