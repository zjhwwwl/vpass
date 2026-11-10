-- VPass schema v1 (blueprint section 5). Everything except email, public keys and timestamps is ciphertext or a hash.
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  kdf_salt TEXT NOT NULL,              -- base64url
  kdf_params TEXT NOT NULL,            -- JSON {alg, ops, mem, v}
  auth_hmac TEXT NOT NULL,             -- HMAC(PEPPER, authHash)
  wrapped_account_key TEXT NOT NULL,   -- envelope JSON
  recovery_wrapped_key TEXT NOT NULL,
  recovery_auth_hmac TEXT NOT NULL,
  public_key TEXT NOT NULL,
  wrapped_private_key TEXT NOT NULL,
  totp_secret_enc TEXT,                -- encrypted with Worker secret TOTP_ENC_KEY, nullable
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE vaults (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL CHECK (kind IN ('personal','shared')),
  name_enc TEXT,                       -- shared vault names are encrypted too
  revision INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE vault_members (
  vault_id TEXT NOT NULL REFERENCES vaults(id),
  user_id TEXT NOT NULL REFERENCES users(id),
  sealed_vault_key TEXT NOT NULL,      -- crypto_box_seal output
  key_epoch INTEGER NOT NULL,          -- +1 on key rotation
  role TEXT NOT NULL CHECK (role IN ('owner','editor','viewer')),
  PRIMARY KEY (vault_id, user_id)
);

CREATE TABLE items (
  id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vaults(id),
  data TEXT NOT NULL,                  -- envelope JSON
  key_epoch INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0,  -- soft delete for sync
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_items_vault_rev ON items(vault_id, revision);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,         -- SHA-256(random 32-byte token)
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  device_label TEXT
);

CREATE TABLE invites (
  code_hash TEXT PRIMARY KEY,
  created_by TEXT REFERENCES users(id),
  used_by TEXT REFERENCES users(id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  event TEXT NOT NULL,                 -- login_ok / login_fail / pw_change / share ...
  ip_hash TEXT,
  created_at INTEGER NOT NULL
);
