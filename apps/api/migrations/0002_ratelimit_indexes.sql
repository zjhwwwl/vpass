-- decisions D-10: rate limiting counts recent failures in audit_log.
CREATE INDEX idx_audit_ip_event_time ON audit_log(ip_hash, event, created_at);
CREATE INDEX idx_audit_user_event_time ON audit_log(user_id, event, created_at);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_members_user ON vault_members(user_id);
