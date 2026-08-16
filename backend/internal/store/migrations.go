package store

const schemaVersion = 25

var migrations = []string{`
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  api_url TEXT NOT NULL,
  tls_server_name TEXT NOT NULL DEFAULT '',
  credential_ref TEXT NOT NULL,
  port_start INTEGER NOT NULL CHECK (port_start BETWEEN 1 AND 65535),
  port_end INTEGER NOT NULL CHECK (port_end BETWEEN 1 AND 65535 AND port_end >= port_start),
  source_cidrs_json TEXT NOT NULL DEFAULT '[]',
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  health_status TEXT NOT NULL DEFAULT 'unknown',
  last_checked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
  owner_name TEXT NOT NULL,
  gateway_mode TEXT NOT NULL CHECK (gateway_mode IN ('create','bind_existing')),
  client_id INTEGER,
  gateway_name TEXT NOT NULL,
  gateway_status TEXT NOT NULL DEFAULT 'pending',
  runtime_type TEXT NOT NULL CHECK (runtime_type IN ('docker','host')),
  runtime_address TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(node_id, client_id)
);

CREATE TABLE project_networks (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  cidr TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0,1)),
  created_at TEXT NOT NULL,
  UNIQUE(project_id, cidr)
);

CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  name TEXT NOT NULL,
  device_type TEXT NOT NULL DEFAULT 'other',
  vendor TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','discovery','import')),
  status TEXT NOT NULL DEFAULT 'unknown',
  last_seen_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, host)
);

CREATE TABLE endpoints (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('http','https','ssh','rtsp','tcp','rdp','mysql','postgresql')),
  target_port INTEGER NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
  access_type TEXT NOT NULL CHECK (access_type IN ('web_proxy','web_ssh','port_forward')),
  verification_status TEXT NOT NULL DEFAULT 'unverified' CHECK (verification_status IN ('unverified','verified','failed')),
  last_verified_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(device_id, protocol, target_port)
);

CREATE TABLE port_forwards (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL UNIQUE REFERENCES endpoints(id) ON DELETE CASCADE,
  node_task_id INTEGER,
  server_port INTEGER NOT NULL CHECK (server_port BETWEEN 1 AND 65535),
  status TEXT NOT NULL DEFAULT 'pending',
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('system_admin','project_admin','operator','temporary')),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE project_memberships (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY(user_id, project_id)
);

CREATE TABLE access_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  scope_json TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  schedule_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE access_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  mode TEXT NOT NULL CHECK (mode IN ('web','ssh')),
  source_ip TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  started_at TEXT NOT NULL,
  ended_at TEXT
);

CREATE TABLE discovery_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  requested_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  networks_json TEXT NOT NULL,
  ports_json TEXT NOT NULL,
  status TEXT NOT NULL,
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  result TEXT NOT NULL,
  request_id TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE INDEX idx_projects_node ON projects(node_id);
CREATE INDEX idx_project_networks_project ON project_networks(project_id);
CREATE INDEX idx_devices_project ON devices(project_id);
CREATE INDEX idx_endpoints_device ON endpoints(device_id);
CREATE INDEX idx_access_sessions_expiry ON access_sessions(status, expires_at);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);
`, `
ALTER TABLE nodes ADD COLUMN socks_host TEXT NOT NULL DEFAULT '';
UPDATE nodes SET socks_host =
  CASE
    WHEN instr(substr(api_url, 9), ':') > 0 THEN substr(substr(api_url, 9), 1, instr(substr(api_url, 9), ':') - 1)
    WHEN instr(substr(api_url, 9), '/') > 0 THEN substr(substr(api_url, 9), 1, instr(substr(api_url, 9), '/') - 1)
    ELSE substr(api_url, 9)
  END
WHERE socks_host = '';
`, `
ALTER TABLE endpoints ADD COLUMN tls_server_name TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN allow_insecure_tls INTEGER NOT NULL DEFAULT 0 CHECK (allow_insecure_tls IN (0,1));
`, `
ALTER TABLE port_forwards ADD COLUMN node_id TEXT REFERENCES nodes(id) ON DELETE RESTRICT;
UPDATE port_forwards
SET node_id = (
  SELECT p.node_id
  FROM endpoints e
  JOIN devices d ON d.id = e.device_id
  JOIN projects p ON p.id = d.project_id
  WHERE e.id = port_forwards.endpoint_id
)
WHERE node_id IS NULL;
CREATE UNIQUE INDEX idx_port_forwards_node_port ON port_forwards(node_id, server_port) WHERE node_id IS NOT NULL;
`, `
CREATE TABLE discovery_results (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES discovery_jobs(id) ON DELETE CASCADE,
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol TEXT NOT NULL CHECK (protocol IN ('http','https','ssh','rtsp','tcp','rdp','mysql','postgresql')),
  service_name TEXT NOT NULL,
  fingerprint TEXT NOT NULL DEFAULT '',
  response_summary TEXT NOT NULL DEFAULT '',
  confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
  import_status TEXT NOT NULL DEFAULT 'pending' CHECK (import_status IN ('pending','imported','ignored')),
  created_at TEXT NOT NULL,
  UNIQUE(job_id, host, protocol, port)
);
CREATE INDEX idx_discovery_results_job_host ON discovery_results(job_id, host, port);
`, `
ALTER TABLE nodes ADD COLUMN bridge_host TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN bridge_port INTEGER NOT NULL DEFAULT 5443 CHECK (bridge_port BETWEEN 1 AND 65535);
UPDATE nodes SET bridge_host = socks_host WHERE bridge_host = '';
`, `
ALTER TABLE endpoints ADD COLUMN ssh_credential_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN ssh_host_key_fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN allow_unknown_ssh_host_key INTEGER NOT NULL DEFAULT 0 CHECK (allow_unknown_ssh_host_key IN (0,1));
`, `
CREATE TABLE auth_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','revoked')),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE INDEX idx_auth_sessions_token ON auth_sessions(token_hash,status,expires_at);
CREATE TABLE policy_users (
  policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(policy_id,user_id)
);
CREATE TABLE policy_projects (
  policy_id TEXT NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  PRIMARY KEY(policy_id,project_id)
);
`, ``, `
CREATE INDEX idx_discovery_jobs_project_created ON discovery_jobs(project_id,created_at DESC);
CREATE INDEX idx_access_sessions_project_status_expiry ON access_sessions(project_id,status,expires_at);
PRAGMA optimize;
`, `
CREATE TABLE user_mfa (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
	secret_ciphertext TEXT NOT NULL DEFAULT '',
	preferred_method TEXT NOT NULL CHECK (preferred_method IN ('totp','email')),
  last_totp_counter INTEGER NOT NULL DEFAULT -1,
  enabled_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE mfa_recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(user_id,code_hash)
);
CREATE INDEX idx_mfa_recovery_user_unused ON mfa_recovery_codes(user_id,used_at);
CREATE TABLE mfa_challenges (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL CHECK (purpose IN ('onboard','verify')),
	method TEXT NOT NULL DEFAULT '' CHECK (method IN ('','totp','email')),
  secret_ciphertext TEXT NOT NULL DEFAULT '',
	email TEXT NOT NULL DEFAULT '',
	email_code_hash TEXT NOT NULL DEFAULT '',
	email_sent_at TEXT,
	email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0,1)),
	new_password_hash TEXT NOT NULL DEFAULT '',
  source_ip TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','consumed','revoked')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_mfa_challenges_token ON mfa_challenges(token_hash,status,expires_at);
ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 1 CHECK (password_change_required IN (0,1));
UPDATE auth_sessions SET status='revoked' WHERE status='active';
`, `
CREATE TABLE node_credentials (
  node_id TEXT PRIMARY KEY,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  updated_at TEXT NOT NULL
);
`, ``, ``, ``, `
ALTER TABLE nodes DROP COLUMN socks_host;
ALTER TABLE nodes DROP COLUMN bridge_host;
ALTER TABLE nodes DROP COLUMN bridge_port;
ALTER TABLE nodes DROP COLUMN source_cidrs_json;
`, `
CREATE TABLE project_scan_ports (
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK (position >= 0),
  name TEXT NOT NULL,
  protocol TEXT NOT NULL CHECK (protocol IN ('auto','http','https','ssh','rtsp','tcp','rdp','mysql','postgresql')),
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  PRIMARY KEY(project_id, position),
  UNIQUE(project_id, protocol, port)
);
INSERT INTO project_scan_ports(project_id,position,name,protocol,port)
SELECT id,0,'Web 服务','http',80 FROM projects
UNION ALL SELECT id,1,'Web 服务（HTTPS）','https',443 FROM projects
UNION ALL SELECT id,2,'AdGuard Home','http',3000 FROM projects
UNION ALL SELECT id,3,'SmartDNS','http',3001 FROM projects
UNION ALL SELECT id,4,'SSH','ssh',22 FROM projects;
`, `
ALTER TABLE endpoints ADD COLUMN ssh_auth_method TEXT NOT NULL DEFAULT '' CHECK (ssh_auth_method IN ('','password','key'));
ALTER TABLE endpoints ADD COLUMN ssh_username TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN ssh_key_path TEXT NOT NULL DEFAULT '';
`, `
UPDATE devices
SET name = '未知设备'
WHERE source = 'discovery'
  AND name IN ('Web 服务','Web 服务（HTTPS）','SSH','AdGuard Home','SmartDNS');
`, `
UPDATE devices
SET name = host
WHERE source = 'discovery' AND name = '未知设备';
`, `
ALTER TABLE endpoints DROP COLUMN allow_unknown_ssh_host_key;
`, `
ALTER TABLE access_sessions ADD COLUMN auth_session_id TEXT REFERENCES auth_sessions(id) ON DELETE CASCADE;
ALTER TABLE access_sessions ADD COLUMN grant_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE access_sessions ADD COLUMN grant_exchanged_at TEXT;
UPDATE access_sessions SET status = 'revoked', ended_at = COALESCE(ended_at, datetime('now')) WHERE status = 'active';
CREATE INDEX idx_access_sessions_auth ON access_sessions(auth_session_id,status,expires_at);
`, `
ALTER TABLE endpoints DROP COLUMN allow_insecure_tls;
`, `
ALTER TABLE access_sessions ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT '';
UPDATE access_sessions
SET last_seen_at = COALESCE(grant_exchanged_at, started_at)
WHERE last_seen_at = '';
CREATE INDEX idx_access_sessions_activity ON access_sessions(status,last_seen_at,expires_at);
`, `
ALTER TABLE access_sessions ADD COLUMN route_label TEXT NOT NULL DEFAULT '';
UPDATE access_sessions
SET status = 'revoked', ended_at = COALESCE(ended_at, datetime('now'))
WHERE mode = 'web' AND route_label = '' AND status = 'active';
`}
