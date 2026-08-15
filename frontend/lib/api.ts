export class APIError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

type ErrorEnvelope = { error?: { code?: string; message?: string } };

let csrfToken = typeof window === "undefined" ? "" : window.sessionStorage.getItem("dmp.csrf") || "";
let lastUserActivityAt = 0;

if (typeof window !== "undefined") {
  const markUserActivity = () => { lastUserActivityAt = Date.now(); };
  for (const eventName of ["pointerdown", "keydown", "touchstart"] as const) {
    window.addEventListener(eventName, markUserActivity, { capture: true, passive: true });
  }
}

function csrfCookie(): string {
  if (typeof document === "undefined") return "";
  const prefix = "dmp_csrf=";
  const item = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const currentCSRF = csrfToken || csrfCookie();
  if (currentCSRF && init.method && !["GET", "HEAD", "OPTIONS"].includes(init.method)) headers.set("X-CSRF-Token", currentCSRF);
  if (Date.now() - lastUserActivityAt < 30_000) headers.set("X-DMP-User-Activity", "1");
  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    let envelope: ErrorEnvelope = {};
    try { envelope = await response.json() as ErrorEnvelope; } catch { /* response may be empty */ }
    throw new APIError(response.status, envelope.error?.code || "request_failed", envelope.error?.message || `请求失败（${response.status}）`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export type APIUser = {
  id: string;
  username: string;
  displayName: string;
  email: string;
  role: "system_admin" | "project_admin" | "operator" | "temporary";
  enabled?: boolean;
  projectIds: string[];
  bootstrap?: boolean;
  mfaEnabled: boolean;
  passwordChangeRequired: boolean;
};

export type APISetupStatus = {
  initialized: boolean;
  mfaEnabled: boolean;
  mfaMethods: Array<"totp" | "email">;
  smtpConfigured: boolean;
};

export type APILoginChallenge = {
  next: "onboard" | "verify";
  challengeToken: string;
  methods: Array<"totp" | "email">;
  preferredMethod?: "totp" | "email";
  steps?: string[];
  expiresAt: string;
};

export type APIAuthSession = {
  user: APIUser;
  csrfToken: string;
  expiresAt: string;
  recoveryCodes?: string[];
  recoveryCodeUsed?: boolean;
  recoveryCodesRemaining?: number;
};

export type APIMFAStart = {
  method: "totp" | "email";
  expiresAt: string;
  maskedEmail?: string;
  resendAfterSeconds?: number;
  enrollment?: { qrCodeDataUrl: string; manualKey: string };
};

export type APISecuritySettings = {
  mfaEnabled: boolean;
  mfaMethods: Array<"totp" | "email">;
  smtpConfigured: boolean;
  smtpHost: string;
  smtpPort: number;
  smtpUsername: string;
  smtpPassword?: string;
  smtpPasswordConfigured: boolean;
  clearSMTPPassword?: boolean;
  smtpFrom: string;
  tlsConfigured: boolean;
  tlsCertFile: string;
  tlsKeyFile: string;
  accessTlsConfigured: boolean;
  accessTlsCertFile: string;
  accessTlsKeyFile: string;
  reusePanelPorts: boolean;
  accessHttpPort: number;
  accessHttpsPort: number;
  httpPort: number;
  httpsPort: number;
  emailCodeTTL: string;
  authSessionTTL: string;
  authSessionIdleTTL: string;
  mfaKeyFile: string;
  panelDomain: string;
  accessDomain: string;
  restartRequired: boolean;
  lockedFields: string[];
  source: "configuration_file" | "web_override";
};

export type APINode = {
  id: string;
  name: string;
  apiUrl: string;
  tlsServerName: string;
  portStart: number;
  portEnd: number;
  enabled: boolean;
  healthStatus: string;
};

export type APIProject = {
  id: string;
  code: string;
  name: string;
  nodeId: string;
  ownerName: string;
  clientId: number | null;
  networks: string[];
};

export type APIManagedTunnel = {
  id: number;
  clientId: number;
  clientName: string;
  port: number;
  configured: boolean;
  running: boolean;
  inletFlow: number;
  exportFlow: number;
};

export type APIMonitorNode = {
  nodeId: string;
  name: string;
  status: "healthy" | "unreachable" | "maintenance" | "unavailable";
  reachable: boolean;
  latencyMs: number;
  tunnelCount: number;
  runningTunnels: number;
  inletFlow: number;
  exportFlow: number;
  message: string;
  checkedAt: string;
};

export type APIMonitorSnapshot = {
  collectedAt: string;
  databaseStatus: string;
  nodeTotal: number;
  nodeReachable: number;
  tunnelTotal: number;
  tunnelRunning: number;
  activeSessions: number;
  runningPortForwards: number;
  inletFlow: number;
  exportFlow: number;
  nodes: APIMonitorNode[];
};

export type APINodeHealth = { reachable: boolean; checkedAt: string; latencyMs: number; message: string };
export type APINodeClient = { id: number; remark: string; address: string; enabled: boolean; connected: boolean; version: string; inletFlow: number; exportFlow: number };
export type APINodeClientCredentials = { basicUsername: string; basicPassword: string; verifyKey: string };
export type APINodeClientCreateResult = { client: APINodeClient; credentials: APINodeClientCredentials };

export type APIEndpoint = {
  id: string;
  name: string;
  protocol: "http" | "https" | "ssh" | "rtsp" | "tcp" | "rdp" | "mysql" | "postgresql";
  targetPort: number;
  verificationStatus: string;
  tlsServerName: string;
  credentialConfigured: boolean;
  sshAuthMethod: "" | "password" | "key";
  sshUsername: string;
  sshKeyPath: string;
  sshHostKeyFingerprint: string;
};

export type APIDevice = {
  id: string;
  projectId: string;
  host: string;
  name: string;
  deviceType: string;
  vendor: string;
  source: string;
  status: string;
  lastSeenAt: string | null;
  endpoints: APIEndpoint[];
  updatedAt: string;
};

export type APIDeviceVerification = {
  device: APIDevice;
  verified: number;
  failed: number;
};

export type APISession = {
  sessionId: string;
  launchUrl: string;
  expiresAt: string;
};

export type APIAccessSession = {
  id: string;
  userId: string | null;
  projectId: string;
  endpointId: string;
  endpointName: string;
  deviceName: string;
  mode: "web" | "ssh";
  sourceIp: string;
  status: string;
  expiresAt: string;
  startedAt: string;
};

export type APIAccessPolicy = {
  id: string;
  name: string;
  projectIds: string[];
  userIds: string[];
  capabilities: string[];
  validFrom: string | null;
  validUntil: string | null;
  enabled: boolean;
};

export type APIAuditLog = {
  id: string;
  actor: string;
  action: string;
  resourceType: string;
  resourceId: string;
  result: string;
  sourceIp: string;
  createdAt: string;
};

export type APIPortForward = {
  id: string;
  projectId: string;
  endpointId: string;
  endpointName: string;
  deviceName: string;
  nodeId: string;
  target: string;
  serverPort: number;
  status: string;
  expiresAt: string | null;
};

export type APIDiscoveryPort = {
  port: number;
  protocol: "auto" | "http" | "https" | "ssh" | "rtsp" | "tcp" | "rdp" | "mysql" | "postgresql";
  name: string;
};

export type APIDiscoveryJob = {
  id: string;
  projectId: string;
  networks: string[];
  ports: APIDiscoveryPort[];
  status: "queued" | "running" | "completed" | "failed" | "canceled";
  progress: number;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
};

export type APIDiscoveryResult = {
  id: string;
  jobId: string;
  host: string;
  port: number;
  protocol: Exclude<APIDiscoveryPort["protocol"], "auto">;
  serviceName: string;
  fingerprint: string;
  responseSummary: string;
  confidence: number;
  importStatus: string;
};

export const api = {
  async setupStatus() { return request<APISetupStatus>("/api/v1/setup/status"); },
  async setup(username: string, displayName: string, password: string) {
    return request<APIUser>("/api/v1/setup", { method: "POST", body: JSON.stringify({ username, displayName, password }) });
  },
  async me() { return request<APIUser>("/api/v1/auth/me"); },
  async login(username: string, password: string) {
    const result = await request<APIAuthSession | APILoginChallenge>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
    if ("user" in result) rememberSession(result);
    return result;
  },
  async setOnboardingPassword(challengeToken: string, newPassword: string) {
    return request<{ next: "email" }>("/api/v1/auth/onboarding/password", { method: "POST", body: JSON.stringify({ challengeToken, newPassword }) });
  },
  async sendOnboardingEmail(challengeToken: string, email: string) {
    return request<{ maskedEmail: string; expiresAt: string; resendAfterSeconds: number }>("/api/v1/auth/onboarding/email/send", { method: "POST", body: JSON.stringify({ challengeToken, email }) });
  },
  async verifyOnboardingEmail(challengeToken: string, code: string) {
    return request<{ next: "mfa"; email: string; methods: Array<"totp" | "email"> }>("/api/v1/auth/onboarding/email/verify", { method: "POST", body: JSON.stringify({ challengeToken, code }) });
  },
  async startMFA(challengeToken: string, method: "totp" | "email") {
    return request<APIMFAStart>("/api/v1/auth/mfa/start", { method: "POST", body: JSON.stringify({ challengeToken, method }) });
  },
  async completeMFA(challengeToken: string, code: string) {
    const result = await request<APIAuthSession>("/api/v1/auth/mfa/complete", { method: "POST", body: JSON.stringify({ challengeToken, code }) });
    rememberSession(result);
    return result;
  },
  async logout() {
    await request<void>("/api/v1/auth/logout", { method: "POST" });
    csrfToken = "";
    if (typeof window !== "undefined") window.sessionStorage.removeItem("dmp.csrf");
  },
  async nodes() { return (await request<{ items: APINode[] }>("/api/v1/nodes")).items; },
  async createNode(input: Record<string, unknown>) { return request<APINode>("/api/v1/nodes", { method: "POST", body: JSON.stringify(input) }); },
  async updateNode(nodeId: string, input: Record<string, unknown>) { return request<APINode>(`/api/v1/nodes/${encodeURIComponent(nodeId)}`, { method: "PATCH", body: JSON.stringify(input) }); },
  async deleteNode(nodeId: string) { return request<void>(`/api/v1/nodes/${encodeURIComponent(nodeId)}`, { method: "DELETE" }); },
  async nodeHealth(nodeId: string) { return request<APINodeHealth>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/health`); },
  async nodeClients(nodeId: string) { return (await request<{ items: APINodeClient[] }>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/clients`)).items; },
  async nodeClientCredentials(nodeId: string, clientId: number) { return request<APINodeClientCredentials>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/clients/${clientId}/credentials`); },
  async createNodeClient(nodeId: string, input: { remark: string; basicUsername: string; basicPassword: string; verifyKey: string }) { return request<APINodeClientCreateResult>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/clients`, { method: "POST", body: JSON.stringify(input) }); },
  async projects() { return (await request<{ items: APIProject[] }>("/api/v1/projects")).items; },
  async createProject(input: Record<string, unknown>) { return request<APIProject>("/api/v1/projects", { method: "POST", body: JSON.stringify(input) }); },
  async updateProject(projectId: string, input: Record<string, unknown>) { return request<APIProject>(`/api/v1/projects/${encodeURIComponent(projectId)}`, { method: "PATCH", body: JSON.stringify(input) }); },
  async deleteProject(projectId: string) { return request<void>(`/api/v1/projects/${encodeURIComponent(projectId)}`, { method: "DELETE" }); },
  async devices(projectId: string) { return (await request<{ items: APIDevice[] }>(`/api/v1/projects/${encodeURIComponent(projectId)}/devices`)).items; },
  async createDevice(projectId: string, input: Record<string, unknown>) { return request<APIDevice>(`/api/v1/projects/${encodeURIComponent(projectId)}/devices`, { method: "POST", body: JSON.stringify(input) }); },
  async createDevices(projectId: string, items: Record<string, unknown>[]) { return (await request<{ items: APIDevice[] }>(`/api/v1/projects/${encodeURIComponent(projectId)}/devices/batch`, { method: "POST", body: JSON.stringify({ items }) })).items; },
  async updateDevice(projectId: string, deviceId: string, input: Record<string, unknown>) { return request<APIDevice>(`/api/v1/projects/${encodeURIComponent(projectId)}/devices/${encodeURIComponent(deviceId)}`, { method: "PATCH", body: JSON.stringify(input) }); },
  async deleteDevice(projectId: string, deviceId: string) { return request<void>(`/api/v1/projects/${encodeURIComponent(projectId)}/devices/${encodeURIComponent(deviceId)}`, { method: "DELETE" }); },
  async verifyDevice(projectId: string, deviceId: string) { return request<APIDeviceVerification>(`/api/v1/projects/${encodeURIComponent(projectId)}/devices/${encodeURIComponent(deviceId)}/verify`, { method: "POST" }); },
  async createAccessSession(endpointId: string, mode: "web" | "ssh") {
    return request<APISession>("/api/v1/access-sessions", { method: "POST", body: JSON.stringify({ endpointId, mode }) });
  },
  async users() { return (await request<{ items: APIUser[] }>("/api/v1/users")).items; },
  async createUser(input: Record<string, unknown>) { return request<APIUser>("/api/v1/users", { method: "POST", body: JSON.stringify(input) }); },
  async updateUser(userId: string, input: Record<string, unknown>) { return request<APIUser>(`/api/v1/users/${encodeURIComponent(userId)}`, { method: "PATCH", body: JSON.stringify(input) }); },
  async deleteUser(userId: string) { return request<void>(`/api/v1/users/${encodeURIComponent(userId)}`, { method: "DELETE" }); },
  async resetUserMFA(userId: string) { return request<void>(`/api/v1/users/${encodeURIComponent(userId)}/mfa/reset`, { method: "POST" }); },
  async securitySettings() { return request<APISecuritySettings>("/api/v1/settings/security"); },
  async updateSecuritySettings(input: APISecuritySettings) { return request<APISecuritySettings>("/api/v1/settings/security", { method: "PUT", body: JSON.stringify(input) }); },
  async restartPanel() { return request<{ status: string }>("/api/v1/system/restart", { method: "POST" }); },
  async policies() { return (await request<{ items: APIAccessPolicy[] }>("/api/v1/access-policies")).items; },
  async createPolicy(input: Record<string, unknown>) { return request<APIAccessPolicy>("/api/v1/access-policies", { method: "POST", body: JSON.stringify(input) }); },
  async updatePolicy(policyId: string, input: Record<string, unknown>) { return request<APIAccessPolicy>(`/api/v1/access-policies/${encodeURIComponent(policyId)}`, { method: "PATCH", body: JSON.stringify(input) }); },
  async deletePolicy(policyId: string) { return request<void>(`/api/v1/access-policies/${encodeURIComponent(policyId)}`, { method: "DELETE" }); },
  async sessions() { return (await request<{ items: APIAccessSession[] }>("/api/v1/access-sessions")).items; },
  async monitorSnapshot() { return request<APIMonitorSnapshot>("/api/v1/monitor/snapshot"); },
  async revokeSession(sessionId: string) { return request<void>(`/api/v1/access-sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" }); },
  async auditLogs(search = "") { return (await request<{ items: APIAuditLog[] }>(`/api/v1/audit-logs?limit=200&search=${encodeURIComponent(search)}`)).items; },
  async portForwards(projectId: string) { return (await request<{ items: APIPortForward[] }>(`/api/v1/projects/${encodeURIComponent(projectId)}/port-forwards`)).items; },
  async createPortForward(projectId: string, input: { endpointId: string; serverPort: number; expiresAt: string | null }) { return request<APIPortForward>(`/api/v1/projects/${encodeURIComponent(projectId)}/port-forwards`, { method: "POST", body: JSON.stringify(input) }); },
  async setPortForward(forwardId: string, running: boolean) { return request<{ id: string; status: string }>(`/api/v1/port-forwards/${encodeURIComponent(forwardId)}/${running ? "start" : "stop"}`, { method: "POST" }); },
  async deletePortForward(forwardId: string) { return request<void>(`/api/v1/port-forwards/${encodeURIComponent(forwardId)}`, { method: "DELETE" }); },
  async setManagedTunnel(nodeId: string, clientId: number, running: boolean) { return request<{ running: boolean }>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/managed-tunnels/${clientId}/${running ? "start" : "stop"}`, { method: "POST" }); },
  async managedTunnels(nodeId: string) { return (await request<{ items: APIManagedTunnel[] }>(`/api/v1/nodes/${encodeURIComponent(nodeId)}/managed-tunnels`)).items; },
  async projectScanPorts(projectId: string) { return (await request<{ items: APIDiscoveryPort[] }>(`/api/v1/projects/${encodeURIComponent(projectId)}/scan-ports`)).items; },
  async updateProjectScanPorts(projectId: string, ports: APIDiscoveryPort[]) { return (await request<{ items: APIDiscoveryPort[] }>(`/api/v1/projects/${encodeURIComponent(projectId)}/scan-ports`, { method: "PUT", body: JSON.stringify({ ports }) })).items; },
  async createDiscoveryJob(projectId: string, networks: string[], ports: APIDiscoveryPort[]) {
    return request<APIDiscoveryJob>(`/api/v1/projects/${encodeURIComponent(projectId)}/discovery-jobs`, { method: "POST", body: JSON.stringify({ networks, ports }) });
  },
  async discoveryJob(jobId: string) {
    return request<{ job: APIDiscoveryJob; results: APIDiscoveryResult[] }>(`/api/v1/discovery-jobs/${encodeURIComponent(jobId)}`);
  },
  async cancelDiscoveryJob(jobId: string) {
    return request<{ id: string; status: string }>(`/api/v1/discovery-jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" });
  },
  async importDiscoveryDevice(jobId: string, input: Record<string, unknown>) {
    return request<APIDevice>(`/api/v1/discovery-jobs/${encodeURIComponent(jobId)}/import`, { method: "POST", body: JSON.stringify(input) });
  },
};

function rememberSession(result: APIAuthSession) {
  csrfToken = result.csrfToken;
  if (typeof window !== "undefined") window.sessionStorage.setItem("dmp.csrf", csrfToken);
}
