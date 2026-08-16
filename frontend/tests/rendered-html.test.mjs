import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const pageURL = new URL("../app/page.tsx", import.meta.url);
const apiURL = new URL("../lib/api.ts", import.meta.url);
const stylesURL = new URL("../app/globals.css", import.meta.url);
const viteConfigURL = new URL("../vite.spa.config.ts", import.meta.url);

const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const contains = (source, values) => {
  for (const value of values) {
    assert.match(source, new RegExp(escapeRegExp(value)), `missing product contract: ${value}`);
  }
};

test("builds the formal application shell", async () => {
  const html = await readFile(new URL("../dist-spa/index.html", import.meta.url), "utf8");
  contains(html, ['<html lang="zh-CN">', "I5CLOUD 远程管理平台", 'id="root"', '/assets/app-']);
  assert.doesNotMatch(html, /Your site is taking shape|Building your site|codex-preview/i);
});

test("keeps the complete formal navigation and no preview artifacts", async () => {
  const [page, packageJson] = await Promise.all([
    readFile(pageURL, "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);
  contains(page, ["概览", "访问门户", "客户项目", "SOCKS隧道", "接入节点", "用户与权限", "访问策略", "运行监控", "访问审计", "系统设置"]);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
  assert.doesNotMatch(page, /SkeletonPreview|codex-preview|remote-management-demo/);
  assert.match(packageJson, /"name": "device-management-platform-frontend"/);
  assert.doesNotMatch(packageJson, /vinext|wrangler|cloudflare|next/);
});

test("uses the authenticated versioned backend contract", async () => {
  const [api, config] = await Promise.all([readFile(apiURL, "utf8"), readFile(viteConfigURL, "utf8")]);
  contains(api, ["/api/v1/nodes", "/api/v1/projects", "/devices/batch", "/api/v1/access-policies", "/api/v1/access-sessions", "/api/v1/monitor/snapshot", "/managed-tunnels", "/discovery-jobs"]);
  contains(api, ['credentials: "same-origin"', "X-CSRF-Token", "throw new APIError"]);
  contains(config, ["DMP_DEV_API_TARGET", '"/api"', '"/access"', "ws: true", '"/health"']);
  assert.doesNotMatch(config, /mock|fakeData|fixture/i);
});

test("deduplicates and briefly reuses safe read queries across page reloads", async () => {
  const [page, api] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8")]);
  contains(api, ["dmp.read-cache.v1:", "defaultReadCacheTTL = 10_000", "freshReadThrottleMs = 2_000", "inFlightReads", "inFlightFreshReads", "lastFreshReadAt", "readCacheGeneration", "readPathGenerations", "invalidateReadPath(path)", "window.sessionStorage", "Cache-Control", "no-store", "no-cache", "if (method !== \"GET\") clearReadCache()", "cacheGeneration === readCacheGeneration", "pathGeneration === (readPathGenerations.get(path) || 0)", "clearReadCache();\n  form.submit()", 'request<APIUser>("/api/v1/auth/me", {}, { cache: false, fresh: true })', "{ cache: false, fresh: true }"]);
  contains(page, ["api.monitorSnapshot(true)", "api.nodeHealth(node.id, true)", "api.managedTunnels(node.id, true)", "api.nodeClients(node.id, true)"]);
});

test("keeps formal login, MFA and editable deployment settings", async () => {
  const [page, api, styles] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8"), readFile(stylesURL, "utf8")]);
  contains(page, ["修改初始密码", "绑定并验证邮箱", "开启双重认证", "认证器令牌", "邮箱验证码", "保存系统设置", "SMTP 主机", "SMTP 密码", "HTTP 端口", "HTTPS 端口", "面板证书文件路径", "面板私钥文件路径", "面板地址", "反代地址", "反代端口", "独立设置反代端口", "反代证书文件路径", "反代私钥文件路径"]);
  contains(page, ['<span aria-hidden="true">*.</span>']);
  assert.match(styles, /\.domain-prefix-input > span \{[^}]*color: #314347;[^}]*background: transparent;[^}]*font-size: 13px;[^}]*font-weight: 700;/);
  assert.doesNotMatch(styles, /\.domain-prefix-input > span \{[^}]*border-right:/);
  contains(api, ["/auth/onboarding/password", "/auth/onboarding/email/send", "/auth/onboarding/email/verify", "/auth/mfa/start", "/auth/mfa/complete", "/mfa/reset", "/settings/security"]);
  assert.doesNotMatch(page, /不可在线降低的边界|连接安全|本机 Relay（无 TLS）|可信反向代理 CIDR|生产环境|开发环境|测试环境/);
});

test("initializes the first administrator without deployment tokens", async () => {
  const [page, api] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8")]);
  contains(page, ["创建首位系统管理员", "显示名称", "初始管理员密码（至少 12 位）", "双重认证可在系统设置中启用"]);
  contains(api, ["/api/v1/setup"]);
  assert.doesNotMatch(page, /初始化令牌|setupToken/);
  assert.doesNotMatch(api, /X-Setup-Token|setupToken/);
});

test("opens opaque Web and SSH sessions without exposing routes", async () => {
  const [page, api] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8")]);
  contains(page, ["submitWebAccessLaunch(endpoint.endpointId)", 'window.open("about:blank", "_blank")', "opened.opener = null", '"ssh"', "opened.location.replace(session.launchUrl)", "浏览器阻止了新标签页"]);
  contains(api, ['form.method = "post"', 'form.action = "/api/v1/access-sessions/launch"', 'form.target = "_blank"', 'form.rel = "noopener noreferrer"', '["csrfToken", currentCSRF]']);
  assert.doesNotMatch(page, /api\.createAccessSession\(endpoint\.endpointId,\s*"web"\)/);
  assert.doesNotMatch(page, /JSON\.stringify\([^\n]*remoteSession|setModal\("web"\)|setModal\("ssh"\)/);
});

test("keeps node configuration minimal and Client management add-only", async () => {
  const [page, api] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8")]);
  contains(page, ["API 地址", "TLS 校验主机名", "NPS API 密钥", "HMAC-SHA256", "AES-GCM 加密保存", "现有 Client 只读", "Basic 认证用户名", "Basic 认证密码", "唯一验证密钥", "留空自动生成"]);
  for (const removed of ["接入方式", "通道访问主机", "客户端接入主机", "客户端接入端口", "来源限制", "高级密钥引用", "删除 Client", "编辑 Client"]) assert.doesNotMatch(page, new RegExp(removed));
  contains(api, ["createNodeClient", "nodeClientCredentials"]);
  assert.doesNotMatch(api, /deleteNodeClient|updateNodeClient/);
});

test("shows all node tunnels with independent state and activity", async () => {
  const [page, api] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8")]);
  contains(page, ["节点实际返回的 SOCKS隧道", "未绑定", "运行中", "已关闭", "流量活跃", "空闲倒计时", "剩余时长", "自动关闭时间", "最近活动", "采样于", "formatDuration", "localTunnelRemainingSeconds", "本地倒计时已结束，请刷新确认节点状态", "remainingSeconds", "autoCloseAt", "observedAt", "端口由 NPS SOCKS隧道详情返回", "域名前缀", "session.domainPrefix", "每次创建 Web 访问会话时生成独立的 8 位随机域名前缀", 'className="socks-table"', "api.setManagedTunnel", "const status = await api.setManagedTunnel", "markProjectTunnelOpen(project)"]);
  assert.doesNotMatch(page, /托管通道|托管隧道|SOCKS 通道/);
  contains(api, ["return request<APIManagedTunnel>", "/managed-tunnels/"]);
  assert.doesNotMatch(page, /<th>会话<\/th>|session\.id\.slice\(0, 8\)<\/code>/);
  assert.doesNotMatch(page, /inactiveCountdown|非活跃倒计时|activityClock|className="socks-card"|按 Client ID 推算 SOCKS 端口/);
  assert.doesNotMatch(page, /setInterval\([\s\S]{0,160}onRefresh/);
});

test("keeps UI clocks local and limits necessary background polling", async () => {
  const page = await readFile(pageURL, "utf8");
  contains(page, ["useLocalClock", "setNow(Date.now())", "document.visibilityState", "visibilitychange", "setTimeout(() => void poll(), 5000)"]);
  assert.doesNotMatch(page, /setInterval\([\s\S]{0,200}(?:api\.|onRefresh|poll\()/);
});

test("creates projects by binding an existing Client and scopes CIDRs to discovery", async () => {
  const page = await readFile(pageURL, "utf8");
  contains(page, ["项目名称", "负责人", "接入节点", "选择 Client 或手动输入 ID", "扫描内网 IP 段", "UnifiedSelect", "unified-select-menu", "ClientCombobox", "client-combobox-menu", "没有匹配的 Client，可直接输入 ID", "MultiChoiceField", 'className="project-table"']);
  assert.equal((page.match(/<select/g) || []).length, 0, "native select elements must not remain");
  assert.doesNotMatch(page, /project-client-select|client-combobox-select|client-combobox-chevron|<select[^>]*multiple|size=\{Math\.min|<datalist|showPicker/);
  assert.doesNotMatch(page, /关联规则|GatewayBootstrapModal|网关接入方式|客户端运行环境|范围外.*不能访问|配置后才允许发现和远程访问/);
});

test("persists the compact per-project discovery contract", async () => {
  const [page, api] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8")]);
  contains(page, ["Web 服务", "Web 服务（HTTPS）", "AdGuard Home", "SmartDNS", "SSH", "保存扫描端口", "按项目保存扫描端口", "一个设备可包含多个命名服务"]);
  for (const port of [80, 443, 3000, 3001, 22]) assert.match(page, new RegExp(`port: ${port}`));
  assert.doesNotMatch(page, /Web 8080|HTTPS 8443|HTTPS 9443|SSH 2222/);
  contains(api, ["projectScanPorts", "updateProjectScanPorts"]);
});

test("edits devices atomically with per-service HTTPS and practical SSH settings", async () => {
  const [page, api] = await Promise.all([readFile(pageURL, "utf8"), readFile(apiURL, "utf8")]);
  contains(page, ["api.updateDevice", "endpoints:", "api.createDevices", "事务化导入", "Web 服务入口", "TCP 服务", "创建访问入口", "TLS 校验主机名", "SSH 主机密钥指纹", "SSH 登录方式", "SSH 私钥文件路径", "密码加密保存且不回显", "sshCredentialChanged", "canReuseStoredSSHSecret", "请完成当前分类中的必填项"]);
  const manageDevice = page.slice(page.indexOf("function ManageDeviceModal"), page.indexOf("function parseCSVLine"));
  assert.doesNotMatch(manageDevice, /name="sshUsername"[\s\S]{0,100}required=/);
  assert.doesNotMatch(manageDevice, /name="sshKeyPath"[\s\S]{0,100}required=/);
  for (const removed of ["HTTPS 高级设置", "允许设备自签名证书", "授权凭据引用（可选）", "临时允许未知主机密钥"]) assert.doesNotMatch(page, new RegExp(removed));
  contains(api, ["tlsServerName", "credentialConfigured", "sshHostKeyFingerprint", "sshAuthMethod", "sshUsername", "sshKeyPath"]);
  assert.doesNotMatch(api, /addEndpoint\(|updateEndpoint\(|deleteEndpoint\(/);
});

test("uses shared pagination, accessible dialogs and destructive confirmation", async () => {
  const [page, styles] = await Promise.all([readFile(pageURL, "utf8"), readFile(stylesURL, "utf8")]);
  contains(page, ["function Pagination", "每页显示", "function ConfirmButton", 'role="dialog"', "aria-modal", 'event.key === "Escape"', 'confirmLabel="确认停止？"', 'label="删除设备"', 'label="删除项目"']);
  contains(styles, [".pagination-footer", ".showcase-hero", ".app-shell", ".sidebar", "main {", "overflow-y: auto"]);
});

test("keeps contextual help single-layered and typography readable", async () => {
  const [page, styles] = await Promise.all([readFile(pageURL, "utf8"), readFile(stylesURL, "utf8")]);
  contains(page, ["function HelpTip", 'role="tooltip"', "userChoiceLabel", "user.displayName", "user.username"]);
  assert.doesNotMatch(page, /className="help-tip"[^>]*title=/);
  contains(styles, [".help-tip:hover", ".scan-network-boundary .help-tip > [role=\"tooltip\"]", "正式版基础字号"]);
});

test("exposes truthful SQLite backup and offline restore guidance", async () => {
  const page = await readFile(pageURL, "utf8");
  contains(page, ["/api/v1/data/backup", "SQLite VACUUM INTO", "恢复属于停机维护操作", "使用管理命令执行"]);
  assert.doesNotMatch(page, /导入 \/ 恢复/);
});
