import {
  type Dispatch,
  FormEvent,
  type SetStateAction,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  api,
  APIError,
  type APIAccessPolicy,
  type APIAccessSession,
  type APIAuditLog,
  type APIAuthSession,
  type APIDevice,
  type APIDiscoveryPort,
  type APIDiscoveryResult,
  type APILoginChallenge,
  type APIMFAStart,
  type APIManagedTunnel,
  type APIMonitorSnapshot,
  type APINode,
  type APINodeClient,
  type APINodeClientCreateResult,
  type APINodeClientCredentials,
  type APIPortForward,
  type APIProject,
  type APISecuritySettings,
  type APISetupStatus,
  type APIUser,
} from "../lib/api";

type View =
  | "overview"
  | "portal"
  | "workspace"
  | "nodes"
  | "projects"
  | "socks"
  | "connections"
  | "accounts"
  | "policies"
  | "monitor"
  | "discovery"
  | "logs"
  | "settings";
type Modal =
  | "add-device"
  | "manage-device"
  | "import-devices"
  | "edit-project"
  | "create-project"
  | "create-node"
  | "create-connection"
  | "create-policy"
  | "create-user"
  | "edit-node"
  | "edit-connection"
  | "edit-policy"
  | "edit-user"
  | "socks-detail"
  | "node-clients"
  | null;
type ConfigModalKind =
  | "create-node"
  | "create-policy"
  | "create-user"
  | "edit-node"
  | "edit-policy"
  | "edit-user";
type WebService = {
  name: string;
  url: string;
  endpointId?: string;
  tlsServerName?: string;
  allowInsecureTls?: boolean;
  verificationStatus?: string;
};
type ServiceProtocol =
  "http" | "https" | "ssh" | "rtsp" | "tcp" | "rdp" | "mysql" | "postgresql";
type OtherServiceProtocol = Exclude<ServiceProtocol, "http" | "https" | "ssh">;
type DeviceServiceEndpoint = {
  id?: string;
  name: string;
  protocol: ServiceProtocol;
  port: number;
  tlsServerName?: string;
  allowInsecureTls?: boolean;
  credentialConfigured?: boolean;
  sshAuthMethod?: "" | "password" | "key";
  sshUsername?: string;
  sshKeyPath?: string;
  sshCredential?: {
    method: "password" | "key";
    username: string;
    password?: string;
    keyPath?: string;
  };
  sshHostKeyFingerprint?: string;
  verificationStatus?: string;
};
type EditableWebRow = {
  id: number | string;
  endpointId?: string;
  name: string;
  protocol: string;
  port: string;
  tlsServerName: string;
  allowInsecureTls: boolean;
};
const VALID_VIEWS = new Set<View>([
  "overview",
  "portal",
  "workspace",
  "nodes",
  "projects",
  "socks",
  "connections",
  "accounts",
  "policies",
  "monitor",
  "discovery",
  "logs",
  "settings",
]);

type Device = {
  id: number | string;
  projectCode: string;
  name: string;
  host: string;
  type: string;
  vendor: string;
  status: "online" | "offline" | "warning";
  web: string | null;
  webServices: WebService[];
  ssh: boolean;
  sshPort: number | null;
  sshEndpointId?: string;
  services: number;
  serviceEndpoints?: DeviceServiceEndpoint[];
  lastSeen: string;
};

type DiscoveryService = {
  id: string;
  name: string;
  protocol: ServiceProtocol;
  port: number | "";
  evidence: string;
  selected: boolean;
};

type DiscoveryResult = {
  host: string;
  title: string;
  fingerprint: string;
  evidence: string;
  confidence: number;
  services: DiscoveryService[];
};

type EditableDiscoveryPort = Omit<APIDiscoveryPort, "port"> & {
  id: string;
  port: number | "";
};
const DEFAULT_DISCOVERY_PORTS: EditableDiscoveryPort[] = [
  { id: "http-80", name: "Web 服务", protocol: "http", port: 80 },
  { id: "https-443", name: "Web 服务（HTTPS）", protocol: "https", port: 443 },
  { id: "http-3000", name: "AdGuard Home", protocol: "http", port: 3000 },
  { id: "http-3001", name: "SmartDNS", protocol: "http", port: 3001 },
  { id: "ssh-22", name: "SSH", protocol: "ssh", port: 22 },
];

type NodeView = {
  id?: string;
  raw?: APINode;
  name: string;
  host: string;
  status: string;
  tlsName: string;
  clients: number;
  projects: number;
  latency: string;
  ports: string;
  tunnels: number;
  runningTunnels: number;
};
type NodeManagedTunnel = APIManagedTunnel & {
  nodeId: string;
  nodeName: string;
};
type ProjectView = {
  id?: string;
  nodeId?: string;
  name: string;
  code: string;
  node: string;
  clientStatus: string;
  clientId: number;
  devices: number;
  web: number;
  owner: string;
  accent: string;
  networks: string[];
};
const EMPTY_PROJECT: ProjectView = {
  name: "未选择项目",
  code: "",
  node: "",
  clientStatus: "离线",
  clientId: 0,
  devices: 0,
  web: 0,
  owner: "",
  accent: "teal",
  networks: [],
};
const userChoiceLabel = (user: APIUser) =>
  `${user.displayName}（${user.username}）`;

const nodeServiceHost = (node?: NodeView) =>
  node
    ? (() => {
        try {
          return new URL(node.raw?.apiUrl || `https://${node.host}`).hostname;
        } catch {
          return node.host.split(":")[0];
        }
      })()
    : "—";
const projectSocksAddress = (
  project: ProjectView,
  nodeList: NodeView[] = [],
  port = 10000 + project.clientId,
) =>
  `${nodeServiceHost(nodeList.find((node) => node.name === project.node))}:${port}`;
const formatBytes = (value: number) => {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  const amount = value / 1024 ** index;
  return `${amount >= 100 || index === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[index]}`;
};

const ipv4ToNumber = (value: string) => {
  const parts = value.split(".");
  if (
    parts.length !== 4 ||
    parts.some((part) => !/^\d+$/.test(part) || Number(part) > 255)
  )
    return null;
  return parts.reduce((total, part) => total * 256 + Number(part), 0) >>> 0;
};

const parseIPv4Cidrs = (value: string) => [
  ...new Set(
    value
      .split(/[,，;；\n]+/)
      .map((item) => item.trim())
      .filter(Boolean),
  ),
];

const isValidIPv4Cidr = (value: string) => {
  const [address, prefixText] = value.split("/");
  const prefix = Number(prefixText);
  return (
    ipv4ToNumber(address) !== null &&
    Number.isInteger(prefix) &&
    prefix >= 0 &&
    prefix <= 32
  );
};

const groupDiscoveryResults = (
  results: APIDiscoveryResult[],
): DiscoveryResult[] => {
  const hosts = new Map<string, APIDiscoveryResult[]>();
  for (const result of results)
    hosts.set(result.host, [...(hosts.get(result.host) || []), result]);
  return [...hosts.entries()].map(([host, services]) => {
    const fingerprints = [
      ...new Set(
        services.map((service) => service.fingerprint).filter(Boolean),
      ),
    ];
    const evidence = [
      ...new Set(
        services.map((service) => service.responseSummary).filter(Boolean),
      ),
    ];
    return {
      host,
      title: host,
      fingerprint: fingerprints.join(" / ") || "未识别设备",
      evidence: evidence.join(" · ") || "TCP 响应已验证",
      confidence: Math.max(...services.map((service) => service.confidence), 0),
      services: services.map((service) => ({
        id: service.id,
        name:
          service.serviceName ||
          `${service.protocol.toUpperCase()} ${service.port}`,
        protocol: service.protocol,
        port: service.port,
        evidence: service.responseSummary || "协议响应已验证",
        selected: service.importStatus !== "imported",
      })),
    };
  });
};

const mapNode = (node: APINode, allProjects: APIProject[]): NodeView => {
  let host = node.apiUrl;
  try {
    host = new URL(node.apiUrl).host;
  } catch {
    /* keep configured address */
  }
  return {
    id: node.id,
    name: node.name,
    host,
    status:
      node.enabled &&
      ["healthy", "online", "reachable"].includes(node.healthStatus)
        ? "运行正常"
        : node.enabled
          ? "待检查"
          : "维护中",
    tlsName: node.tlsServerName || "—",
    clients: 0,
    projects: allProjects.filter((project) => project.nodeId === node.id)
      .length,
    latency: "—",
    ports: `${node.portStart}–${node.portEnd}`,
    tunnels: 0,
    runningTunnels: 0,
    raw: node,
  };
};

const mapProject = (project: APIProject, allNodes: APINode[]): ProjectView => ({
  id: project.id,
  nodeId: project.nodeId,
  name: project.name,
  code: project.code,
  node:
    allNodes.find((node) => node.id === project.nodeId)?.name || "未分配节点",
  clientStatus: "离线",
  clientId: project.clientId || 0,
  devices: 0,
  web: 0,
  owner: project.ownerName,
  accent: "teal",
  networks: project.networks,
});

const deviceTypeLabel = (value: string) => {
  const labels: Record<string, string> = {
    network: "网络设备",
    camera: "视频监控",
    plc: "工业控制",
    server: "服务器",
    other: "未知设备",
    discovered: "未知设备",
  };
  return labels[value] || value || "未知设备";
};

const mapDevice = (device: APIDevice, project: ProjectView): Device => {
  const webEndpoints = device.endpoints.filter(
    (endpoint) => endpoint.protocol === "http" || endpoint.protocol === "https",
  );
  const sshEndpoint = device.endpoints.find(
    (endpoint) => endpoint.protocol === "ssh",
  );
  const serviceEndpoints: DeviceServiceEndpoint[] = device.endpoints.map(
    (endpoint) => ({
      id: endpoint.id,
      name: endpoint.name,
      protocol: endpoint.protocol as ServiceProtocol,
      port: endpoint.targetPort,
      tlsServerName: endpoint.tlsServerName,
      allowInsecureTls: endpoint.allowInsecureTls,
      credentialConfigured: endpoint.credentialConfigured,
      sshAuthMethod: endpoint.sshAuthMethod,
      sshUsername: endpoint.sshUsername,
      sshKeyPath: endpoint.sshKeyPath,
      sshHostKeyFingerprint: endpoint.sshHostKeyFingerprint,
      verificationStatus: endpoint.verificationStatus,
    }),
  );
  const webServices = webEndpoints.map((endpoint) => ({
    endpointId: endpoint.id,
    name: endpoint.name,
    url: `${endpoint.protocol}://${device.host}:${endpoint.targetPort}`,
    tlsServerName: endpoint.tlsServerName,
    allowInsecureTls: endpoint.allowInsecureTls,
    verificationStatus: endpoint.verificationStatus,
  }));
  return {
    id: device.id,
    projectCode: project.code,
    name: device.name,
    host: device.host,
    type: deviceTypeLabel(device.deviceType),
    vendor: device.vendor || "未识别",
    status:
      device.status === "online"
        ? "online"
        : device.status === "offline"
          ? "offline"
          : "warning",
    web: webServices[0]?.url || null,
    webServices,
    ssh: Boolean(sshEndpoint),
    sshPort: sshEndpoint?.targetPort || null,
    sshEndpointId: sshEndpoint?.id,
    services: device.endpoints.length,
    serviceEndpoints,
    lastSeen: device.lastSeenAt
      ? new Date(device.lastSeenAt).toLocaleString("zh-CN")
      : "尚未检测",
  };
};

function StatusDot({ status }: { status: Device["status"] }) {
  const label =
    status === "online" ? "在线" : status === "offline" ? "离线" : "待检测";
  return (
    <span className={`status status-${status}`}>
      <i />
      {label}
    </span>
  );
}

function Tag({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={`tag tag-${tone}`}>{children}</span>;
}

const FIELD_HELP: Record<string, string> = {
  "API 地址":
    "平台后端访问接入节点管理接口的地址，不是最终用户打开设备后台的地址。",
  "TLS 校验主机名":
    "用于校验 HTTPS 证书中的 SAN 主机名。即使通过 IP 访问，也应填写证书实际覆盖的域名。",
  认证账号: "节点管理账号。编辑时留空会保留已保存的账号。",
  认证密码:
    "密码只会通过 HTTPS 提交一次，后端使用 AES-GCM 加密后写入数据库；页面和 API 永不回显。编辑时留空会保留现有密码。",
  节点状态:
    "维护中会停止平台对该节点发起新的项目级操作；恢复服务后重新设为启用并执行连接检查。",
  端口池:
    "该节点为端口转发自动分配公网端口的范围，不同节点的端口池应避免冲突。",
  作用项目: "策略只对所选客户项目生效；未被策略覆盖的项目默认拒绝访问。",
  授权用户: "选择实际平台用户；策略不会按显示名称隐式扩展到其他账号。",
  授权能力:
    "V1 访问策略用于临时用户，只支持授权 Web 和 WebSSH；管理能力由角色与项目成员范围决定。",
  有效时间:
    "限制授权生效的时间窗口；过期后新会话会被拒绝，活动会话按平台策略终止。",
  授权项目: "用户能够查看和访问的客户项目范围，系统管理员权限除外。",
  角色: "角色决定平台级权限基线，用户仍需获得具体客户项目授权后才能访问对应资源。",
  "新密码（选填）":
    "仅在管理员需要重置该用户密码时填写，至少 12 位；留空会保留现有密码哈希。",
};

const FIELD_OPTIONS: Record<string, string[]> = {
  授权能力: ["Web", "WebSSH"],
  有效时间: ["永久有效", "24 小时", "7 天"],
  角色: ["系统管理员", "项目管理员", "运维用户", "临时用户"],
  节点状态: ["启用", "维护中"],
};

const MULTI_CHOICE_FIELDS = new Set([
  "授权用户",
  "授权能力",
  "授权项目",
  "作用项目",
]);
const OPTIONAL_RESOURCE_FIELDS = new Set([
  "TLS 校验主机名",
  "新密码（选填）",
  "认证账号",
  "认证密码",
]);

function HelpTip({ text }: { text: string }) {
  return (
    <span
      className="help-tip"
      tabIndex={0}
      aria-label={`说明：${text}`}
      onMouseDown={(event) => {
        event.preventDefault();
        event.stopPropagation();
        event.currentTarget.focus();
      }}
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        event.currentTarget.focus();
      }}
    >
      ?<span role="tooltip">{text}</span>
    </span>
  );
}

function EmptyState({
  title,
  detail,
  onClear,
}: {
  title: string;
  detail: string;
  onClear?: () => void;
}) {
  return (
    <div className="empty-state">
      <span>⌕</span>
      <h3>{title}</h3>
      <p>{detail}</p>
      {onClear && (
        <button className="btn secondary" onClick={onClear}>
          清除筛选
        </button>
      )}
    </div>
  );
}

function ConfirmButton({
  label,
  confirmLabel,
  className = "",
  disabled = false,
  onConfirm,
}: {
  label: string;
  confirmLabel: string;
  className?: string;
  disabled?: boolean;
  onConfirm: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  useEffect(() => {
    if (!confirming) return;
    const timer = window.setTimeout(() => setConfirming(false), 4000);
    return () => window.clearTimeout(timer);
  }, [confirming]);
  return (
    <button
      type="button"
      className={`${className} ${confirming ? "confirming" : ""}`.trim()}
      disabled={disabled}
      onClick={() => {
        if (!confirming) {
          setConfirming(true);
          return;
        }
        setConfirming(false);
        onConfirm();
      }}
    >
      {confirming ? confirmLabel : label}
    </button>
  );
}

function Metric({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string;
  detail: string;
  tone: string;
}) {
  return (
    <div className="metric-card">
      <div className={`metric-icon metric-${tone}`}>
        {tone === "green"
          ? "●"
          : tone === "blue"
            ? "↗"
            : tone === "violet"
              ? "⌘"
              : "◫"}
      </div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        <small>{detail}</small>
      </div>
    </div>
  );
}

function PaginationFooter({
  total,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  noun = "条记录",
}: {
  total: number;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
  noun?: string;
}) {
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(page, pageCount);
  const start = total ? (safePage - 1) * pageSize + 1 : 0;
  const end = Math.min(safePage * pageSize, total);
  const firstPage = Math.max(1, Math.min(safePage - 2, pageCount - 4));
  const pages = Array.from(
    { length: Math.min(5, pageCount) },
    (_, index) => firstPage + index,
  );
  return (
    <div className="table-footer pagination-footer">
      <div className="pagination-summary">
        <span>
          显示第 {start} 到第 {end} {noun}，总共 {total} {noun}
        </span>
        <label>
          每页显示
          <select
            aria-label="每页显示条数"
            value={pageSize}
            onChange={(event) => {
              onPageSizeChange(Number(event.target.value));
              onPageChange(1);
            }}
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
          </select>
          {noun}
        </label>
      </div>
      <div className="pagination-buttons">
        <button
          type="button"
          aria-label="上一页"
          disabled={safePage <= 1}
          onClick={() => onPageChange(safePage - 1)}
        >
          ‹
        </button>
        {pages.map((item) => (
          <button
            type="button"
            key={item}
            className={item === safePage ? "current" : ""}
            aria-current={item === safePage ? "page" : undefined}
            onClick={() => onPageChange(item)}
          >
            {item}
          </button>
        ))}
        <button
          type="button"
          aria-label="下一页"
          disabled={safePage >= pageCount}
          onClick={() => onPageChange(safePage + 1)}
        >
          ›
        </button>
      </div>
    </div>
  );
}

function PlatformSplash({ message }: { message: string }) {
  return (
    <div className="platform-gate">
      <div className="platform-gate-card">
        <div className="platform-gate-logo">I5</div>
        <h1>I5CLOUD</h1>
        <p>{message}</p>
        <div className="platform-loader">
          <i />
        </div>
      </div>
    </div>
  );
}

function PlatformError({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div className="platform-gate">
      <div className="platform-gate-card">
        <div className="platform-gate-logo error">!</div>
        <h1>平台服务暂不可用</h1>
        <p>{message}</p>
        <button className="btn primary" onClick={onRetry}>
          重新连接
        </button>
      </div>
    </div>
  );
}

function LoginScreen({
  onAuthenticated,
}: {
  onAuthenticated: (user: APIUser) => Promise<void>;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<APISetupStatus | null>(null);
  const [challenge, setChallenge] = useState<APILoginChallenge | null>(null);
  const [step, setStep] = useState<
    "credentials" | "password" | "email" | "mfa" | "verify" | "recovery"
  >("credentials");
  const [email, setEmail] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [maskedEmail, setMaskedEmail] = useState("");
  const [mfaStart, setMFAStart] = useState<APIMFAStart | null>(null);
  const [resendSeconds, setResendSeconds] = useState(0);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [completedUser, setCompletedUser] = useState<APIUser | null>(null);

  useEffect(() => {
    api
      .setupStatus()
      .then(setStatus)
      .catch((setupError) =>
        setError(
          setupError instanceof Error
            ? setupError.message
            : "无法读取初始化状态",
        ),
      );
  }, []);
  useEffect(() => {
    if (resendSeconds <= 0) return;
    const timer = window.setInterval(
      () => setResendSeconds((seconds) => Math.max(0, seconds - 1)),
      1000,
    );
    return () => window.clearInterval(timer);
  }, [resendSeconds]);

  const fail = (cause: unknown, fallback: string) => {
    setError(cause instanceof Error ? cause.message : fallback);
    setSubmitting(false);
  };
  const beginChallenge = async (result: APIAuthSession | APILoginChallenge) => {
    if ("user" in result) {
      await onAuthenticated(result.user);
      return;
    }
    setChallenge(result);
    if (result.next === "onboard") setStep("password");
    else {
      setStep("verify");
      if (result.preferredMethod === "email") {
        const started = await api.startMFA(result.challengeToken, "email");
        setMFAStart(started);
        setMaskedEmail(started.maskedEmail || "已绑定邮箱");
        setResendSeconds(started.resendAfterSeconds || 60);
      }
    }
    setSubmitting(false);
  };
  const resendMFAEmail = async () => {
    if (!challenge || resendSeconds > 0) return;
    setSubmitting(true);
    setError("");
    try {
      const started = await api.startMFA(challenge.challengeToken, "email");
      setMFAStart(started);
      setMaskedEmail(started.maskedEmail || "已绑定邮箱");
      setResendSeconds(started.resendAfterSeconds || 60);
      setSubmitting(false);
    } catch (cause) {
      fail(cause, "验证码重新发送失败");
    }
  };
  const complete = async (code: string) => {
    if (!challenge) return;
    const result = await api.completeMFA(challenge.challengeToken, code);
    if (result.recoveryCodes?.length) {
      setRecoveryCodes(result.recoveryCodes);
      setCompletedUser(result.user);
      setStep("recovery");
      setSubmitting(false);
    } else await onAuthenticated(result.user);
  };

  let content: React.ReactNode;
  if (step === "credentials")
    content = (
      <form
        key="credentials"
        className="login-card"
        onSubmit={async (event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setSubmitting(true);
          setError("");
          try {
            const username = String(form.get("username") || "");
            const password = String(form.get("password") || "");
            if (status?.initialized === false)
              await api.setup(
                username,
                String(form.get("displayName") || ""),
                password,
                String(form.get("setupToken") || ""),
              );
            await beginChallenge(await api.login(username, password));
          } catch (cause) {
            fail(cause, "登录失败");
          }
        }}
      >
        <LoginBrand
          subtitle={
            status?.initialized === false
              ? "创建首位系统管理员"
              : "远程管理平台"
          }
        />
        {status?.initialized === false && (
          <>
            <label>
              显示名称
              <input
                name="displayName"
                autoComplete="name"
                required
                placeholder="例如：系统管理员"
              />
            </label>
            <label>
              初始化令牌
              <input
                name="setupToken"
                type="password"
                autoComplete="off"
                required
                placeholder="由部署管理员提供的一次性令牌"
              />
            </label>
          </>
        )}
        <label>
          登录账号
          <input name="username" autoComplete="username" required autoFocus />
        </label>
        <label>
          {status?.initialized === false
            ? "初始管理员密码（至少 12 位）"
            : "登录密码"}
          <input
            name="password"
            type="password"
            minLength={status?.initialized === false ? 12 : undefined}
            autoComplete={
              status?.initialized === false
                ? "new-password"
                : "current-password"
            }
            required
          />
        </label>
        {status?.initialized === false && (
          <div className="security-note">
            首次登录后还需修改初始密码、验证邮箱并绑定双重认证。
          </div>
        )}
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <button
          className="btn primary"
          disabled={submitting || status === null}
        >
          {submitting
            ? "正在提交…"
            : status?.initialized === false
              ? "初始化并继续"
              : status === null
                ? "正在检查…"
                : "登录平台"}
        </button>
      </form>
    );
  else if (step === "password")
    content = (
      <form
        key="password"
        className="login-card onboarding-card"
        onSubmit={async (event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          const password = String(form.get("newPassword") || "");
          const confirm = String(form.get("confirmPassword") || "");
          setError("");
          if (password !== confirm) {
            setError("两次输入的新密码不一致");
            return;
          }
          setSubmitting(true);
          try {
            await api.setOnboardingPassword(
              challenge!.challengeToken,
              password,
            );
            setStep("email");
            setSubmitting(false);
          } catch (cause) {
            fail(cause, "密码修改失败");
          }
        }}
      >
        <LoginBrand subtitle="首次登录安全设置" />
        <OnboardingSteps active={1} />
        <div className="onboarding-title">
          <h2>修改初始密码</h2>
          <p>新密码不能与管理员分配的初始密码相同。</p>
        </div>
        <label>
          新密码
          <input
            name="newPassword"
            type="password"
            minLength={12}
            autoComplete="new-password"
            required
            autoFocus
          />
        </label>
        <label>
          确认新密码
          <input
            name="confirmPassword"
            type="password"
            minLength={12}
            autoComplete="new-password"
            required
          />
        </label>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <button className="btn primary" disabled={submitting}>
          {submitting ? "正在保存…" : "保存并继续"}
        </button>
      </form>
    );
  else if (step === "email")
    content = (
      <form
        key="email"
        className="login-card onboarding-card"
        onSubmit={async (event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setSubmitting(true);
          setError("");
          try {
            await api.verifyOnboardingEmail(
              challenge!.challengeToken,
              String(form.get("emailCode") || ""),
            );
            setStep("mfa");
            setEmailSent(false);
            setSubmitting(false);
          } catch (cause) {
            fail(cause, "邮箱验证失败");
          }
        }}
      >
        <LoginBrand subtitle="首次登录安全设置" />
        <OnboardingSteps active={2} />
        <div className="onboarding-title">
          <h2>绑定并验证邮箱</h2>
          <p>邮箱用于身份确认，也可作为双重认证方式。</p>
        </div>
        <div className="login-field">
          <label htmlFor="onboarding-email">邮箱地址</label>
          <div className="inline-input-action">
            <input
              id="onboarding-email"
              aria-label="邮箱地址"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              required
              disabled={emailSent}
              placeholder="name@example.com"
            />
            <button
              type="button"
              className="btn secondary"
              disabled={submitting || !email || resendSeconds > 0}
              onClick={async () => {
                setSubmitting(true);
                setError("");
                try {
                  const result = await api.sendOnboardingEmail(
                    challenge!.challengeToken,
                    email,
                  );
                  setMaskedEmail(result.maskedEmail);
                  setEmailSent(true);
                  setResendSeconds(result.resendAfterSeconds || 60);
                  setSubmitting(false);
                } catch (cause) {
                  fail(cause, "验证码发送失败");
                }
              }}
            >
              {resendSeconds > 0
                ? `${resendSeconds} 秒后${emailSent ? "重发" : "可发送"}`
                : emailSent
                  ? "重新发送"
                  : "发送验证码"}
            </button>
          </div>
        </div>
        {emailSent && (
          <>
            <div className="security-note" aria-live="polite">
              验证码已发送至 {maskedEmail}，
              {resendSeconds > 0
                ? `${resendSeconds} 秒后可重新发送`
                : "现在可以重新发送"}
              。
            </div>
            <label>
              邮箱验证码
              <input
                name="emailCode"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                required
                autoFocus
                placeholder="6 位验证码"
              />
            </label>
          </>
        )}
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        {emailSent && (
          <div className="login-actions">
            <button
              type="button"
              className="btn secondary"
              onClick={() => setEmailSent(false)}
            >
              更换邮箱
            </button>
            <button className="btn primary" disabled={submitting}>
              {submitting ? "正在验证…" : "验证并继续"}
            </button>
          </div>
        )}
      </form>
    );
  else if (step === "mfa" && !mfaStart)
    content = (
      <div className="login-card onboarding-card">
        <LoginBrand subtitle="首次登录安全设置" />
        <OnboardingSteps active={3} />
        <div className="onboarding-title">
          <h2>开启双重认证</h2>
          <p>请选择一种日常登录验证方式。绑定完成前不能进入平台。</p>
        </div>
        <div className="mfa-method-grid">
          {challenge?.methods.map((method) => (
            <button
              key={method}
              type="button"
              onClick={async () => {
                setSubmitting(true);
                setError("");
                try {
                  const result = await api.startMFA(
                    challenge.challengeToken,
                    method,
                  );
                  setMFAStart(result);
                  setMaskedEmail(result.maskedEmail || "");
                  setResendSeconds(
                    method === "email" ? result.resendAfterSeconds || 60 : 0,
                  );
                  setSubmitting(false);
                } catch (cause) {
                  fail(cause, "双重认证启动失败");
                }
              }}
            >
              <b>{method === "totp" ? "认证器令牌" : "邮箱验证码"}</b>
              <span>
                {method === "totp"
                  ? "使用身份验证器扫描二维码，离线也可生成验证码"
                  : "每次登录向已验证邮箱发送一次性验证码"}
              </span>
              <em>{method === "totp" ? "推荐" : "可选"} →</em>
            </button>
          ))}
        </div>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        {submitting && <div className="security-note">正在准备验证方式…</div>}
      </div>
    );
  // TOTP 二维码是后端生成的短期 data URL，不适合交给 Next 图片优化器持久化或代理。
  else if (step === "mfa")
    content = (
      <form
        className="login-card onboarding-card mfa-enrollment"
        onSubmit={async (event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setSubmitting(true);
          setError("");
          try {
            await complete(String(form.get("mfaCode") || ""));
          } catch (cause) {
            fail(cause, "双重认证绑定失败");
          }
        }}
      >
        <LoginBrand subtitle="首次登录安全设置" />
        <OnboardingSteps active={3} />
        <div className="onboarding-title">
          <h2>{mfaStart?.method === "totp" ? "绑定认证器" : "验证登录邮箱"}</h2>
          <p>
            {mfaStart?.method === "totp"
              ? "扫描二维码后输入认证器生成的 6 位动态码。"
              : `验证码已发送至 ${maskedEmail}。`}
          </p>
        </div>
        {mfaStart?.enrollment && (
          <div className="totp-enrollment">
            <img src={mfaStart.enrollment.qrCodeDataUrl} alt="双重认证二维码" />
            <div>
              <span>无法扫码时输入密钥</span>
              <code>{mfaStart.enrollment.manualKey}</code>
            </div>
          </div>
        )}
        <label>
          6 位验证码
          <input
            name="mfaCode"
            inputMode="numeric"
            pattern="[0-9]{6}"
            maxLength={6}
            required
            autoFocus
          />
        </label>
        {mfaStart?.method === "email" && (
          <button
            type="button"
            className="btn secondary resend-code"
            disabled={submitting || resendSeconds > 0}
            onClick={() => void resendMFAEmail()}
          >
            {resendSeconds > 0
              ? `${resendSeconds} 秒后可重新发送`
              : "重新发送验证码"}
          </button>
        )}
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="login-actions">
          <button
            type="button"
            className="btn secondary"
            onClick={() => {
              setMFAStart(null);
              setResendSeconds(0);
              setError("");
            }}
          >
            返回选择
          </button>
          <button className="btn primary" disabled={submitting}>
            {submitting ? "正在启用…" : "启用并完成"}
          </button>
        </div>
      </form>
    );
  else if (step === "verify")
    content = (
      <form
        className="login-card onboarding-card"
        onSubmit={async (event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setSubmitting(true);
          setError("");
          try {
            await complete(String(form.get("mfaCode") || ""));
          } catch (cause) {
            fail(cause, "双重认证失败");
          }
        }}
      >
        <LoginBrand subtitle="双重认证" />
        <div className="onboarding-title">
          <h2>
            {challenge?.preferredMethod === "email"
              ? "检查登录邮箱"
              : "输入动态验证码"}
          </h2>
          <p>
            {challenge?.preferredMethod === "email"
              ? `登录验证码已发送至 ${maskedEmail}。`
              : "输入认证器生成的 6 位动态码，也可以使用一枚恢复码。"}
          </p>
        </div>
        <label>
          验证码或恢复码
          <input
            name="mfaCode"
            autoComplete="one-time-code"
            required
            autoFocus
            placeholder="6 位验证码或 XXXX-XXXX-XXXX"
          />
        </label>
        {challenge?.preferredMethod === "email" && (
          <button
            type="button"
            className="btn secondary resend-code"
            disabled={submitting || resendSeconds > 0}
            onClick={() => void resendMFAEmail()}
          >
            {resendSeconds > 0
              ? `${resendSeconds} 秒后可重新发送`
              : "重新发送验证码"}
          </button>
        )}
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <button className="btn primary" disabled={submitting}>
          {submitting ? "正在验证…" : "验证并登录"}
        </button>
      </form>
    );
  else
    content = (
      <div className="login-card onboarding-card recovery-card">
        <LoginBrand subtitle="安全设置完成" />
        <div className="onboarding-title">
          <h2>保存恢复码</h2>
          <p>
            每枚恢复码只能使用一次。请离线保存，离开此页后平台不会再次显示。
          </p>
        </div>
        <div className="recovery-codes">
          {recoveryCodes.map((code) => (
            <code key={code}>{code}</code>
          ))}
        </div>
        <button
          type="button"
          className="btn secondary"
          onClick={() =>
            void navigator.clipboard.writeText(recoveryCodes.join("\n"))
          }
        >
          复制全部恢复码
        </button>
        <button
          type="button"
          className="btn primary"
          onClick={() => completedUser && void onAuthenticated(completedUser)}
        >
          我已安全保存，进入平台
        </button>
      </div>
    );
  return (
    <div className="platform-gate">
      <div
        key={`${step}-${mfaStart?.method || "none"}`}
        className="login-stage"
      >
        {content}
      </div>
    </div>
  );
}

function LoginBrand({ subtitle }: { subtitle: string }) {
  return (
    <>
      <div className="platform-gate-logo">I5</div>
      <div className="login-brand-copy">
        <h1>I5CLOUD</h1>
        <p>{subtitle}</p>
      </div>
    </>
  );
}

function OnboardingSteps({ active }: { active: 1 | 2 | 3 }) {
  return (
    <ol className="onboarding-steps">
      <li className={active >= 1 ? "active" : ""}>
        <b>1</b>
        <span>修改密码</span>
      </li>
      <li className={active >= 2 ? "active" : ""}>
        <b>2</b>
        <span>绑定邮箱</span>
      </li>
      <li className={active >= 3 ? "active" : ""}>
        <b>3</b>
        <span>双重认证</span>
      </li>
    </ol>
  );
}

export default function Home() {
  const [view, setView] = useState<View>("overview");
  const [modal, setModal] = useState<Modal>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [nodeItems, setNodeItems] = useState<NodeView[]>([]);
  const [projectItems, setProjectItems] = useState<ProjectView[]>([]);
  const [currentUser, setCurrentUser] = useState<APIUser | null>(null);
  const [userItems, setUserItems] = useState<APIUser[]>([]);
  const [policyItems, setPolicyItems] = useState<APIAccessPolicy[]>([]);
  const [sessionItems, setSessionItems] = useState<APIAccessSession[]>([]);
  const [auditItems, setAuditItems] = useState<APIAuditLog[]>([]);
  const [forwardItems, setForwardItems] = useState<APIPortForward[]>([]);
  const [platformState, setPlatformState] = useState<
    "checking" | "login" | "loading" | "ready" | "error"
  >("checking");
  const [platformError, setPlatformError] = useState("");
  const [activeProject, setActiveProject] =
    useState<ProjectView>(EMPTY_PROJECT);
  const [activeDevice, setActiveDevice] = useState<Device>({
    id: "",
    projectCode: "",
    name: "",
    host: "",
    type: "",
    vendor: "",
    status: "offline",
    web: null,
    webServices: [],
    ssh: false,
    sshPort: null,
    services: 0,
    lastSeen: "—",
  });
  const [socksStatus, setSocksStatus] = useState<Record<string, boolean>>({});
  const [managedTunnels, setManagedTunnels] = useState<NodeManagedTunnel[]>([]);
  const [query, setQuery] = useState("");
  const [scanActive, setScanActive] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [imported, setImported] = useState<number[]>([]);
  const [discoveryCandidates, setDiscoveryCandidates] = useState<
    Record<string, DiscoveryResult[]>
  >({});
  const [ignoredDiscovery, setIgnoredDiscovery] = useState<
    Record<string, number[]>
  >({});
  const [toast, setToast] = useState("");
  const [activeResourceName, setActiveResourceName] = useState("");
  const [navigationReady, setNavigationReady] = useState(false);
  const [securitySettings, setSecuritySettings] =
    useState<APISecuritySettings | null>(null);
  const [monitorSnapshot, setMonitorSnapshot] =
    useState<APIMonitorSnapshot | null>(null);
  const [monitorLoading, setMonitorLoading] = useState(false);

  const loadPlatform = async (user: APIUser) => {
    setPlatformState("loading");
    setPlatformError("");
    try {
      const [backendNodes, backendProjects] = await Promise.all([
        api.nodes(),
        api.projects(),
      ]);
      const tunnelGroups = await Promise.all(
        backendNodes.map(async (node) => {
          try {
            const [items, clients] = await Promise.all([
              api.managedTunnels(node.id),
              api.nodeClients(node.id),
            ]);
            return { nodeId: node.id, items, clients, available: true };
          } catch {
            return {
              nodeId: node.id,
              items: [],
              clients: [],
              available: false,
            };
          }
        }),
      );
      const mappedProjects = backendProjects.map((project) =>
        mapProject(project, backendNodes),
      );
      for (const project of mappedProjects) {
        const group = tunnelGroups.find(
          (item) => item.nodeId === project.nodeId,
        );
        const client = group?.clients.find(
          (item) => item.id === project.clientId,
        );
        if (group?.available)
          project.clientStatus = client?.connected ? "在线" : "离线";
      }
      const mappedNodes = backendNodes.map((node) =>
        mapNode(node, backendProjects),
      );
      for (const node of mappedNodes) {
        const group = tunnelGroups.find((item) => item.nodeId === node.id);
        node.clients = group?.clients.length || 0;
        node.tunnels = group?.items.length || 0;
        node.runningTunnels =
          group?.items.filter((item) => item.running).length || 0;
      }
      const deviceGroups = await Promise.all(
        backendProjects.map(async (project) => {
          const projectView = mappedProjects.find(
            (item) => item.id === project.id,
          );
          if (!projectView) return [];
          return (await api.devices(project.id)).map((device) =>
            mapDevice(device, projectView),
          );
        }),
      );
      const mappedDevices = deviceGroups.flat();
      const [
        backendUsers,
        backendPolicies,
        backendSessions,
        backendAudits,
        forwardGroups,
        backendSecurity,
      ] = await Promise.all([
        api.users().catch(() => []),
        api.policies().catch(() => []),
        api.sessions().catch(() => []),
        api.auditLogs().catch(() => []),
        Promise.all(
          backendProjects.map((project) =>
            api.portForwards(project.id).catch(() => []),
          ),
        ),
        user.role === "system_admin"
          ? api.securitySettings().catch(() => null)
          : Promise.resolve(null),
      ]);
      for (const project of mappedProjects) {
        const projectDevices = mappedDevices.filter(
          (device) => device.projectCode === project.code,
        );
        project.devices = projectDevices.length;
        project.web = projectDevices.reduce(
          (total, device) => total + device.webServices.length,
          0,
        );
      }
      setCurrentUser(user);
      if (user.role === "temporary") setView("portal");
      setNodeItems(mappedNodes);
      setProjectItems(mappedProjects);
      setDevices(mappedDevices);
      setUserItems(backendUsers);
      setPolicyItems(backendPolicies);
      setSessionItems(backendSessions);
      setAuditItems(backendAudits);
      setForwardItems(forwardGroups.flat());
      setSecuritySettings(backendSecurity);
      setSocksStatus(
        Object.fromEntries(
          mappedProjects.map((project) => {
            const group = tunnelGroups.find(
              (item) => item.nodeId === project.nodeId,
            );
            const tunnel = group?.items.find(
              (item) => item.clientId === project.clientId,
            );
            return [
              project.code,
              group?.available ? Boolean(tunnel?.running) : false,
            ];
          }),
        ),
      );
      setManagedTunnels(
        tunnelGroups.flatMap((group) =>
          group.items.map((tunnel) => ({
            ...tunnel,
            nodeId: group.nodeId,
            nodeName:
              mappedNodes.find((node) => node.id === group.nodeId)?.name ||
              group.nodeId,
          })),
        ),
      );
      const requestedProject = new URLSearchParams(window.location.search).get(
        "project",
      );
      setActiveProject(
        mappedProjects.find((project) => project.code === requestedProject) ||
          mappedProjects[0] ||
          EMPTY_PROJECT,
      );
      if (mappedDevices.length) setActiveDevice(mappedDevices[0]);
      setPlatformState("ready");
    } catch (error) {
      if (error instanceof APIError && error.status === 401) {
        setPlatformState("login");
        return;
      }
      setPlatformError(
        error instanceof Error ? error.message : "平台数据加载失败",
      );
      setPlatformState("error");
    }
  };

  useEffect(() => {
    let cancelled = false;
    api
      .me()
      .then((user) => {
        if (!cancelled) void loadPlatform(user);
      })
      .catch((error) => {
        if (cancelled) return;
        if (error instanceof APIError && error.status === 401)
          setPlatformState("login");
        else {
          setPlatformError(
            error instanceof Error ? error.message : "无法连接平台服务",
          );
          setPlatformState("error");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!scanActive || !scanJobId) return;
    let stopped = false;
    const poll = async () => {
      try {
        const result = await api.discoveryJob(scanJobId);
        if (stopped) return;
        setScanProgress(result.job.progress);
        setDiscoveryCandidates((items) => ({
          ...items,
          [activeProject.code]: groupDiscoveryResults(result.results),
        }));
        if (["completed", "failed", "canceled"].includes(result.job.status)) {
          setScanActive(false);
          if (result.job.status === "completed") {
            const grouped = groupDiscoveryResults(result.results);
            setToast(
              `扫描完成，发现 ${grouped.length} 台设备、${result.results.length} 个待确认服务`,
            );
          } else if (result.job.status === "failed")
            setToast("扫描任务失败，请检查项目通道与扫描网段");
        }
      } catch (error) {
        if (!stopped) {
          setScanActive(false);
          setToast(error instanceof Error ? error.message : "读取扫描进度失败");
        }
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 1000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [activeProject.code, scanActive, scanJobId]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 2800);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    if (
      view !== "monitor" ||
      platformState !== "ready" ||
      currentUser?.role !== "system_admin"
    )
      return;
    let cancelled = false;
    const loadingTimer = window.setTimeout(() => {
      if (!cancelled) setMonitorLoading(true);
    }, 0);
    api
      .monitorSnapshot()
      .then((snapshot) => {
        if (!cancelled) setMonitorSnapshot(snapshot);
      })
      .catch((error) => {
        if (!cancelled)
          setToast(error instanceof Error ? error.message : "运行快照读取失败");
      })
      .finally(() => {
        if (!cancelled) setMonitorLoading(false);
      });
    return () => {
      cancelled = true;
      window.clearTimeout(loadingTimer);
    };
  }, [currentUser?.role, platformState, view]);

  const refreshMonitor = async () => {
    setMonitorLoading(true);
    try {
      const snapshot = await api.monitorSnapshot();
      setMonitorSnapshot(snapshot);
      setToast("运行快照已刷新");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "运行快照读取失败");
    } finally {
      setMonitorLoading(false);
    }
  };

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requestedView = params.get("view");
    window.queueMicrotask(() => {
      if (requestedView && VALID_VIEWS.has(requestedView as View))
        setView(requestedView as View);
      setNavigationReady(true);
    });
  }, []);

  useEffect(() => {
    if (!navigationReady || platformState !== "ready") return;
    const params = new URLSearchParams();
    if (view !== "overview") params.set("view", view);
    if (view === "workspace" || view === "discovery" || view === "connections")
      params.set("project", activeProject.code);
    const queryString = params.toString();
    window.history.replaceState(
      {},
      "",
      `${window.location.pathname}${queryString ? `?${queryString}` : ""}`,
    );
  }, [activeProject.code, navigationReady, platformState, view]);

  const projectDevices = useMemo(
    () => devices.filter((device) => device.projectCode === activeProject.code),
    [devices, activeProject.code],
  );

  const markProjectTunnelOpen = (project: ProjectView) => {
    setManagedTunnels((items) =>
      items.map((item) =>
        item.nodeId === project.nodeId && item.clientId === project.clientId
          ? { ...item, configured: true, running: true }
          : item,
      ),
    );
    setSocksStatus((items) => ({ ...items, [project.code]: true }));
  };

  const openWeb = async (device: Device, webUrl?: string) => {
    const project = projectItems.find(
      (item) => item.code === device.projectCode,
    );
    if (!project) {
      setToast("设备所属项目不存在，无法建立 Web 访问会话");
      return;
    }
    const targetUrl = webUrl || device.web || device.webServices[0]?.url || "";
    const endpoint =
      device.webServices.find((service) => service.url === targetUrl) ||
      device.webServices[0];
    if (!endpoint?.endpointId) {
      setToast("该 Web 服务尚未写入后台 Endpoint");
      return;
    }
    const opened = window.open("about:blank", "_blank");
    if (!opened) {
      setToast("浏览器阻止了新标签页，请允许本站弹出窗口后重试");
      return;
    }
    opened.opener = null;
    try {
      const session = await api.createAccessSession(endpoint.endpointId, "web");
      markProjectTunnelOpen(project);
      opened.location.replace(session.launchUrl);
    } catch (error) {
      opened.close();
      setToast(error instanceof Error ? error.message : "Web 访问会话创建失败");
    }
  };

  const openSsh = async (device: Device) => {
    const project = projectItems.find(
      (item) => item.code === device.projectCode,
    );
    if (!project) {
      setToast("设备所属项目不存在，无法建立 WebSSH 会话");
      return;
    }
    if (!device.sshEndpointId) {
      setToast("该 SSH 服务尚未写入后台 Endpoint");
      return;
    }
    const opened = window.open("about:blank", "_blank");
    if (!opened) {
      setToast("浏览器阻止了新标签页，请允许本站弹出窗口后重试");
      return;
    }
    opened.opener = null;
    try {
      const session = await api.createAccessSession(
        device.sshEndpointId,
        "ssh",
      );
      markProjectTunnelOpen(project);
      opened.location.replace(session.launchUrl);
    } catch (error) {
      opened.close();
      setToast(error instanceof Error ? error.message : "WebSSH 会话创建失败");
    }
  };

  const addDevice = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const name = String(form.get("name") || "新设备");
    const host = String(form.get("host") || "192.168.10.99");
    if (
      devices.some(
        (device) =>
          device.projectCode === activeProject.code && device.host === host,
      )
    ) {
      setToast(`项目中已存在目标 ${host}，请编辑现有设备并添加服务入口`);
      return;
    }
    const webNames = form.getAll("webServiceName").map(String);
    const webProtocols = form.getAll("webProtocol").map(String);
    const webPorts = form.getAll("webPort").map(Number);
    const webTlsServerNames = form
      .getAll("webTlsServerName")
      .map((value) => String(value).trim());
    const webAllowInsecureTls = form
      .getAll("webAllowInsecureTls")
      .map((value) => value === "true");
    const webServices = webPorts
      .filter((port) => port > 0)
      .map((port, index) => ({
        name: webNames[index] || `Web 服务 ${index + 1}`,
        url: `${webProtocols[index] || "http"}://${host}:${port}`,
        tlsServerName: webTlsServerNames[index] || "",
        allowInsecureTls: webAllowInsecureTls[index] || false,
      }));
    const ssh = Boolean(form.get("ssh"));
    const sshPort = ssh ? Number(form.get("sshPort") || 22) : null;
    const sshAuthMethod = String(form.get("sshAuthMethod") || "password") as
      "password" | "key";
    const sshUsername = String(form.get("sshUsername") || "").trim();
    const sshPassword = String(form.get("sshPassword") || "");
    const sshKeyPath = String(form.get("sshKeyPath") || "").trim();
    const sshHostKeyFingerprint = String(
      form.get("sshHostKeyFingerprint") || "",
    ).trim();
    if (
      ssh &&
      (!sshUsername ||
        (sshAuthMethod === "password" ? !sshPassword : !sshKeyPath))
    ) {
      setToast(
        sshAuthMethod === "password"
          ? "请填写 SSH 用户名和密码"
          : "请填写 SSH 用户名和私钥文件路径",
      );
      return;
    }
    const otherNames = form.getAll("otherServiceName").map(String);
    const otherProtocols = form
      .getAll("otherProtocol")
      .map((value) => String(value) as ServiceProtocol);
    const otherPorts = form.getAll("otherPort").map(Number);
    const otherServices = otherPorts
      .filter((port) => port > 0)
      .map((port, index) => ({
        name: otherNames[index] || `其他服务 ${index + 1}`,
        protocol: otherProtocols[index] || "tcp",
        port,
      }));
    const serviceEndpoints: DeviceServiceEndpoint[] = [
      ...webServices.map((service) => {
        const url = new URL(service.url);
        return {
          name: service.name,
          protocol: url.protocol.replace(":", "") as ServiceProtocol,
          port: Number(url.port || (url.protocol === "https:" ? 443 : 80)),
          tlsServerName: service.tlsServerName,
          allowInsecureTls: service.allowInsecureTls,
        };
      }),
      ...(ssh && sshPort
        ? [
            {
              name: "WebSSH",
              protocol: "ssh" as const,
              port: sshPort,
              sshHostKeyFingerprint,
              sshCredential: {
                method: sshAuthMethod,
                username: sshUsername,
                password:
                  sshAuthMethod === "password" ? sshPassword : undefined,
                keyPath: sshAuthMethod === "key" ? sshKeyPath : undefined,
              },
            },
          ]
        : []),
      ...otherServices,
    ];
    if (!activeProject.id) {
      setToast("项目尚未写入后台，无法添加设备");
      return;
    }
    try {
      const created = await api.createDevice(activeProject.id, {
        host,
        name,
        deviceType: String(form.get("type") || "其他设备"),
        vendor: String(form.get("vendor") || ""),
        source: "manual",
        endpoints: serviceEndpoints.map((service) => ({
          name: service.name,
          protocol: service.protocol,
          targetPort: service.port,
          tlsServerName: service.tlsServerName || "",
          allowInsecureTls: Boolean(service.allowInsecureTls),
          sshCredential: service.sshCredential,
          sshHostKeyFingerprint: service.sshHostKeyFingerprint || "",
        })),
      });
      const next = mapDevice(created, activeProject);
      setDevices((items) => [next, ...items]);
      setProjectItems((items) =>
        items.map((project) =>
          project.code === activeProject.code
            ? {
                ...project,
                devices: project.devices + 1,
                web: project.web + webServices.length,
              }
            : project,
        ),
      );
      setModal(null);
      setToast(`已添加设备：${name}`);
    } catch (error) {
      setToast(error instanceof Error ? error.message : "添加设备失败");
    }
  };

  const submitResource = async (
    kind: ConfigModalKind,
    label: string,
    values: Record<string, string | string[]>,
  ) => {
    if (!currentUser) throw new Error("登录会话已失效，请重新登录");
    if (kind === "create-node") {
      const portParts = String(values["端口池"] || "")
        .split(/[-–—]/)
        .map(Number);
      const credentialUsername = String(values["认证账号"] || "");
      const credentialPassword = String(values["认证密码"] || "");
      await api.createNode({
        name: values["节点名称"],
        apiUrl: values["API 地址"],
        tlsServerName: values["TLS 校验主机名"],
        credential: {
          type: "session",
          username: credentialUsername,
          password: credentialPassword,
        },
        portStart: portParts[0],
        portEnd: portParts[1],
      });
    } else if (kind === "create-user") {
      const role =
        {
          系统管理员: "system_admin",
          项目管理员: "project_admin",
          运维用户: "operator",
          临时用户: "temporary",
        }[String(values["角色"])] || "operator";
      const selectedProjects = Array.isArray(values["授权项目"])
        ? values["授权项目"]
        : [];
      const projectIds = selectedProjects.includes("全部项目")
        ? projectItems
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id))
        : projectItems
            .filter((project) => selectedProjects.includes(project.name))
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id));
      await api.createUser({
        username: values["登录账号"],
        displayName: values["姓名"],
        password: values["初始密码"],
        role,
        enabled: true,
        projectIds,
      });
    } else if (kind === "create-policy") {
      const selectedProjects = Array.isArray(values["作用项目"])
        ? values["作用项目"]
        : [];
      const selectedUsers = Array.isArray(values["授权用户"])
        ? values["授权用户"]
        : [];
      const selectedCapabilities = Array.isArray(values["授权能力"])
        ? values["授权能力"]
        : [];
      const projectIds = selectedProjects.includes("全部项目")
        ? projectItems
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id))
        : projectItems
            .filter((project) => selectedProjects.includes(project.name))
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id));
      const userIds = userItems
        .filter((user) => selectedUsers.includes(userChoiceLabel(user)))
        .map((user) => user.id);
      const capabilityMap: Record<string, string> = {
        Web: "web",
        WebSSH: "webssh",
      };
      const duration = String(values["有效时间"] || "永久有效");
      const validUntil =
        duration === "24 小时"
          ? new Date(Date.now() + 86400000).toISOString()
          : duration === "7 天"
            ? new Date(Date.now() + 7 * 86400000).toISOString()
            : null;
      await api.createPolicy({
        name: values["策略名称"],
        projectIds,
        userIds,
        capabilities: selectedCapabilities
          .map((item) => capabilityMap[item])
          .filter(Boolean),
        validFrom: null,
        validUntil,
        enabled: true,
      });
    } else if (kind === "edit-node") {
      const node = nodeItems.find((item) => item.name === activeResourceName);
      if (!node?.id || !node.raw) throw new Error("接入节点不存在");
      const portParts = String(values["端口池"] || "")
        .split(/[-–—]/)
        .map(Number);
      const credentialUsername = String(values["认证账号"] || "");
      const credentialPassword = String(values["认证密码"] || "");
      await api.updateNode(node.id, {
        name: values["节点名称"],
        apiUrl: values["API 地址"],
        tlsServerName: values["TLS 校验主机名"],
        credential:
          credentialUsername || credentialPassword
            ? {
                type: "session",
                username: credentialUsername,
                password: credentialPassword,
              }
            : undefined,
        portStart: portParts[0],
        portEnd: portParts[1],
        enabled: values["节点状态"] !== "维护中",
      });
    } else if (kind === "edit-user") {
      const user = userItems.find((item) => item.id === activeResourceName);
      if (!user) throw new Error("用户不存在");
      const role =
        {
          系统管理员: "system_admin",
          项目管理员: "project_admin",
          运维用户: "operator",
          临时用户: "temporary",
        }[String(values["角色"])] || user.role;
      const selectedProjects = Array.isArray(values["授权项目"])
        ? values["授权项目"]
        : [];
      const projectIds = selectedProjects.includes("全部项目")
        ? projectItems
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id))
        : projectItems
            .filter((project) => selectedProjects.includes(project.name))
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id));
      await api.updateUser(user.id, {
        displayName: values["姓名"],
        password: values["新密码（选填）"] || "",
        role,
        enabled: user.enabled !== false,
        projectIds,
      });
    } else if (kind === "edit-policy") {
      const policy = policyItems.find(
        (item) => item.name === activeResourceName,
      );
      if (!policy) throw new Error("访问策略不存在");
      const selectedProjects = Array.isArray(values["作用项目"])
        ? values["作用项目"]
        : [];
      const selectedUsers = Array.isArray(values["授权用户"])
        ? values["授权用户"]
        : [];
      const selectedCapabilities = Array.isArray(values["授权能力"])
        ? values["授权能力"]
        : [];
      const projectIds = selectedProjects.includes("全部项目")
        ? projectItems
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id))
        : projectItems
            .filter((project) => selectedProjects.includes(project.name))
            .map((project) => project.id)
            .filter((id): id is string => Boolean(id));
      const userIds = userItems
        .filter((user) => selectedUsers.includes(userChoiceLabel(user)))
        .map((user) => user.id);
      const capabilityMap: Record<string, string> = {
        Web: "web",
        WebSSH: "webssh",
      };
      const duration = String(values["有效时间"] || "保持现有有效期");
      const validUntil =
        duration === "保持现有有效期"
          ? policy.validUntil
          : duration === "24 小时"
            ? new Date(Date.now() + 86400000).toISOString()
            : duration === "7 天"
              ? new Date(Date.now() + 7 * 86400000).toISOString()
              : null;
      await api.updatePolicy(policy.id, {
        name: values["策略名称"],
        projectIds,
        userIds,
        capabilities: selectedCapabilities
          .map((item) => capabilityMap[item])
          .filter(Boolean),
        validFrom: duration === "保持现有有效期" ? policy.validFrom : null,
        validUntil,
        enabled: policy.enabled,
      });
    }
    setToast(`${label}已保存并写入后台`);
    await loadPlatform(currentUser);
    setModal(null);
  };

  const resourceInitialValues = (
    kind: ConfigModalKind,
  ): Record<string, string | string[]> => {
    if (kind === "edit-node") {
      const node = nodeItems.find((item) => item.name === activeResourceName);
      if (!node?.raw) return {};
      return {
        节点名称: node.name,
        "API 地址": node.raw.apiUrl,
        "TLS 校验主机名": node.raw.tlsServerName,
        认证账号: "",
        认证密码: "",
        端口池: `${node.raw.portStart}-${node.raw.portEnd}`,
        节点状态: node.raw.enabled ? "启用" : "维护中",
      };
    }
    if (kind === "edit-user") {
      const user = userItems.find((item) => item.id === activeResourceName);
      if (!user) return {};
      const roleLabel = {
        system_admin: "系统管理员",
        project_admin: "项目管理员",
        operator: "运维用户",
        temporary: "临时用户",
      }[user.role];
      return {
        姓名: user.displayName,
        登录账号: user.username,
        角色: roleLabel,
        授权项目:
          user.role === "system_admin"
            ? ["全部项目"]
            : user.projectIds.map(
                (id) =>
                  projectItems.find((project) => project.id === id)?.name || id,
              ),
        "新密码（选填）": "",
      };
    }
    if (kind === "edit-policy") {
      const policy = policyItems.find(
        (item) => item.name === activeResourceName,
      );
      if (!policy) return {};
      const capabilityLabel: Record<string, string> = {
        web: "Web",
        webssh: "WebSSH",
      };
      return {
        策略名称: policy.name,
        作用项目: policy.projectIds.map(
          (id) => projectItems.find((project) => project.id === id)?.name || id,
        ),
        授权用户: policy.userIds.map((id) => {
          const user = userItems.find((item) => item.id === id);
          return user ? userChoiceLabel(user) : id;
        }),
        授权能力: policy.capabilities.map(
          (item) => capabilityLabel[item] || item,
        ),
        有效时间: "保持现有有效期",
      };
    }
    return {};
  };

  const deleteResource = async (kind: ConfigModalKind) => {
    let deletedLabel = activeResourceName;
    if (kind === "edit-node") {
      const item = nodeItems.find((node) => node.name === activeResourceName);
      if (!item?.id) throw new Error("接入节点不存在");
      deletedLabel = item.name;
      await api.deleteNode(item.id);
    } else if (kind === "edit-user") {
      const item = userItems.find((user) => user.id === activeResourceName);
      if (!item) throw new Error("用户不存在");
      deletedLabel = `${item.displayName}（${item.username}）`;
      await api.deleteUser(item.id);
    } else if (kind === "edit-policy") {
      const item = policyItems.find(
        (policy) => policy.name === activeResourceName,
      );
      if (!item) throw new Error("访问策略不存在");
      deletedLabel = item.name;
      await api.deletePolicy(item.id);
    } else throw new Error("该资源不支持删除");
    setModal(null);
    setToast(`${deletedLabel}已删除`);
    await loadPlatform(currentUser!);
  };

  const nav = [
    { id: "overview" as View, label: "概览", icon: "⌂" },
    { id: "portal" as View, label: "访问门户", icon: "◫" },
    { id: "projects" as View, label: "客户项目", icon: "▦" },
    { id: "socks" as View, label: "托管通道", icon: "═" },
    { id: "nodes" as View, label: "接入节点", icon: "◇" },
    { id: "accounts" as View, label: "用户与权限", icon: "♙" },
    { id: "policies" as View, label: "访问策略", icon: "▤" },
    { id: "monitor" as View, label: "运行监控", icon: "◈" },
    { id: "logs" as View, label: "访问审计", icon: "≡" },
    { id: "settings" as View, label: "系统设置", icon: "⚙" },
  ].filter((item) => {
    if (currentUser?.role === "system_admin") return true;
    if (currentUser?.role === "temporary") return item.id === "portal";
    return ["overview", "portal", "projects"].includes(item.id);
  });
  const canManageProject =
    currentUser?.role === "system_admin" ||
    currentUser?.role === "project_admin";

  if (platformState === "checking" || platformState === "loading")
    return (
      <PlatformSplash
        message={
          platformState === "checking"
            ? "正在验证登录状态…"
            : "正在加载平台数据…"
        }
      />
    );
  if (platformState === "login")
    return <LoginScreen onAuthenticated={loadPlatform} />;
  if (platformState === "error")
    return (
      <PlatformError
        message={platformError}
        onRetry={() => {
          setPlatformState("checking");
          api
            .me()
            .then(loadPlatform)
            .catch((error) => {
              if (error instanceof APIError && error.status === 401)
                setPlatformState("login");
              else {
                setPlatformError(
                  error instanceof Error ? error.message : "无法连接平台服务",
                );
                setPlatformState("error");
              }
            });
        }}
      />
    );

  return (
    <div className="showcase">
      <header className="showcase-hero">
        <h1>
          <span>I5CLOUD</span> 远程管理平台
        </h1>
      </header>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="brand">
            <div className="brand-mark">I5</div>
            <div>
              <strong>I5CLOUD</strong>
              <span>Managed Access</span>
            </div>
          </div>
          <nav>
            <p className="nav-caption">I5CLOUD 控制中心</p>
            {nav.map((item) => (
              <button
                key={item.id}
                className={
                  view === item.id ||
                  (item.id === "projects" &&
                    (view === "workspace" ||
                      view === "discovery" ||
                      view === "connections"))
                    ? "active"
                    : ""
                }
                onClick={() => setView(item.id)}
              >
                <span className="nav-icon">{item.icon}</span>
                {item.label}
              </button>
            ))}
          </nav>
          <div className="sidebar-account">
            <div className="account-avatar">
              {currentUser?.displayName?.slice(0, 1) || "I"}
            </div>
            <div>
              <strong>{currentUser?.displayName || "平台用户"}</strong>
              <span>{currentUser?.username}</span>
            </div>
            <button
              type="button"
              title="退出登录"
              aria-label="退出登录"
              onClick={() =>
                void api
                  .logout()
                  .then(() => {
                    setCurrentUser(null);
                    setPlatformState("login");
                  })
                  .catch((error) =>
                    setToast(
                      error instanceof Error ? error.message : "退出登录失败",
                    ),
                  )
              }
            >
              ⇥
            </button>
          </div>
        </aside>

        <main>
          <section className="page">
            {(view === "workspace" ||
              view === "discovery" ||
              view === "connections") && (
              <ProjectTabs
                project={activeProject}
                active={view}
                canManage={canManageProject}
                onChange={setView}
                onEdit={() => setModal("edit-project")}
              />
            )}
            {view === "overview" && (
              <Overview
                devices={devices}
                projects={projectItems}
                nodes={nodeItems}
                tunnels={managedTunnels}
                sessions={sessionItems}
                onNavigate={setView}
              />
            )}
            {view === "portal" && (
              <AccessPortal
                devices={devices}
                projects={projectItems}
                user={currentUser}
                onWeb={openWeb}
                onSsh={openSsh}
              />
            )}
            {view === "workspace" && (
              <Workspace
                devices={projectDevices}
                project={activeProject}
                query={query}
                setQuery={setQuery}
                socksRunning={Boolean(socksStatus[activeProject.code])}
                canManage={canManageProject}
                onWeb={openWeb}
                onSsh={openSsh}
                onToast={setToast}
                onAdd={() => setModal("add-device")}
                onImport={() => setModal("import-devices")}
                onManage={(device) => {
                  setActiveDevice(device);
                  setModal("manage-device");
                }}
                onVerify={async (device) => {
                  if (!activeProject.id) throw new Error("项目尚未写入后台");
                  const result = await api.verifyDevice(
                    activeProject.id,
                    String(device.id),
                  );
                  const mapped = mapDevice(result.device, activeProject);
                  setDevices((items) =>
                    items.map((item) =>
                      String(item.id) === String(device.id) ? mapped : item,
                    ),
                  );
                  setSocksStatus((items) => ({
                    ...items,
                    [activeProject.code]: true,
                  }));
                  return { verified: result.verified, failed: result.failed };
                }}
                onNetworksChange={async (networks) => {
                  if (!activeProject.id) throw new Error("项目尚未写入后台");
                  await api.updateProject(activeProject.id, {
                    name: activeProject.name,
                    ownerName: activeProject.owner,
                    networks,
                  });
                  setActiveProject((project) => ({ ...project, networks }));
                  setProjectItems((items) =>
                    items.map((project) =>
                      project.code === activeProject.code
                        ? { ...project, networks }
                        : project,
                    ),
                  );
                }}
              />
            )}
            {view === "nodes" && (
              <NodesView
                nodes={nodeItems}
                usedPorts={forwardItems.length}
                onCreate={() => setModal("create-node")}
                onOpen={(node) => {
                  setActiveResourceName(node.name);
                  setModal("node-clients");
                }}
                onManage={(name) => {
                  setActiveResourceName(name);
                  setModal("edit-node");
                }}
                onRefresh={async (node) => {
                  if (!node.id) return;
                  try {
                    const [health, tunnels, clients] = await Promise.all([
                      api.nodeHealth(node.id),
                      api.managedTunnels(node.id),
                      api.nodeClients(node.id),
                    ]);
                    setNodeItems((items) =>
                      items.map((item) =>
                        item.id === node.id
                          ? {
                              ...item,
                              status: health.reachable ? "运行正常" : "待检查",
                              latency: `${health.latencyMs} ms`,
                              clients: clients.length,
                              tunnels: tunnels.length,
                              runningTunnels: tunnels.filter(
                                (tunnel) => tunnel.running,
                              ).length,
                              raw: item.raw
                                ? {
                                    ...item.raw,
                                    healthStatus: health.reachable
                                      ? "healthy"
                                      : "unreachable",
                                  }
                                : item.raw,
                            }
                          : item,
                      ),
                    );
                    setToast(
                      `${node.name}连接正常，${clients.length} 个 Client，延迟 ${health.latencyMs} ms`,
                    );
                  } catch (error) {
                    setNodeItems((items) =>
                      items.map((item) =>
                        item.id === node.id
                          ? { ...item, status: "待检查", latency: "失败" }
                          : item,
                      ),
                    );
                    setToast(
                      error instanceof Error
                        ? error.message
                        : "节点连接检查失败",
                    );
                  }
                }}
              />
            )}
            {view === "projects" && (
              <ProjectsView
                projects={projectItems}
                canCreate={currentUser?.role === "system_admin"}
                onOpen={(project) => {
                  setActiveProject(project);
                  setQuery("");
                  setScanActive(false);
                  setScanProgress(0);
                  setImported([]);
                  setView("workspace");
                }}
                onCreate={() => setModal("create-project")}
              />
            )}
            {view === "socks" && (
              <SocksView
                projects={projectItems}
                nodes={nodeItems}
                tunnels={managedTunnels}
                onRefresh={async () => {
                  const groups = await Promise.all(
                    nodeItems
                      .filter((node): node is NodeView & { id: string } =>
                        Boolean(node.id),
                      )
                      .map(async (node) => ({
                        node,
                        items: await api.managedTunnels(node.id),
                      })),
                  );
                  const nextStatus: Record<string, boolean> = {};
                  for (const project of projectItems) {
                    const tunnel = groups
                      .find((group) => group.node.id === project.nodeId)
                      ?.items.find(
                        (item) => item.clientId === project.clientId,
                      );
                    if (tunnel) nextStatus[project.code] = tunnel.running;
                  }
                  setManagedTunnels(
                    groups.flatMap((group) =>
                      group.items.map((tunnel) => ({
                        ...tunnel,
                        nodeId: group.node.id,
                        nodeName: group.node.name,
                      })),
                    ),
                  );
                  setSocksStatus(nextStatus);
                  setNodeItems((items) =>
                    items.map((node) => {
                      const group = groups.find(
                        (candidate) => candidate.node.id === node.id,
                      );
                      return group
                        ? {
                            ...node,
                            tunnels: group.items.length,
                            runningTunnels: group.items.filter(
                              (tunnel) => tunnel.running,
                            ).length,
                          }
                        : node;
                    }),
                  );
                }}
                onToggle={async (tunnel, running) => {
                  await api.setManagedTunnel(
                    tunnel.nodeId,
                    tunnel.clientId,
                    running,
                  );
                  setManagedTunnels((items) =>
                    items.map((item) =>
                      item.nodeId === tunnel.nodeId &&
                      item.clientId === tunnel.clientId
                        ? { ...item, configured: running, running }
                        : item,
                    ),
                  );
                  const project = projectItems.find(
                    (item) =>
                      item.nodeId === tunnel.nodeId &&
                      item.clientId === tunnel.clientId,
                  );
                  if (project)
                    setSocksStatus((items) => ({
                      ...items,
                      [project.code]: running,
                    }));
                  setNodeItems((items) =>
                    items.map((node) =>
                      node.id === tunnel.nodeId
                        ? {
                            ...node,
                            runningTunnels: Math.max(
                              0,
                              node.runningTunnels + (running ? 1 : -1),
                            ),
                          }
                        : node,
                    ),
                  );
                }}
                onToast={setToast}
                onDetails={(name) => {
                  setActiveResourceName(name);
                  setModal("socks-detail");
                }}
              />
            )}
            {view === "connections" && (
              <ConnectionsView
                project={activeProject}
                forwards={forwardItems.filter(
                  (item) => item.projectId === activeProject.id,
                )}
                nodes={nodeItems}
                onCreate={() => setModal("create-connection")}
                onManage={(forward) => {
                  setActiveResourceName(forward.id);
                  setModal("edit-connection");
                }}
                onToast={setToast}
              />
            )}
            {view === "accounts" && (
              <AccountsView
                users={userItems}
                currentUser={currentUser}
                projects={projectItems}
                onCreate={() => setModal("create-user")}
                onEdit={(userId) => {
                  setActiveResourceName(userId);
                  setModal("edit-user");
                }}
                onToggle={async (user, enabled) => {
                  const updated = await api.updateUser(user.id, {
                    displayName: user.displayName,
                    password: "",
                    role: user.role,
                    enabled,
                    projectIds: user.projectIds,
                  });
                  setUserItems((items) =>
                    items.map((item) =>
                      item.id === updated.id ? updated : item,
                    ),
                  );
                }}
                onResetMFA={async (user) => {
                  await api.resetUserMFA(user.id);
                  setUserItems((items) =>
                    items.map((item) =>
                      item.id === user.id
                        ? {
                            ...item,
                            mfaEnabled: false,
                            passwordChangeRequired: true,
                          }
                        : item,
                    ),
                  );
                }}
                onToast={setToast}
              />
            )}
            {view === "policies" && (
              <PoliciesView
                policies={policyItems}
                projects={projectItems}
                onCreate={() => setModal("create-policy")}
                onEdit={(name) => {
                  setActiveResourceName(name);
                  setModal("edit-policy");
                }}
                onToggle={async (policy, enabled) => {
                  const updated = await api.updatePolicy(policy.id, {
                    name: policy.name,
                    projectIds: policy.projectIds,
                    userIds: policy.userIds,
                    capabilities: policy.capabilities,
                    validFrom: policy.validFrom,
                    validUntil: policy.validUntil,
                    enabled,
                  });
                  setPolicyItems((items) =>
                    items.map((item) =>
                      item.id === updated.id ? updated : item,
                    ),
                  );
                }}
                onToast={setToast}
              />
            )}
            {view === "monitor" && (
              <MonitorView
                nodes={nodeItems}
                snapshot={monitorSnapshot}
                loading={monitorLoading}
                sessions={sessionItems}
                users={userItems}
                projects={projectItems}
                onRefresh={refreshMonitor}
                onRevoke={async (id) => {
                  await api.revokeSession(id);
                  setSessionItems((items) =>
                    items.filter((item) => item.id !== id),
                  );
                  setMonitorSnapshot((current) =>
                    current
                      ? {
                          ...current,
                          activeSessions: Math.max(
                            0,
                            current.activeSessions - 1,
                          ),
                        }
                      : current,
                  );
                }}
                onToast={setToast}
              />
            )}
            {view === "discovery" && (
              <DiscoveryView
                project={activeProject}
                active={scanActive}
                progress={scanProgress}
                imported={imported}
                ignored={ignoredDiscovery[activeProject.code] || []}
                candidates={discoveryCandidates[activeProject.code] || []}
                onCandidatesChange={(candidates) =>
                  setDiscoveryCandidates((items) => ({
                    ...items,
                    [activeProject.code]: candidates,
                  }))
                }
                onIgnoredChange={(ignored) =>
                  setIgnoredDiscovery((items) => ({
                    ...items,
                    [activeProject.code]: ignored,
                  }))
                }
                onStart={async (ports) => {
                  if (!activeProject.id) {
                    setToast("项目尚未写入后台，无法执行自动发现");
                    return;
                  }
                  setScanProgress(0);
                  setImported([]);
                  setIgnoredDiscovery((items) => ({
                    ...items,
                    [activeProject.code]: [],
                  }));
                  setDiscoveryCandidates((items) => ({
                    ...items,
                    [activeProject.code]: [],
                  }));
                  try {
                    const job = await api.createDiscoveryJob(
                      activeProject.id,
                      activeProject.networks,
                      ports,
                    );
                    setScanJobId(job.id);
                    setScanActive(true);
                    setSocksStatus((items) => ({
                      ...items,
                      [activeProject.code]: true,
                    }));
                  } catch (error) {
                    setToast(
                      error instanceof Error
                        ? error.message
                        : "扫描任务创建失败",
                    );
                  }
                }}
                onCancel={async () => {
                  if (scanJobId) {
                    try {
                      await api.cancelDiscoveryJob(scanJobId);
                    } catch (error) {
                      setToast(
                        error instanceof Error ? error.message : "取消扫描失败",
                      );
                      return;
                    }
                  }
                  setScanActive(false);
                  setToast("扫描任务已取消");
                }}
                onImport={async (index, item) => {
                  const selectedServices = item.services.filter(
                    (service): service is DiscoveryService & { port: number } =>
                      service.selected &&
                      typeof service.port === "number" &&
                      service.port > 0 &&
                      service.name.trim().length > 0,
                  );
                  if (!scanJobId || !activeProject.id) {
                    setToast("扫描任务上下文已失效，请重新扫描");
                    return;
                  }
                  try {
                    await api.importDiscoveryDevice(scanJobId, {
                      host: item.host,
                      name: item.title.trim(),
                      deviceType: "other",
                      vendor: item.fingerprint,
                      endpoints: selectedServices.map((service) => ({
                        name: service.name.trim(),
                        protocol: service.protocol,
                        targetPort: service.port,
                      })),
                    });
                    const backendDevices = await api.devices(activeProject.id);
                    const mapped = backendDevices.map((device) =>
                      mapDevice(device, activeProject),
                    );
                    setDevices((items) => [
                      ...items.filter(
                        (device) => device.projectCode !== activeProject.code,
                      ),
                      ...mapped,
                    ]);
                    setImported((items) => [...items, index]);
                    const webCount = selectedServices.filter(
                      (service) =>
                        service.protocol === "http" ||
                        service.protocol === "https",
                    ).length;
                    setToast(
                      `已导入 ${item.title}：${webCount} 个 Web 服务 · ${selectedServices.length - webCount} 个其他服务`,
                    );
                  } catch (error) {
                    setToast(
                      error instanceof Error
                        ? error.message
                        : "发现结果导入失败",
                    );
                  }
                }}
              />
            )}
            {view === "logs" && (
              <LogsView logs={auditItems} onToast={setToast} />
            )}
            {view === "settings" && (
              <SettingsView
                security={securitySettings}
                onSecurityChange={setSecuritySettings}
                onToast={setToast}
              />
            )}
          </section>
        </main>

        {modal === "add-device" && (
          <AddDeviceModal onClose={() => setModal(null)} onSubmit={addDevice} />
        )}
        {modal === "manage-device" && (
          <ManageDeviceModal
            device={activeDevice}
            onClose={() => setModal(null)}
            onDelete={async () => {
              const project =
                projectItems.find(
                  (item) => item.code === activeDevice.projectCode,
                ) || activeProject;
              if (!project.id || !activeDevice.id)
                throw new Error("设备或项目上下文已经失效");
              await api.deleteDevice(project.id, String(activeDevice.id));
              setDevices((items) =>
                items.filter(
                  (item) => String(item.id) !== String(activeDevice.id),
                ),
              );
              setProjectItems((items) =>
                items.map((item) =>
                  item.id === project.id
                    ? {
                        ...item,
                        devices: Math.max(0, item.devices - 1),
                        web: Math.max(
                          0,
                          item.web - activeDevice.webServices.length,
                        ),
                      }
                    : item,
                ),
              );
              setModal(null);
              setToast(`${activeDevice.name}已删除`);
            }}
            onSave={async (device) => {
              const project =
                projectItems.find((item) => item.code === device.projectCode) ||
                activeProject;
              if (!project.id) throw new Error("项目尚未写入后台");
              const desired = device.serviceEndpoints || [];
              await api.updateDevice(project.id, String(device.id), {
                host: device.host,
                name: device.name,
                deviceType: device.type,
                vendor: device.vendor,
                endpoints: desired.map((endpoint) => ({
                  id: endpoint.id,
                  name: endpoint.name,
                  protocol: endpoint.protocol,
                  targetPort: endpoint.port,
                  tlsServerName: endpoint.tlsServerName || "",
                  allowInsecureTls: Boolean(endpoint.allowInsecureTls),
                  sshCredential: endpoint.sshCredential,
                  sshHostKeyFingerprint: endpoint.sshHostKeyFingerprint || "",
                })),
              });
              const refreshed = (await api.devices(project.id)).map((item) =>
                mapDevice(item, project),
              );
              setDevices((items) => [
                ...items.filter((item) => item.projectCode !== project.code),
                ...refreshed,
              ]);
              setModal(null);
              setToast(`${device.name}配置已写入后台`);
            }}
          />
        )}
        {modal === "import-devices" && (
          <ImportDevicesModal
            project={activeProject}
            onClose={() => setModal(null)}
            onImport={async (inputs) => {
              if (!activeProject.id) throw new Error("项目尚未写入后台");
              await api.createDevices(activeProject.id, inputs);
              const refreshed = (await api.devices(activeProject.id)).map(
                (item) => mapDevice(item, activeProject),
              );
              setDevices((items) => [
                ...items.filter(
                  (item) => item.projectCode !== activeProject.code,
                ),
                ...refreshed,
              ]);
              setModal(null);
              setToast(`已导入 ${inputs.length} 台设备并合并同主机多服务`);
            }}
          />
        )}
        {modal === "edit-project" && (
          <ProjectSettingsModal
            project={activeProject}
            userNames={userItems.map((user) => user.displayName)}
            onClose={() => setModal(null)}
            onDelete={
              currentUser?.role === "system_admin"
                ? async () => {
                    if (!activeProject.id) throw new Error("项目尚未写入后台");
                    const deletedName = activeProject.name;
                    await api.deleteProject(activeProject.id);
                    setModal(null);
                    setView("projects");
                    setQuery("");
                    setScanActive(false);
                    setScanJobId(null);
                    if (!currentUser)
                      throw new Error("登录会话已失效，请重新登录");
                    await loadPlatform(currentUser);
                    setView("projects");
                    setToast(`${deletedName}及项目内数据已删除`);
                  }
                : undefined
            }
            onSave={async (project) => {
              if (!project.id) throw new Error("项目尚未写入后台");
              await api.updateProject(project.id, {
                name: project.name,
                ownerName: project.owner,
                networks: project.networks,
              });
              setActiveProject(project);
              setProjectItems((items) =>
                items.map((item) => (item.id === project.id ? project : item)),
              );
              setModal(null);
              setToast(`${project.name}项目设置已保存`);
            }}
          />
        )}
        {modal === "create-project" && (
          <CreateProjectModal
            nodes={nodeItems}
            userNames={userItems.map((user) => user.displayName)}
            onClose={() => setModal(null)}
            onCreated={async (input) => {
              const created = await api.createProject(input);
              setModal(null);
              await loadPlatform(currentUser!);
              setView("projects");
              setToast(
                `${created.name}项目已绑定 Client ID ${created.clientId}`,
              );
            }}
          />
        )}
        {modal &&
          [
            "create-node",
            "create-policy",
            "create-user",
            "edit-node",
            "edit-policy",
            "edit-user",
          ].includes(modal) && (
            <ResourceModal
              kind={modal as ConfigModalKind}
              initialName={activeResourceName}
              initialValues={resourceInitialValues(modal as ConfigModalKind)}
              projectNames={projectItems.map((project) => project.name)}
              userNames={
                modal === "create-policy" || modal === "edit-policy"
                  ? userItems
                      .filter((user) => user.role === "temporary")
                      .map(userChoiceLabel)
                  : userItems.map((user) => user.displayName)
              }
              onClose={() => setModal(null)}
              onSubmit={(label, values) =>
                submitResource(modal as ConfigModalKind, label, values)
              }
              onDelete={
                modal.startsWith("edit-")
                  ? () => deleteResource(modal as ConfigModalKind)
                  : undefined
              }
            />
          )}
        {(modal === "create-connection" || modal === "edit-connection") && (
          <PortForwardModal
            project={activeProject}
            devices={projectDevices}
            existing={
              modal === "edit-connection"
                ? forwardItems.find((item) => item.id === activeResourceName)
                : undefined
            }
            onClose={() => setModal(null)}
            onChanged={async (message) => {
              const projectId = activeProject.id;
              if (projectId) {
                const refreshed = await api.portForwards(projectId);
                setForwardItems((items) => [
                  ...items.filter((item) => item.projectId !== projectId),
                  ...refreshed,
                ]);
              }
              setModal(null);
              setToast(message);
            }}
          />
        )}
        {modal === "socks-detail" && (
          <SocksDetailModal
            name={activeResourceName}
            projects={projectItems}
            nodes={nodeItems}
            onClose={() => setModal(null)}
          />
        )}
        {modal === "node-clients" &&
          (() => {
            const node = nodeItems.find(
              (item) => item.name === activeResourceName,
            );
            return node?.id ? (
              <NodeClientsModal
                node={{ ...node, id: node.id }}
                canCreate={currentUser?.role === "system_admin"}
                onClose={() => setModal(null)}
                onCountChange={(count) =>
                  setNodeItems((items) =>
                    items.map((item) =>
                      item.id === node.id ? { ...item, clients: count } : item,
                    ),
                  )
                }
              />
            ) : null;
          })()}
        {toast && (
          <div className="toast">
            <span>✓</span>
            {toast}
          </div>
        )}
      </div>
    </div>
  );
}

function Overview({
  devices,
  projects,
  nodes,
  tunnels,
  sessions,
  onNavigate,
}: {
  devices: Device[];
  projects: ProjectView[];
  nodes: NodeView[];
  tunnels: NodeManagedTunnel[];
  sessions: APIAccessSession[];
  onNavigate: (view: View) => void;
}) {
  const online = devices.filter((device) => device.status === "online").length;
  const availableNodes = nodes.filter((node) => node.status === "运行正常").length;
  const onlineClients = projects.filter((project) => project.clientStatus === "在线").length;
  const runningTunnels = tunnels.filter((tunnel) => tunnel.running).length;
  const webServices = devices.reduce((total, device) => total + device.webServices.length, 0);
  const sshServices = devices.filter((device) => device.ssh).length;
  const scanNetworks = projects.reduce((total, project) => total + project.networks.length, 0);
  const deviceRate = devices.length ? Math.round((online / devices.length) * 100) : 0;
  const capabilityItems = [
    { icon: "▦", title: "客户项目", value: projects.length, detail: `${onlineClients} 个 Client 在线`, action: "管理项目", view: "projects" as View },
    { icon: "═", title: "托管通道", value: tunnels.length, detail: `${runningTunnels} 条正在运行`, action: "查看通道", view: "socks" as View },
    { icon: "◇", title: "接入节点", value: nodes.length, detail: `${availableNodes} 个节点可用`, action: "管理节点", view: "nodes" as View },
    { icon: "◫", title: "远程入口", value: webServices + sshServices, detail: `${webServices} 个 Web · ${sshServices} 个 SSH`, action: "访问门户", view: "portal" as View },
  ];
  return (
    <>
      <div className="overview-dashboard-head">
        <div>
          <span className="eyebrow">I5CLOUD CONTROL CENTER</span>
          <h1>平台运行概览</h1>
          <p>客户项目、接入节点、托管通道与远程访问的实时汇总</p>
        </div>
        <div className="overview-date">
          <i className="live-dot" />
          <span>平台服务运行正常</span>
          <b>{new Date().toLocaleDateString("zh-CN")}</b>
        </div>
      </div>
      <div className="overview-metrics">
        <Metric label="客户项目" value={String(projects.length)} detail={`${onlineClients} 个 Client 在线`} tone="blue" />
        <Metric label="可用节点" value={`${availableNodes}/${nodes.length}`} detail="节点接口实时状态" tone="green" />
        <Metric label="运行通道" value={`${runningTunnels}/${tunnels.length}`} detail="NPS SOCKS 实时状态" tone="violet" />
        <Metric label="活动会话" value={String(sessions.length)} detail="Web 与 WebSSH 会话" tone="amber" />
      </div>
      <div className="overview-capability-grid">
        {capabilityItems.map((item) => (
          <article className="overview-capability-card" key={item.title}>
            <div className="overview-capability-icon">{item.icon}</div>
            <div><span>{item.title}</span><strong>{item.value}</strong><small>{item.detail}</small></div>
            <button onClick={() => onNavigate(item.view)}>{item.action} →</button>
          </article>
        ))}
      </div>
      <div className="overview-operations-grid">
        <section className="content-card overview-status-card">
          <div className="card-header"><div><h2>运行状态</h2><p>所有数据均来自当前平台和接入节点</p></div><Tag tone="green">实时</Tag></div>
          <div className="overview-status-list">
            <div><span>项目 Client</span><strong>{onlineClients} / {projects.length}</strong><Tag tone={onlineClients === projects.length && projects.length ? "green" : "amber"}>{onlineClients === projects.length && projects.length ? "全部在线" : "存在离线"}</Tag></div>
            <div><span>接入节点</span><strong>{availableNodes} / {nodes.length}</strong><Tag tone={availableNodes === nodes.length && nodes.length ? "green" : "amber"}>{availableNodes === nodes.length && nodes.length ? "全部可用" : "需要检查"}</Tag></div>
            <div><span>托管 SOCKS</span><strong>{runningTunnels} / {tunnels.length}</strong><Tag tone={runningTunnels ? "green" : "gray"}>{runningTunnels ? "存在运行通道" : "全部关闭"}</Tag></div>
            <div><span>远程访问会话</span><strong>{sessions.length}</strong><Tag tone={sessions.length ? "blue" : "gray"}>{sessions.length ? "正在访问" : "暂无会话"}</Tag></div>
          </div>
        </section>
        <section className="content-card overview-resource-card">
          <div className="card-header"><div><h2>资源与能力</h2><p>已纳入平台管理的远程资源</p></div></div>
          <div className="overview-resource-summary">
            <div><span>登记设备</span><strong>{devices.length}</strong><small>{online} 台在线 · 在线率 {deviceRate}%</small></div>
            <div><span>Web 服务</span><strong>{webServices}</strong><small>通过独立反代域名访问</small></div>
            <div><span>WebSSH</span><strong>{sshServices}</strong><small>支持保存凭据或临时登录</small></div>
            <div><span>扫描网段</span><strong>{scanNetworks}</strong><small>分布在 {projects.filter((project) => project.networks.length).length} 个项目</small></div>
          </div>
          <div className="overview-route-strip"><span>访问链路</span><b>浏览器</b><i>→</i><b>平台网关</b><i>→</i><b>托管 SOCKS</b><i>→</i><b>内网服务</b></div>
        </section>
      </div>
    </>
  );
}

function SocksView({
  projects,
  nodes,
  tunnels,
  onRefresh,
  onToggle,
  onToast,
  onDetails,
}: {
  projects: ProjectView[];
  nodes: NodeView[];
  tunnels: NodeManagedTunnel[];
  onRefresh: () => Promise<void>;
  onToggle: (tunnel: NodeManagedTunnel, running: boolean) => Promise<void>;
  onToast: (value: string) => void;
  onDetails: (name: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<
    "all" | "running" | "stopped"
  >("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  useEffect(() => {
    const refresh = window.setInterval(
      () => void onRefresh().catch(() => undefined),
      10000,
    );
    return () => window.clearInterval(refresh);
  }, [onRefresh]);
  const formatFlow = (value: number) =>
    value < 1024
      ? `${value} B`
      : value < 1048576
        ? `${(value / 1024).toFixed(1)} KB`
        : `${(value / 1048576).toFixed(1)} MB`;
  const rows = tunnels.map((tunnel) => {
    const project = projects.find(
      (item) =>
        item.nodeId === tunnel.nodeId && item.clientId === tunnel.clientId,
    );
    const node = nodes.find((item) => item.id === tunnel.nodeId);
    return {
      key: `${tunnel.nodeId}:${tunnel.clientId}`,
      tunnel,
      project,
      title: project?.name || tunnel.clientName || `Client ${tunnel.clientId}`,
      host: `${nodeServiceHost(node)}:${tunnel.port || 10000 + tunnel.clientId}`,
      flow: formatFlow(tunnel.inletFlow + tunnel.exportFlow),
    };
  });
  const visibleRows = rows.filter(
    (row) =>
      `${row.title}${row.tunnel.nodeName}${row.tunnel.clientId}${row.host}`
        .toLowerCase()
        .includes(query.toLowerCase()) &&
      (statusFilter === "all" ||
        (statusFilter === "running"
          ? row.tunnel.configured
          : !row.tunnel.configured)),
  );
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visibleRows.length / pageSize)),
  );
  const pagedRows = visibleRows.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  const runningCount = rows.filter((row) => row.tunnel.configured).length;
  const startAvailable = async () => {
    const available = tunnels.filter((tunnel) => !tunnel.configured);
    const results = await Promise.allSettled(
      available.map((tunnel) => onToggle(tunnel, true)),
    );
    const started = results.filter(
      (result) => result.status === "fulfilled",
    ).length;
    onToast(`已启动 ${started} 个通道，${results.length - started} 个失败`);
  };
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">网络服务</div>
          <h1>托管通道</h1>
          <p>展示并控制节点实际存在的全部 SOCKS 通道</p>
        </div>
        <div className="heading-actions">
          <button
            className="btn secondary"
            onClick={() =>
              void onRefresh()
                .then(() => onToast("已从节点刷新全部 SOCKS 通道和流量状态"))
                .catch((error) =>
                  onToast(
                    error instanceof Error ? error.message : "通道状态刷新失败",
                  ),
                )
            }
          >
            刷新状态
          </button>
          <button
            className="btn primary"
            disabled={!rows.some((row) => !row.tunnel.running)}
            onClick={startAvailable}
          >
            启动全部已关闭通道
          </button>
        </div>
      </div>
      <div className="socks-summary">
        <div>
          <span>托管实例</span>
          <strong>{rows.length}</strong>
          <small>节点实际返回的 SOCKS 通道</small>
        </div>
        <div>
          <span>运行中</span>
          <strong className="teal-text">{runningCount}</strong>
          <small>通道已由节点开启</small>
        </div>
        <div>
          <span>已关闭</span>
          <strong>{rows.length - runningCount}</strong>
          <small>通道当前处于关闭状态</small>
        </div>
      </div>
      <div className="content-card">
        <div className="card-header search-card-header">
          <div>
            <h2>节点 SOCKS 通道</h2>
            <p>状态与活跃状态直接来自节点实时数据</p>
          </div>
          <div className="management-tools">
            <div className="table-search">
              <span>⌕</span>
              <input
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
                placeholder="搜索项目、节点、Client ID 或地址"
              />
            </div>
            <select
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value as typeof statusFilter);
                setPage(1);
              }}
            >
              <option value="all">全部状态</option>
              <option value="running">运行中</option>
              <option value="stopped">已关闭</option>
            </select>
            <Tag tone="green">{visibleRows.length} 个结果</Tag>
          </div>
        </div>
        {visibleRows.length ? (
          <>
            <div className="socks-table-scroll">
              <table className="socks-table">
                <thead>
                  <tr>
                    <th>通道</th>
                    <th>节点 / Client</th>
                    <th>访问地址</th>
                    <th>项目绑定</th>
                    <th>状态</th>
                    <th>累计流量</th>
                    <th>活跃状态</th>
                    <th className="socks-actions-heading">操作</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedRows.map((row) => {
                    const isRunning = row.tunnel.configured;
                    const isActive = row.tunnel.running;
                    const toggleRunning = () =>
                      void onToggle(row.tunnel, !isRunning)
                        .then(() =>
                          onToast(
                            `${row.title}通道已${isRunning ? "停止" : "启动"}`,
                          ),
                        )
                        .catch((error) =>
                          onToast(
                            error instanceof Error
                              ? error.message
                              : "通道操作失败",
                          ),
                        );
                    return (
                      <tr key={row.key}>
                        <td>
                          <div className="socks-name-cell">
                            <i>═</i>
                            <strong>{row.title}</strong>
                          </div>
                        </td>
                        <td>
                          <strong>{row.tunnel.nodeName}</strong>
                          <small>Client ID {row.tunnel.clientId}</small>
                        </td>
                        <td>
                          <code>{row.host}</code>
                        </td>
                        <td>
                          {row.project ? (
                            <button
                              className="socks-project-link"
                              onClick={() => onDetails(row.project!.name)}
                            >
                              {row.project.code}
                            </button>
                          ) : (
                            <span className="socks-unbound">未绑定</span>
                          )}
                        </td>
                        <td>
                          <Tag tone={isRunning ? "green" : "gray"}>
                            {isRunning ? "运行中" : "已关闭"}
                          </Tag>
                        </td>
                        <td>
                          <strong className="socks-flow">{row.flow}</strong>
                        </td>
                        <td>
                          <Tag tone={isActive ? "green" : "gray"}>
                            {isActive ? "活跃中" : "非活跃"}
                          </Tag>
                        </td>
                        <td>
                          <div className="socks-row-actions">
                            {isRunning ? (
                              <ConfirmButton
                                className="danger-soft"
                                label="停止"
                                confirmLabel="确认停止？"
                                onConfirm={toggleRunning}
                              />
                            ) : (
                              <button
                                className="primary-soft"
                                onClick={toggleRunning}
                              >
                                启动
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <PaginationFooter
              total={visibleRows.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              noun="条记录"
            />
          </>
        ) : (
          <EmptyState
            title={rows.length ? "没有匹配的通道" : "节点未返回 SOCKS 通道"}
            detail={
              rows.length
                ? "请调整搜索词或状态筛选条件"
                : "请检查节点上是否已经创建 SOCKS 类型通道"
            }
            onClear={
              rows.length
                ? () => {
                    setQuery("");
                    setStatusFilter("all");
                  }
                : undefined
            }
          />
        )}
      </div>
    </>
  );
}

function ConnectionsView({
  project,
  forwards,
  nodes,
  onCreate,
  onManage,
  onToast,
}: {
  project: ProjectView;
  forwards: APIPortForward[];
  nodes: NodeView[];
  onCreate: () => void;
  onManage: (forward: APIPortForward) => void;
  onToast: (value: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const node = nodes.find((item) => item.id === project.nodeId);
  const connections = forwards.map((item) => ({
    ...item,
    name: item.endpointName,
    type: "TCP",
    public: `${nodeServiceHost(node)}:${item.serverPort}`,
    statusLabel:
      item.status === "running"
        ? "运行中"
        : item.status === "stopped"
          ? "已停止"
          : item.status === "cleanup_failed"
            ? "清理失败"
            : item.status,
  }));
  const visibleConnections = connections.filter((item) =>
    `${item.name}${item.type}${item.public}${item.target}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visibleConnections.length / pageSize)),
  );
  const pagedConnections = visibleConnections.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  const runningConnections = connections.filter(
    (item) => item.status === "running",
  ).length;
  const expiringConnections = connections.filter((item) =>
    Boolean(item.expiresAt),
  ).length;
  const copyAddress = async (address: string) => {
    try {
      await navigator.clipboard.writeText(address);
      onToast(`已复制：${address}`);
    } catch {
      onToast(`复制失败，请手动复制：${address}`);
    }
  };
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">
            <span>客户项目</span>
            <b>/</b>
            {project.name}
          </div>
          <h1>端口转发</h1>
          <p>为 SSH、RDP、数据库和自定义 TCP 服务提供原生客户端入口</p>
        </div>
        <button className="btn primary" onClick={onCreate}>
          ＋ 新建端口转发
        </button>
      </div>
      <div className="metrics">
        <Metric
          label="项目连接"
          value={String(connections.length)}
          detail={`${runningConnections} 个运行中`}
          tone="blue"
        />
        <Metric
          label="运行中"
          value={String(runningConnections)}
          detail="节点状态实时保存"
          tone="green"
        />
        <Metric
          label="限时服务"
          value={String(expiringConnections)}
          detail="到期后自动清理"
          tone="violet"
        />
        <Metric
          label="节点端口池"
          value={node?.ports || "—"}
          detail="按节点事务分配"
          tone="amber"
        />
      </div>
      <div className="content-card">
        <div className="card-header">
          <div>
            <h2>项目端口转发服务</h2>
            <p>设备 Web 后台不在此列表，Web 访问固定经项目托管 SOCKS</p>
          </div>
          <div className="table-search">
            <span>⌕</span>
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
              placeholder="搜索服务、类型、入口或目标"
            />
          </div>
        </div>
        {visibleConnections.length ? (
          <>
            <div className="table-wrap">
              <table className="device-table">
                <thead>
                  <tr>
                    <th>服务名称</th>
                    <th>类型</th>
                    <th>公网入口</th>
                    <th>内网目标</th>
                    <th>到期时间</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedConnections.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <strong>{item.name}</strong>
                      </td>
                      <td>
                        <Tag tone="blue">{item.type}</Tag>
                      </td>
                      <td>
                        <code>{item.public}</code>
                      </td>
                      <td>
                        <code>{item.target}</code>
                      </td>
                      <td>
                        {item.expiresAt
                          ? new Date(item.expiresAt).toLocaleString("zh-CN")
                          : "永久"}
                      </td>
                      <td>
                        <Tag
                          tone={
                            item.status === "running"
                              ? "green"
                              : item.status === "cleanup_failed"
                                ? "amber"
                                : "gray"
                          }
                        >
                          {item.statusLabel}
                        </Tag>
                      </td>
                      <td>
                        <div className="row-actions">
                          <button onClick={() => void copyAddress(item.public)}>
                            复制地址
                          </button>
                          <button onClick={() => onManage(item)}>
                            管理连接
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PaginationFooter
              total={visibleConnections.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              noun="条连接"
            />
          </>
        ) : (
          <EmptyState
            title={query ? "没有匹配的端口转发" : "当前项目暂无端口转发"}
            detail={
              query
                ? "请调整服务名、类型或端口关键词"
                : "Web 服务无需创建转发；仅为原生客户端服务按需创建"
            }
            onClear={query ? () => setQuery("") : undefined}
          />
        )}
      </div>
    </>
  );
}

function AccountsView({
  users,
  currentUser,
  projects,
  onCreate,
  onEdit,
  onToggle,
  onResetMFA,
  onToast,
}: {
  users: APIUser[];
  currentUser: APIUser | null;
  projects: ProjectView[];
  onCreate: () => void;
  onEdit: (userId: string) => void;
  onToggle: (user: APIUser, enabled: boolean) => Promise<void>;
  onResetMFA: (user: APIUser) => Promise<void>;
  onToast: (value: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const roleLabels = {
    system_admin: "系统管理员",
    project_admin: "项目管理员",
    operator: "运维用户",
    temporary: "临时用户",
  };
  const projectName = (id: string) =>
    projects.find((project) => project.id === id)?.name || id;
  const visible = users.filter((user) =>
    `${user.displayName}${user.username}${user.email}${roleLabels[user.role]}${user.projectIds.map(projectName).join(" ")}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visible.length / pageSize)),
  );
  const pagedUsers = visible.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  const onboarded = users.filter(
    (user) => user.mfaEnabled && !user.passwordChangeRequired,
  ).length;
  const pending = users.filter(
    (user) => user.passwordChangeRequired || !user.mfaEnabled,
  ).length;
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">安全中心</div>
          <h1>用户与权限</h1>
          <p>管理平台用户、角色、项目范围与首次登录安全状态</p>
        </div>
        <button className="btn primary" onClick={onCreate}>
          ＋ 添加用户
        </button>
      </div>
      <div className="metrics">
        <Metric
          label="平台用户"
          value={String(users.length)}
          detail="来自用户数据库"
          tone="blue"
        />
        <Metric
          label="安全设置完成"
          value={String(onboarded)}
          detail="邮箱与双重认证已绑定"
          tone="green"
        />
        <Metric
          label="待首次设置"
          value={String(pending)}
          detail="登录后必须完成安全向导"
          tone="violet"
        />
        <Metric
          label="停用账号"
          value={String(users.filter((user) => !user.enabled).length)}
          detail="保留审计记录"
          tone="amber"
        />
      </div>
      <div className="content-card">
        <div className="card-header">
          <div>
            <h2>用户列表</h2>
            <p>
              管理员只分配初始密码；用户首次登录必须改密、验证邮箱并绑定双重认证
            </p>
          </div>
          <div className="table-search">
            <span>⌕</span>
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
              placeholder="搜索用户、邮箱、角色或项目"
            />
          </div>
        </div>
        {visible.length ? (
          <>
            <div className="table-wrap">
              <table className="device-table account-security-table">
                <thead>
                  <tr>
                    <th>用户</th>
                    <th>账号 / 邮箱</th>
                    <th>角色</th>
                    <th>项目范围</th>
                    <th>登录安全</th>
                    <th>账号状态</th>
                    <th>管理</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedUsers.map((user) => (
                    <tr key={user.id}>
                      <td>
                        <div className="device-name">
                          <strong>{user.displayName}</strong>
                          {user.id === currentUser?.id && (
                            <span>当前登录账号</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="account-identity">
                          <code>{user.username}</code>
                          <span>{user.email || "尚未绑定邮箱"}</span>
                        </div>
                      </td>
                      <td>
                        <Tag
                          tone={
                            user.role === "system_admin"
                              ? "violet"
                              : user.role === "project_admin"
                                ? "blue"
                                : "gray"
                          }
                        >
                          {roleLabels[user.role]}
                        </Tag>
                      </td>
                      <td>
                        {user.role === "system_admin"
                          ? "全部项目"
                          : user.projectIds.map(projectName).join("、") ||
                            "未授权"}
                      </td>
                      <td>
                        <div className="account-security-state">
                          <Tag tone={user.mfaEnabled ? "green" : "amber"}>
                            {user.mfaEnabled
                              ? "双重认证已启用"
                              : "双重认证未绑定"}
                          </Tag>
                          {user.passwordChangeRequired && (
                            <span>下次登录进入首次设置向导</span>
                          )}
                        </div>
                      </td>
                      <td>
                        <button
                          aria-label={`切换 ${user.displayName} 账号`}
                          className={`switch ${user.enabled ? "on" : ""}`}
                          onClick={() =>
                            void onToggle(user, !user.enabled)
                              .then(() =>
                                onToast(
                                  `${user.displayName}账号已${!user.enabled ? "启用" : "停用"}`,
                                ),
                              )
                              .catch((error) =>
                                onToast(
                                  error instanceof Error
                                    ? error.message
                                    : "账号状态更新失败",
                                ),
                              )
                          }
                        >
                          <i />
                        </button>
                      </td>
                      <td>
                        <div className="row-actions">
                          <button onClick={() => onEdit(user.id)}>
                            编辑用户
                          </button>
                          {user.id !== currentUser?.id && user.mfaEnabled && (
                            <ConfirmButton
                              label="重置双重认证"
                              confirmLabel="确认重置？"
                              onConfirm={() =>
                                void onResetMFA(user)
                                  .then(() =>
                                    onToast(
                                      `${user.displayName}的双重认证已重置，下次登录需重新设置`,
                                    ),
                                  )
                                  .catch((error) =>
                                    onToast(
                                      error instanceof Error
                                        ? error.message
                                        : "双重认证重置失败",
                                    ),
                                  )
                              }
                            />
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PaginationFooter
              total={visible.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              noun="名用户"
            />
          </>
        ) : (
          <EmptyState
            title="没有匹配的用户"
            detail="请调整用户名、邮箱、角色或项目关键词"
            onClear={() => setQuery("")}
          />
        )}
      </div>
    </>
  );
}

function PoliciesView({
  policies,
  projects,
  onCreate,
  onEdit,
  onToggle,
  onToast,
}: {
  policies: APIAccessPolicy[];
  projects: ProjectView[];
  onCreate: () => void;
  onEdit: (name: string) => void;
  onToggle: (policy: APIAccessPolicy, enabled: boolean) => Promise<void>;
  onToast: (value: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const scope = (policy: APIAccessPolicy) =>
    policy.projectIds
      .map((id) => projects.find((project) => project.id === id)?.name || id)
      .join("、") || "无项目";
  const capabilityName = (capability: string) =>
    capability === "web"
      ? "Web 后台"
      : capability === "webssh"
        ? "WebSSH"
        : capability;
  const visiblePolicies = policies.filter((policy) =>
    `${policy.name}${scope(policy)}${policy.capabilities.join(" ")}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visiblePolicies.length / pageSize)),
  );
  const pagedPolicies = visiblePolicies.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">安全中心</div>
          <h1>访问策略</h1>
          <p>为临时用户授权指定项目的 Web 后台或 WebSSH 访问</p>
        </div>
        <button className="btn primary" onClick={onCreate}>
          ＋ 创建策略
        </button>
      </div>
      <div className="management-bar">
        <div className="table-search">
          <span>⌕</span>
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
            placeholder="搜索策略名称、项目范围或授权能力"
          />
        </div>
        <span>共 {visiblePolicies.length} 条策略</span>
      </div>
      <div className="policy-layout">
        <div className="policy-list">
          {visiblePolicies.length ? (
            pagedPolicies.map((policy) => (
              <div className="policy-card" key={policy.id}>
                <div className="policy-icon teal">▤</div>
                <div>
                  <div className="policy-title">
                    <h3>{policy.name}</h3>
                    <Tag tone={policy.enabled ? "green" : "gray"}>
                      {policy.enabled ? "已启用" : "已停用"}
                    </Tag>
                  </div>
                  <p>{policy.capabilities.map(capabilityName).join(" · ")}</p>
                  <div className="policy-meta">
                    <span>
                      作用范围 <strong>{scope(policy)}</strong>
                    </span>
                    <span>
                      授权用户 <strong>{policy.userIds.length} 人</strong>
                    </span>
                  </div>
                </div>
                <div className="policy-actions">
                  <button
                    aria-label={`切换 ${policy.name} 策略`}
                    className={`switch ${policy.enabled ? "on" : ""}`}
                    onClick={() =>
                      void onToggle(policy, !policy.enabled)
                        .then(() =>
                          onToast(
                            `${policy.name}已${policy.enabled ? "停用" : "启用"}`,
                          ),
                        )
                        .catch((error) =>
                          onToast(
                            error instanceof Error
                              ? error.message
                              : "策略状态更新失败",
                          ),
                        )
                    }
                  >
                    <i />
                  </button>
                  <button onClick={() => onEdit(policy.name)}>
                    编辑策略 →
                  </button>
                </div>
              </div>
            ))
          ) : (
            <EmptyState
              title="没有匹配的访问策略"
              detail="请调整策略名称、项目或能力关键词"
              onClear={() => setQuery("")}
            />
          )}
          {visiblePolicies.length > 0 && (
            <PaginationFooter
              total={visiblePolicies.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              noun="条策略"
            />
          )}
        </div>
        <div className="policy-side">
          <div className="shield">✓</div>
          <h2>默认拒绝</h2>
          <p>临时用户未被有效策略授权时，无法建立 Web 后台或 WebSSH 会话。</p>
          <div>
            <span>已启用策略</span>
            <strong>
              {policies.filter((policy) => policy.enabled).length}
            </strong>
          </div>
          <i>
            <em
              style={{
                width: policies.length
                  ? `${Math.round((policies.filter((policy) => policy.enabled).length / policies.length) * 100)}%`
                  : "0%",
              }}
            />
          </i>
          <Tag tone="gray">仅适用于临时用户</Tag>
        </div>
      </div>
    </>
  );
}

function MonitorView({
  nodes,
  snapshot,
  loading,
  sessions,
  users,
  projects,
  onRefresh,
  onRevoke,
  onToast,
}: {
  nodes: NodeView[];
  snapshot: APIMonitorSnapshot | null;
  loading: boolean;
  sessions: APIAccessSession[];
  users: APIUser[];
  projects: ProjectView[];
  onRefresh: () => Promise<void>;
  onRevoke: (id: string) => Promise<void>;
  onToast: (value: string) => void;
}) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const userName = (id: string | null) =>
    users.find((user) => user.id === id)?.displayName ||
    (id ? "已删除用户" : "平台令牌");
  const projectName = (id: string) =>
    projects.find((project) => project.id === id)?.name || id;
  const nodeSnapshots = snapshot?.nodes || [];
  const collectedAt = snapshot
    ? new Date(snapshot.collectedAt).toLocaleString("zh-CN")
    : "尚未采集";
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(sessions.length / pageSize)),
  );
  const pagedSessions = sessions.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">运行中心</div>
          <h1>系统监控</h1>
          <p>平台、接入节点、托管通道与远程会话当前状态</p>
        </div>
        <div className="heading-actions">
          <Tag tone={snapshot ? "green" : "gray"}>
            {loading ? "正在采集" : "实时快照"}
          </Tag>
          <button
            className="btn secondary"
            disabled={loading}
            onClick={() => void onRefresh()}
          >
            {loading ? "刷新中…" : "刷新快照"}
          </button>
        </div>
      </div>
      <div className="metrics">
        <Metric
          label="平台状态"
          value={
            snapshot?.databaseStatus === "ready"
              ? "就绪"
              : snapshot
                ? "异常"
                : "采集中"
          }
          detail="SQLite 就绪状态"
          tone="green"
        />
        <Metric
          label="可达节点"
          value={
            snapshot ? `${snapshot.nodeReachable}/${snapshot.nodeTotal}` : "—"
          }
          detail="通过节点通道接口验证"
          tone="blue"
        />
        <Metric
          label="当前会话"
          value={String(snapshot?.activeSessions ?? sessions.length)}
          detail="可由管理员强制终止"
          tone="violet"
        />
        <Metric
          label="累计流量"
          value={
            snapshot
              ? formatBytes(snapshot.inletFlow + snapshot.exportFlow)
              : "—"
          }
          detail="节点托管通道累计计数"
          tone="amber"
        />
      </div>
      <div className="monitor-grid">
        <div className="monitor-chart">
          <div className="monitor-head">
            <div>
              <h2>远程访问实时指标</h2>
              <p>来自节点托管通道计数器与平台数据库 · {collectedAt}</p>
            </div>
          </div>
          {snapshot ? (
            <div className="monitor-current-grid">
              <div>
                <span>托管通道</span>
                <strong>
                  {snapshot.tunnelRunning} / {snapshot.tunnelTotal}
                </strong>
                <small>运行中 / 总数</small>
              </div>
              <div>
                <span>入口流量</span>
                <strong>{formatBytes(snapshot.inletFlow)}</strong>
                <small>节点累计计数</small>
              </div>
              <div>
                <span>出口流量</span>
                <strong>{formatBytes(snapshot.exportFlow)}</strong>
                <small>节点累计计数</small>
              </div>
              <div>
                <span>原生转发</span>
                <strong>{snapshot.runningPortForwards}</strong>
                <small>平台运行中任务</small>
              </div>
            </div>
          ) : (
            <EmptyState
              title={loading ? "正在采集运行快照" : "运行快照暂不可用"}
              detail="可点击刷新重新读取节点与平台状态"
            />
          )}
        </div>
        <div className="node-health">
          <div className="monitor-head">
            <div>
              <h2>节点健康度</h2>
              <p>每次刷新都实际读取节点托管通道接口</p>
            </div>
          </div>
          {nodeSnapshots.length ? (
            nodeSnapshots.map((node) => {
              const configured = nodes.find((item) => item.id === node.nodeId);
              const label =
                node.status === "healthy"
                  ? "可达"
                  : node.status === "maintenance"
                    ? "维护中"
                    : node.status === "unavailable"
                      ? "未启用"
                      : "不可达";
              return (
                <div className="health-row" key={node.nodeId}>
                  <div>
                    <span className="node-icon small">N</span>
                    <div>
                      <strong>{node.name}</strong>
                      <small>{configured?.host || node.message}</small>
                    </div>
                  </div>
                  <Tag
                    tone={
                      node.reachable
                        ? "green"
                        : node.status === "maintenance"
                          ? "gray"
                          : "amber"
                    }
                  >
                    {label}
                  </Tag>
                  <div className="health-stats">
                    <span>
                      延迟{" "}
                      <b>{node.reachable ? `${node.latencyMs} ms` : "—"}</b>
                    </span>
                    <span>
                      通道{" "}
                      <b>
                        {node.runningTunnels}/{node.tunnelCount}
                      </b>
                    </span>
                    <span>
                      流量{" "}
                      <b>{formatBytes(node.inletFlow + node.exportFlow)}</b>
                    </span>
                  </div>
                </div>
              );
            })
          ) : (
            <EmptyState
              title={loading ? "正在检查节点" : "暂无接入节点"}
              detail={
                loading
                  ? "节点请求设置了 15 秒超时，不会无限等待"
                  : "添加节点后显示真实健康状态"
              }
            />
          )}
        </div>
      </div>
      <div className="content-card">
        <div className="card-header">
          <div>
            <h2>活动访问会话</h2>
            <p>会话令牌、Web 网关和 WebSSH 网关由平台管理；终止后立即吊销</p>
          </div>
          <Tag tone="green">{sessions.length} 个活动会话</Tag>
        </div>
        {sessions.length ? (
          <>
            <div className="table-wrap">
              <table className="device-table">
                <thead>
                  <tr>
                    <th>会话</th>
                    <th>用户</th>
                    <th>项目</th>
                    <th>目标</th>
                    <th>类型</th>
                    <th>来源 IP</th>
                    <th>到期</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedSessions.map((session) => (
                    <tr key={session.id}>
                      <td>
                        <code>{session.id.slice(0, 8)}</code>
                      </td>
                      <td>
                        <strong>{userName(session.userId)}</strong>
                      </td>
                      <td>{projectName(session.projectId)}</td>
                      <td>
                        {session.deviceName} · {session.endpointName}
                      </td>
                      <td>
                        <Tag tone={session.mode === "ssh" ? "blue" : "violet"}>
                          {session.mode === "ssh" ? "WebSSH" : "Web"}
                        </Tag>
                      </td>
                      <td>
                        <code>{session.sourceIp}</code>
                      </td>
                      <td>
                        {new Date(session.expiresAt).toLocaleString("zh-CN")}
                      </td>
                      <td>
                        <ConfirmButton
                          className="danger-link"
                          label="终止会话"
                          confirmLabel="确认终止？"
                          onConfirm={() =>
                            void onRevoke(session.id)
                              .then(() =>
                                onToast(`${session.id.slice(0, 8)} 已终止`),
                              )
                              .catch((error) =>
                                onToast(
                                  error instanceof Error
                                    ? error.message
                                    : "终止会话失败",
                                ),
                              )
                          }
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PaginationFooter
              total={sessions.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              noun="个会话"
            />
          </>
        ) : (
          <EmptyState
            title="暂无活动访问会话"
            detail="新的 Web 或 WebSSH 会话建立后会显示在这里"
          />
        )}
      </div>
    </>
  );
}

function ProjectAccessSummary({
  project,
  socksRunning,
  canManage,
  onImport,
  onAdd,
  onToast,
  onNetworksChange,
}: {
  project: ProjectView;
  socksRunning: boolean;
  canManage: boolean;
  onImport: () => void;
  onAdd: () => void;
  onToast: (value: string) => void;
  onNetworksChange: (networks: string[]) => Promise<void>;
}) {
  const [scopes, setScopes] = useState(project.networks.join(", "));
  const [verified, setVerified] = useState(true);
  const [saving, setSaving] = useState(false);
  const isValidCidr = (value: string) => {
    const match = value
      .trim()
      .match(/^(\d{1,3})(?:\.(\d{1,3})){3}\/(\d|[12]\d|3[0-2])$/);
    if (!match) return false;
    return value
      .trim()
      .split("/")[0]
      .split(".")
      .every((part) => Number(part) <= 255);
  };
  const save = async () => {
    const networks = parseIPv4Cidrs(scopes);
    if (!networks.length || !networks.every(isValidCidr)) {
      setVerified(false);
      onToast("网段格式无效，请使用 IPv4 CIDR，例如 192.168.10.0/24");
      return;
    }
    setSaving(true);
    try {
      await onNetworksChange(networks);
      setVerified(true);
      onToast(`${project.name}：${networks.length} 个网段已保存`);
    } catch (error) {
      setVerified(false);
      onToast(error instanceof Error ? error.message : "网段保存失败");
    } finally {
      setSaving(false);
    }
  };
  return (
    <section className="project-access-summary">
      <div className="project-access-head">
        <div>
          <h2>网络与访问</h2>
          <p>关联 Client、托管通道和设备发现范围</p>
        </div>
        {canManage && (
          <div>
            <button className="btn secondary" onClick={onImport}>
              ⇧ 批量导入
            </button>
            <button className="btn primary" onClick={onAdd}>
              ＋ 添加设备
            </button>
          </div>
        )}
      </div>
      <div className="project-access-grid">
        <div className="access-fact">
          <span>关联 Client</span>
          <strong>Client ID {project.clientId}</strong>
          <small>
            {project.node} · {project.clientStatus}
          </small>
        </div>
        <div className="access-fact access-channel">
          <span className="label-with-help">
            托管 SOCKS{" "}
            <HelpTip text="只供平台远程访问服务使用。普通用户和浏览器不会直接获得地址或认证信息；启停请在托管通道页面操作。" />
          </span>
          <div>
            <strong>Client ID {project.clientId}</strong>
            <Tag tone={socksRunning ? "green" : "gray"}>
              {socksRunning ? "运行中" : "已关闭"}
            </Tag>
          </div>
          <small>
            {socksRunning ? "节点当前正在监听" : "远程访问时平台自动开启"}
          </small>
        </div>
        <div className="access-scope">
          <div>
            <span className="label-with-help">
              设备发现网段{" "}
              <HelpTip text="只控制内网设备发现功能扫描哪些 IPv4 网段，不限制手工添加、已登记设备或远程访问。" />
            </span>
            <Tag tone={verified ? "green" : "amber"}>
              {verified ? "已保存" : "待保存"}
            </Tag>
          </div>
          <label>
            <input
              aria-label="项目设备发现网段"
              value={scopes}
              readOnly={!canManage || saving}
              onChange={(event) => {
                setScopes(event.target.value);
                setVerified(false);
              }}
            />
            {canManage && (
              <button
                className="btn secondary"
                disabled={saving}
                onClick={() => void save()}
              >
                {saving ? "正在保存…" : "保存网段"}
              </button>
            )}
          </label>
          <small>
            多个 CIDR 可用逗号或换行分隔；不会影响已登记设备的 Web 或 SSH 访问
          </small>
        </div>
      </div>
    </section>
  );
}

function ProjectTabs({
  project,
  active,
  canManage,
  onChange,
  onEdit,
}: {
  project: ProjectView;
  active: "workspace" | "discovery" | "connections";
  canManage: boolean;
  onChange: (view: View) => void;
  onEdit: () => void;
}) {
  const tabs = [
    { id: "workspace" as const, label: "内网设备", icon: "▣" },
    { id: "discovery" as const, label: "设备发现", icon: "⌁" },
    { id: "connections" as const, label: "端口转发", icon: "⊙" },
  ].filter((tab) => canManage || tab.id === "workspace");
  return (
    <>
      <div className="project-context-bar">
        <div className="project-context-identity">
          <span>{project.name.slice(0, 2)}</span>
          <div>
            <strong>{project.name}</strong>
            <small>
              {project.code} · {project.owner}
            </small>
          </div>
        </div>
        <div className="project-context-meta">
          <span>
            接入节点 <strong>{project.node}</strong>
          </span>
          <Tag tone={project.clientStatus === "在线" ? "green" : "amber"}>
            Client {project.clientStatus}
          </Tag>
          {canManage && (
            <button
              className="btn secondary project-settings-button"
              onClick={onEdit}
            >
              项目设置
            </button>
          )}
        </div>
      </div>
      <div className="project-tabs">
        <nav aria-label="项目功能">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              className={active === tab.id ? "active" : ""}
              onClick={() => onChange(tab.id)}
            >
              <i>{tab.icon}</i>
              {tab.label}
            </button>
          ))}
        </nav>
      </div>
    </>
  );
}

function AccessPortal({
  devices,
  projects,
  user,
  onWeb,
  onSsh,
}: {
  devices: Device[];
  projects: ProjectView[];
  user: APIUser | null;
  onWeb: (device: Device, webUrl?: string) => void;
  onSsh: (device: Device) => void;
}) {
  const [query, setQuery] = useState("");
  const [projectFilter, setProjectFilter] = useState("全部项目");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const authorizedProjects = projects;
  const authorizedProjectCodes = new Set(
    authorizedProjects.map((project) => project.code),
  );
  const portalDevices = devices
    .filter((device) => authorizedProjectCodes.has(device.projectCode))
    .map((device) => ({
      ...device,
      projectName:
        projects.find((item) => item.code === device.projectCode)?.name ||
        "未知项目",
    }));
  const visible = portalDevices.filter((device) => {
    const services = [
      ...device.webServices.map((service) => `${service.name} ${service.url}`),
      ...(device.serviceEndpoints || []).map(
        (service) => `${service.name} ${service.protocol} ${service.port}`,
      ),
    ].join(" ");
    return (
      `${device.name} ${device.host} ${device.vendor} ${device.projectName} ${services}`
        .toLowerCase()
        .includes(query.toLowerCase()) &&
      (projectFilter === "全部项目" || device.projectName === projectFilter)
    );
  });
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visible.length / pageSize)),
  );
  const pagedDevices = visible.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  return (
    <>
      <div className="portal-welcome">
        <div>
          <span className="eyebrow">I5CLOUD ACCESS PORTAL</span>
          <h1>我的远程访问</h1>
          <p>集中访问已授权项目的设备后台、WebSSH 和远程服务</p>
        </div>
        <div className="portal-user">
          <span>{(user?.displayName || "用户").slice(0, 1)}</span>
          <div>
            <strong>{user?.displayName || user?.username || "当前用户"}</strong>
            <small>
              已授权 {authorizedProjects.length} 个项目 · {portalDevices.length}{" "}
              台设备
            </small>
          </div>
        </div>
      </div>
      <div className="management-bar portal-tools">
        <div className="table-search">
          <span>⌕</span>
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
            placeholder="搜索设备、IP、项目或服务"
          />
        </div>
        <select
          value={projectFilter}
          onChange={(event) => {
            setProjectFilter(event.target.value);
            setPage(1);
          }}
        >
          <option>全部项目</option>
          {authorizedProjects.map((project) => (
            <option key={project.code}>{project.name}</option>
          ))}
        </select>
        <span>{visible.length} 台匹配设备</span>
      </div>
      {visible.length ? (
        <div className="content-card portal-list-card">
          <div className="table-wrap">
            <table className="device-table portal-list-table">
              <thead><tr><th>设备</th><th>所属项目</th><th>内网地址</th><th>状态</th><th>Web 服务</th><th>WebSSH</th><th>访问入口</th></tr></thead>
              <tbody>{pagedDevices.map((device) => (
                <tr key={device.id}>
                  <td><div className="overview-device-name"><span className="mini-monitor">▣</span><div><strong>{device.name}</strong><small>{device.vendor || "未识别设备"}</small></div></div></td>
                  <td><span className="project-cell"><i />{device.projectName}</span></td>
                  <td><code>{device.host}</code></td>
                  <td><StatusDot status={device.status} /></td>
                  <td><strong>{device.webServices.length}</strong><small className="table-subtext"> 个入口</small></td>
                  <td>{device.ssh ? <Tag tone="blue">SSH · {device.sshPort}</Tag> : <span className="empty-cell">—</span>}</td>
                  <td><div className="portal-row-actions">{device.webServices.map((service) => <button key={service.url} className="action-web" onClick={() => onWeb(device, service.url)}>{service.name} ↗</button>)}{device.ssh && <button onClick={() => onSsh(device)}>WebSSH →</button>}{!device.webServices.length && !device.ssh && <span className="empty-cell">暂无入口</span>}</div></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <PaginationFooter
            total={visible.length}
            page={safePage}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            noun="台设备"
          />
        </div>
      ) : (
        <EmptyState
          title="没有匹配的授权设备"
          detail="请调整项目或设备关键词"
          onClear={() => {
            setQuery("");
            setProjectFilter("全部项目");
          }}
        />
      )}
    </>
  );
}

function Workspace({
  devices,
  project,
  query,
  setQuery,
  socksRunning,
  canManage,
  onWeb,
  onSsh,
  onAdd,
  onImport,
  onManage,
  onVerify,
  onToast,
  onNetworksChange,
}: {
  devices: Device[];
  project: ProjectView;
  query: string;
  setQuery: (value: string) => void;
  socksRunning: boolean;
  canManage: boolean;
  onWeb: (device: Device, webUrl?: string) => void;
  onSsh: (device: Device) => void;
  onAdd: () => void;
  onImport: () => void;
  onManage: (device: Device) => void;
  onVerify: (device: Device) => Promise<{ verified: number; failed: number }>;
  onToast: (value: string) => void;
  onNetworksChange: (networks: string[]) => Promise<void>;
}) {
  const [onlyOnline, setOnlyOnline] = useState(false);
  const [verifyingDevice, setVerifyingDevice] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const matchingDevices = devices.filter((device) =>
    `${device.name}${device.host}${device.type}${device.vendor}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const visibleDevices = onlyOnline
    ? matchingDevices.filter((device) => device.status === "online")
    : matchingDevices;
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visibleDevices.length / pageSize)),
  );
  const pagedDevices = visibleDevices.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  return (
    <>
      <ProjectAccessSummary
        key={project.code}
        project={project}
        socksRunning={socksRunning}
        canManage={canManage}
        onImport={onImport}
        onAdd={onAdd}
        onToast={onToast}
        onNetworksChange={onNetworksChange}
      />

      <div className="metrics">
        <Metric
          label="当前设备"
          value={String(devices.length)}
          detail={`项目登记 ${project.devices} 台`}
          tone="blue"
        />
        <Metric
          label="在线设备"
          value={String(
            devices.filter((device) => device.status === "online").length,
          )}
          detail="按设备实际状态"
          tone="green"
        />
        <Metric
          label="Web 入口"
          value={String(
            devices.reduce(
              (total, device) => total + device.webServices.length,
              0,
            ),
          )}
          detail="全部经托管 SOCKS"
          tone="violet"
        />
        <Metric
          label="SSH 服务"
          value={String(devices.filter((device) => device.ssh).length)}
          detail="支持独立目标端口"
          tone="amber"
        />
      </div>

      <div className="content-card">
        <div className="card-header">
          <div>
            <h2>设备列表</h2>
            <p>Web 后台与 WebSSH 均通过项目托管 SOCKS 访问</p>
          </div>
          <div className="table-tools">
            <div className="table-search">
              <span>⌕</span>
              <input
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
                placeholder="搜索设备或 IP"
              />
            </div>
            <button
              className={`filter-button ${onlyOnline ? "selected" : ""}`}
              onClick={() => {
                setOnlyOnline(!onlyOnline);
                setPage(1);
              }}
            >
              {onlyOnline ? "仅在线 ✓" : "全部状态⌄"}
            </button>
          </div>
        </div>
        {visibleDevices.length ? (
          <>
            <div className="table-wrap">
              <table className="device-table">
                <thead>
                  <tr>
                    <th>设备</th>
                    <th>内网地址</th>
                    <th>类型</th>
                    <th>
                      <span className="label-with-help">
                        状态{" "}
                        <HelpTip text="手工添加的设备初始为待检测。点击该设备的检测服务后，平台只通过项目托管通道探测已经登记的端口。" />
                      </span>
                    </th>
                    <th>
                      <span className="label-with-help">
                        访问入口{" "}
                        <HelpTip text="该列只汇总设备已经登记的 Web 与 SSH 服务数量，不代表已创建端口转发。" />
                      </span>
                    </th>
                    <th>最后活动</th>
                    <th className="remote-actions-column">
                      <span className="label-with-help">
                        远程访问{" "}
                        <HelpTip text="打开独立标签页，经平台远程访问服务和项目托管通道访问设备，不会新建 Web 端口转发。" />
                      </span>
                    </th>
                    {canManage && (
                      <th className="manage-column">
                        <span className="label-with-help">
                          配置{" "}
                          <HelpTip text="修改设备信息、多个 Web 服务入口与 SSH 目标端口；不会直接发起远程访问。" />
                        </span>
                      </th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {pagedDevices.map((device) => (
                    <tr key={device.id}>
                      <td>
                        <div
                          className={`device-symbol device-${device.type === "视频监控" ? "camera" : device.type === "网络设备" ? "network" : device.type === "工业控制" ? "plc" : "access"}`}
                        >
                          {device.type === "视频监控"
                            ? "◉"
                            : device.type === "网络设备"
                              ? "⌘"
                              : device.type === "工业控制"
                                ? "▤"
                                : "▣"}
                        </div>
                        <div className="device-name">
                          <strong>{device.name}</strong>
                          <span>{device.vendor}</span>
                        </div>
                      </td>
                      <td>
                        <code>{device.host}</code>
                      </td>
                      <td>
                        <Tag>{device.type}</Tag>
                      </td>
                      <td>
                        <div className="device-status-actions">
                          <StatusDot status={device.status} />
                          {canManage && (
                            <button
                              type="button"
                              disabled={verifyingDevice !== null}
                              onClick={async () => {
                                const deviceID = String(device.id);
                                setVerifyingDevice(deviceID);
                                try {
                                  const result = await onVerify(device);
                                  onToast(
                                    `${device.name}检测完成：${result.verified} 个服务可达，${result.failed} 个失败`,
                                  );
                                } catch (error) {
                                  onToast(
                                    error instanceof Error
                                      ? error.message
                                      : "设备检测失败",
                                  );
                                } finally {
                                  setVerifyingDevice(null);
                                }
                              }}
                            >
                              {verifyingDevice === String(device.id)
                                ? "检测中…"
                                : "检测服务"}
                            </button>
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="entry-tags">
                          {device.webServices.length > 0 && (
                            <Tag tone="violet">
                              WEB · {device.webServices.length} 个
                            </Tag>
                          )}
                          {device.ssh && (
                            <Tag tone="blue">SSH · {device.sshPort}</Tag>
                          )}
                          {device.services >
                            device.webServices.length + Number(device.ssh) && (
                            <span
                              title={(device.serviceEndpoints || [])
                                .filter(
                                  (service) =>
                                    !["http", "https", "ssh"].includes(
                                      service.protocol,
                                    ),
                                )
                                .map(
                                  (service) =>
                                    `${service.name}:${service.port}`,
                                )
                                .join(" · ")}
                            >
                              <Tag tone="gray">
                                其它 ·{" "}
                                {device.services -
                                  device.webServices.length -
                                  Number(device.ssh)}
                              </Tag>
                            </span>
                          )}
                        </div>
                      </td>
                      <td>
                        <span className="last-seen">{device.lastSeen}</span>
                      </td>
                      <td>
                        <div className="row-actions service-actions">
                          {device.webServices.map((service) => (
                            <button
                              key={service.url}
                              className="action-web"
                              onClick={() => onWeb(device, service.url)}
                              title={service.url}
                            >
                              {service.name} ↗
                            </button>
                          ))}
                          {device.ssh && (
                            <button onClick={() => onSsh(device)}>
                              WebSSH
                            </button>
                          )}
                          {!device.webServices.length && !device.ssh && (
                            <span className="no-remote-entry">暂无入口</span>
                          )}
                        </div>
                      </td>
                      {canManage && (
                        <td className="manage-cell">
                          <button
                            aria-label={`管理设备：${device.name}`}
                            onClick={() => onManage(device)}
                          >
                            管理
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PaginationFooter
              total={visibleDevices.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              noun="台设备"
            />
          </>
        ) : (
          <EmptyState
            title="没有匹配的设备"
            detail="请调整设备关键词或状态筛选"
            onClear={() => {
              setQuery("");
              setOnlyOnline(false);
            }}
          />
        )}
      </div>
    </>
  );
}

function NodesView({
  nodes,
  usedPorts,
  onCreate,
  onOpen,
  onManage,
  onRefresh,
}: {
  nodes: NodeView[];
  usedPorts: number;
  onCreate: () => void;
  onOpen: (node: NodeView) => void;
  onManage: (name: string) => void;
  onRefresh: (node: NodeView) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("全部状态");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const availableNodes = nodes.filter(
    (node) => node.status === "运行正常",
  ).length;
  const totalClients = nodes.reduce((total, node) => total + node.clients, 0);
  const activeTunnels = nodes.reduce(
    (total, node) => total + node.runningTunnels,
    0,
  );
  const visibleNodes = nodes.filter(
    (node) =>
      `${node.name}${node.host}${node.tlsName}`
        .toLowerCase()
        .includes(query.toLowerCase()) &&
      (statusFilter === "全部状态" ||
        (statusFilter === "可用"
          ? node.status === "运行正常"
          : node.status !== "运行正常")),
  );
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visibleNodes.length / pageSize)),
  );
  const pagedNodes = visibleNodes.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">基础设施</div>
          <h1>接入节点</h1>
          <p>统一管理节点 API、TLS 与端口资源</p>
        </div>
        <button className="btn primary" onClick={onCreate}>
          ＋ 添加节点
        </button>
      </div>
      <div className="metrics">
        <Metric
          label="节点总数"
          value={String(nodes.length)}
          detail={`${availableNodes} 个节点可用`}
          tone="blue"
        />
        <Metric
          label="节点 Client"
          value={String(totalClients)}
          detail="节点接口实时统计"
          tone="green"
        />
        <Metric
          label="活跃 SOCKS"
          value={String(activeTunnels)}
          detail={`${nodes.reduce((total, node) => total + node.tunnels, 0)} 个托管通道`}
          tone="violet"
        />
        <Metric
          label="已用端口"
          value={String(usedPorts)}
          detail="平台登记的转发端口"
          tone="amber"
        />
      </div>
      <div className="management-bar">
        <div className="table-search">
          <span>⌕</span>
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
            placeholder="搜索节点名称、地址或 TLS 主机名"
          />
        </div>
        <select
          value={statusFilter}
          onChange={(event) => {
            setStatusFilter(event.target.value);
            setPage(1);
          }}
        >
          <option>全部状态</option>
          <option>可用</option>
          <option>维护中</option>
        </select>
        <span>共 {visibleNodes.length} 个节点</span>
      </div>
      {visibleNodes.length ? (
        <div className="content-card node-list-card">
          <div className="table-wrap">
            <table className="device-table node-list-table">
              <thead>
                <tr>
                  <th>节点</th>
                  <th>API 地址</th>
                  <th>域名</th>
                  <th>状态</th>
                  <th>项目</th>
                  <th>Client</th>
                  <th>托管通道</th>
                  <th>API 延迟</th>
                  <th>端口池</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {pagedNodes.map((node) => {
                  const index = nodes.indexOf(node);
                  const runningRatio = node.tunnels
                    ? Math.round(
                        (node.runningTunnels / node.tunnels) * 100,
                      )
                    : 0;
                  return (
                    <tr key={node.name}>
                      <td>
                        <button
                          className="node-list-identity"
                          aria-label={`查看 ${node.name} Client`}
                          onClick={() => onOpen(node)}
                        >
                          <span className="node-icon small">N{index + 1}</span>
                          <strong>{node.name}</strong>
                        </button>
                      </td>
                      <td>
                        <code>{node.host}</code>
                      </td>
                      <td>
                        <span className="node-list-domain">
                          {node.tlsName || "—"}
                        </span>
                      </td>
                      <td>
                        <Tag
                          tone={
                            node.status === "运行正常" ? "green" : "amber"
                          }
                        >
                          {node.status}
                        </Tag>
                      </td>
                      <td>
                        <strong>{node.projects}</strong>
                      </td>
                      <td>
                        <strong>{node.clients}</strong>
                      </td>
                      <td>
                        <div className="node-tunnel-cell">
                          <strong>
                            {node.runningTunnels} / {node.tunnels}
                          </strong>
                          <i>
                            <em style={{ width: `${runningRatio}%` }} />
                          </i>
                        </div>
                      </td>
                      <td>
                        <strong>{node.latency}</strong>
                      </td>
                      <td>
                        <code>{node.ports}</code>
                      </td>
                      <td>
                        <div className="node-list-actions">
                          <button onClick={() => onOpen(node)}>
                            查看 Client
                          </button>
                          <button onClick={() => void onRefresh(node)}>
                            检查连接
                          </button>
                          <button onClick={() => onManage(node.name)}>
                            配置节点
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <PaginationFooter
            total={visibleNodes.length}
            page={safePage}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            noun="个节点"
          />
        </div>
      ) : (
        <EmptyState
          title="没有匹配的接入节点"
          detail="请调整节点关键词或状态筛选"
          onClear={() => {
            setQuery("");
            setStatusFilter("全部状态");
          }}
        />
      )}
    </>
  );
}

function ProjectsView({
  projects,
  canCreate,
  onOpen,
  onCreate,
}: {
  projects: ProjectView[];
  canCreate: boolean;
  onOpen: (project: ProjectView) => void;
  onCreate: () => void;
}) {
  const [query, setQuery] = useState("");
  const [clientStatusFilter, setClientStatusFilter] = useState<
    "全部" | "在线" | "离线"
  >("全部");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const visibleProjects = projects.filter(
    (project) =>
      `${project.name}${project.code}${project.node}${project.owner}`
        .toLowerCase()
        .includes(query.toLowerCase()) &&
      (clientStatusFilter === "全部" ||
        project.clientStatus === clientStatusFilter),
  );
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visibleProjects.length / pageSize)),
  );
  const pagedProjects = visibleProjects.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">客户管理</div>
          <h1>客户项目</h1>
          <p>项目绑定接入节点、Client 与设备发现范围</p>
        </div>
        {canCreate && (
          <button className="btn primary" onClick={onCreate}>
            ＋ 创建项目
          </button>
        )}
      </div>
      <div className="management-bar">
        <div className="table-search">
          <span>⌕</span>
          <input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
            placeholder="搜索项目名称、编号、节点或负责人"
          />
        </div>
        <select
          aria-label="Client 状态"
          value={clientStatusFilter}
          onChange={(event) => {
            setClientStatusFilter(
              event.target.value as typeof clientStatusFilter,
            );
            setPage(1);
          }}
        >
          <option>全部</option>
          <option>在线</option>
          <option>离线</option>
        </select>
        <span>共 {visibleProjects.length} 个项目</span>
      </div>
      {visibleProjects.length ? (
        <div className="content-card project-list-card">
          <div className="table-wrap">
            <table className="project-table">
              <thead>
                <tr>
                  <th>项目名称</th>
                  <th>项目编号</th>
                  <th>Client 状态</th>
                  <th>接入节点</th>
                  <th>负责人</th>
                  <th>设备</th>
                  <th>Web 入口</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {pagedProjects.map((project) => (
                  <tr key={project.code}>
                    <td>
                      <button
                        className="project-name-button"
                        onClick={() => onOpen(project)}
                      >
                        <span className={`project-list-logo ${project.accent}`}>
                          {project.name.slice(0, 2)}
                        </span>
                        <strong>{project.name}</strong>
                      </button>
                    </td>
                    <td>
                      <code>{project.code}</code>
                    </td>
                    <td>
                      <Tag
                        tone={
                          project.clientStatus === "在线" ? "green" : "gray"
                        }
                      >
                        Client {project.clientStatus}
                      </Tag>
                    </td>
                    <td>
                      <strong>{project.node}</strong>
                    </td>
                    <td>{project.owner}</td>
                    <td>
                      <strong>{project.devices}</strong>
                    </td>
                    <td>
                      <strong>{project.web}</strong>
                    </td>
                    <td>
                      <button
                        className="project-open-button"
                        onClick={() => onOpen(project)}
                      >
                        进入项目 →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <PaginationFooter
            total={visibleProjects.length}
            page={safePage}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            noun="条记录"
          />
        </div>
      ) : (
        <EmptyState
          title="没有找到项目"
          detail="请调整项目关键词或 Client 状态"
          onClear={() => {
            setQuery("");
            setClientStatusFilter("全部");
          }}
        />
      )}
    </>
  );
}

function SettingsView({
  security,
  onSecurityChange,
  onToast,
}: {
  security: APISecuritySettings | null;
  onSecurityChange: (value: APISecuritySettings) => void;
  onToast: (value: string) => void;
}) {
  const [draft, setDraft] = useState<APISecuritySettings | null>(security);
  const [saving, setSaving] = useState(false);
  const locked = (field: string) =>
    Boolean(draft?.lockedFields.includes(field));
  const patch = (value: Partial<APISecuritySettings>) =>
    setDraft((current) => (current ? { ...current, ...value } : current));
  const toggleMethod = (method: "totp" | "email") => {
    if (!draft || locked("mfaMethods")) return;
    patch({
      mfaMethods: draft.mfaMethods.includes(method)
        ? draft.mfaMethods.filter((item) => item !== method)
        : [...draft.mfaMethods, method],
    });
  };
  const save = async () => {
    if (!draft) return;
    setSaving(true);
    try {
      const updated = await api.updateSecuritySettings(draft);
      onSecurityChange(updated);
      setDraft(updated);
      onToast(
        updated.restartRequired
          ? "设置已安全保存，重启服务后生效"
          : "设置已保存",
      );
    } catch (error) {
      onToast(error instanceof Error ? error.message : "安全设置保存失败");
    } finally {
      setSaving(false);
    }
  };
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">平台管理</div>
          <h1>系统设置</h1>
          <p>维护登录安全、邮件服务、访问域名与平台数据</p>
        </div>
        <div className="heading-actions">
          <button
            className="btn secondary"
            disabled={!security || saving}
            onClick={() => setDraft(security)}
          >
            放弃修改
          </button>
          <button
            className="btn primary"
            disabled={!draft || saving}
            onClick={() => void save()}
          >
            {saving ? "正在保存…" : "保存系统设置"}
          </button>
        </div>
      </div>
      {draft?.restartRequired && (
        <div className="settings-restart-banner">
          <span>!</span>
          <div>
            <strong>配置已保存，等待重启生效</strong>
            <p>
              当前进程仍使用启动时配置。Docker 部署可执行{" "}
              <code>docker compose restart platform</code>
              ，重启后此提示会自动消失。
            </p>
          </div>
        </div>
      )}
      {!draft && (
        <div className="settings-restart-banner error">
          <span>!</span>
          <div>
            <strong>无法读取安全设置</strong>
            <p>请检查当前账号权限和后端服务状态。</p>
          </div>
        </div>
      )}
      {draft && (
        <div className="settings-editor-grid">
          <section className="settings-card settings-form-card">
            <div>
              <span className="settings-icon">◇</span>
              <div>
                <h2>登录与双重认证</h2>
                <p>控制首次登录和日常二次验证</p>
              </div>
              <Tag tone={draft.mfaEnabled ? "green" : "gray"}>
                {draft.restartRequired
                  ? draft.mfaEnabled
                    ? "计划启用"
                    : "计划关闭"
                  : draft.mfaEnabled
                    ? "已启用"
                    : "未启用"}
              </Tag>
            </div>
            <div className="settings-control-row">
              <div>
                <strong>强制双重认证</strong>
                <small>
                  启用后所有用户首次登录必须改密、验证邮箱并绑定一种二次验证方式
                </small>
              </div>
              <button
                type="button"
                aria-label="强制双重认证"
                disabled={locked("mfaEnabled")}
                className={`switch ${draft.mfaEnabled ? "on" : ""}`}
                onClick={() => patch({ mfaEnabled: !draft.mfaEnabled })}
              >
                <i />
              </button>
            </div>
            <div className="settings-form-section">
              <div className="settings-field-label">
                <span>允许的验证方式</span>
                <HelpTip text="首次登录始终需要验证邮箱；这里决定用户日常登录可选择认证器令牌、邮箱验证码或两者。" />
              </div>
              <div className="settings-choice-row">
                <button
                  type="button"
                  disabled={locked("mfaMethods")}
                  className={
                    draft.mfaMethods.includes("totp") ? "selected" : ""
                  }
                  onClick={() => toggleMethod("totp")}
                >
                  <i>{draft.mfaMethods.includes("totp") ? "✓" : ""}</i>
                  <span>
                    <b>认证器令牌</b>
                    <small>推荐，离线生成动态码</small>
                  </span>
                </button>
                <button
                  type="button"
                  disabled={locked("mfaMethods")}
                  className={
                    draft.mfaMethods.includes("email") ? "selected" : ""
                  }
                  onClick={() => toggleMethod("email")}
                >
                  <i>{draft.mfaMethods.includes("email") ? "✓" : ""}</i>
                  <span>
                    <b>邮箱验证码</b>
                    <small>通过已验证邮箱接收</small>
                  </span>
                </button>
              </div>
            </div>
            <div className="settings-field-grid">
              <label>
                邮箱验证码有效期
                <select
                  disabled={locked("emailCodeTTL")}
                  value={draft.emailCodeTTL}
                  onChange={(event) =>
                    patch({ emailCodeTTL: event.target.value })
                  }
                >
                  <option value="5m">5 分钟</option>
                  <option value="10m">10 分钟</option>
                  <option value="15m">15 分钟</option>
                  <option value="30m">30 分钟</option>
                </select>
              </label>
              <label>
                加密主密钥文件
                <input value={draft.mfaKeyFile} readOnly />
                <small>为避免误操作导致所有 TOTP 失效，网页中只读</small>
              </label>
            </div>
          </section>

          <section className="settings-card settings-form-card">
            <div>
              <span className="settings-icon">✉</span>
              <div>
                <h2>邮箱发件服务</h2>
                <p>用于邮箱绑定和登录验证码</p>
              </div>
              <Tag tone={draft.smtpConfigured ? "green" : "amber"}>
                {draft.smtpConfigured ? "参数完整" : "待配置"}
              </Tag>
            </div>
            <div className="settings-field-grid">
              <label>
                SMTP 主机
                <input
                  disabled={locked("smtpHost")}
                  value={draft.smtpHost}
                  onChange={(event) => patch({ smtpHost: event.target.value })}
                  placeholder="smtp.example.com"
                />
              </label>
              <label>
                SMTP 端口
                <input
                  disabled={locked("smtpPort")}
                  type="number"
                  min="1"
                  max="65535"
                  value={draft.smtpPort}
                  onChange={(event) =>
                    patch({ smtpPort: Number(event.target.value) })
                  }
                />
                <small>
                  {draft.smtpPort === 465
                    ? "自动使用隐式 TLS"
                    : "自动使用 STARTTLS 加密"}
                </small>
              </label>
              <label>
                SMTP 用户名
                <input
                  disabled={locked("smtpUsername")}
                  value={draft.smtpUsername}
                  onChange={(event) =>
                    patch({ smtpUsername: event.target.value })
                  }
                  placeholder="notifier@example.com"
                />
              </label>
              <label>
                SMTP 密码
                <input
                  disabled={locked("smtpPassword") || draft.clearSMTPPassword}
                  type="password"
                  value={draft.smtpPassword || ""}
                  onChange={(event) =>
                    patch({
                      smtpPassword: event.target.value,
                      clearSMTPPassword: false,
                    })
                  }
                  placeholder={
                    draft.clearSMTPPassword
                      ? "保存后清除密码"
                      : draft.smtpPasswordConfigured
                        ? "已配置，留空保持不变"
                        : "输入发件密码"
                  }
                  autoComplete="new-password"
                />
                <small>密码写入数据卷中的 0600 Secret 文件，API 永不回显</small>
                {draft.smtpPasswordConfigured && !locked("smtpPassword") && (
                  <button
                    type="button"
                    className={`secret-clear-button ${draft.clearSMTPPassword ? "selected" : ""}`}
                    onClick={() =>
                      patch({
                        clearSMTPPassword: !draft.clearSMTPPassword,
                        smtpPassword: "",
                      })
                    }
                  >
                    {draft.clearSMTPPassword
                      ? "取消清除密码"
                      : "清除已保存密码"}
                  </button>
                )}
              </label>
              <label className="full">
                发件人
                <input
                  disabled={locked("smtpFrom")}
                  value={draft.smtpFrom}
                  onChange={(event) => patch({ smtpFrom: event.target.value })}
                  placeholder="I5CLOUD <notifier@example.com>"
                />
              </label>
            </div>
          </section>

          <section className="settings-card settings-form-card">
            <div>
              <span className="settings-icon">⌁</span>
              <div>
                <h2>证书与访问域名</h2>
                <p>分别配置面板地址和 Web 会话泛域名</p>
              </div>
              <Tag tone={draft.tlsConfigured ? "green" : "gray"}>
                {draft.tlsConfigured ? "已配置证书" : "未配置证书"}
              </Tag>
            </div>
            <div className="settings-field-grid">
              <label>
                证书文件路径
                <input
                  disabled={locked("tlsCertFile")}
                  value={draft.tlsCertFile}
                  onChange={(event) =>
                    patch({ tlsCertFile: event.target.value })
                  }
                  placeholder="/run/secrets/platform_tls_cert"
                />
              </label>
              <label>
                私钥文件路径
                <input
                  disabled={locked("tlsKeyFile")}
                  value={draft.tlsKeyFile}
                  onChange={(event) =>
                    patch({ tlsKeyFile: event.target.value })
                  }
                  placeholder="/run/secrets/platform_tls_key"
                />
                <small>只保存文件路径，不读取或显示私钥</small>
              </label>
              <label>
                面板地址
                <input
                  disabled={locked("panelDomain")}
                  value={draft.panelDomain}
                  onChange={(event) =>
                    patch({
                      panelDomain: event.target.value
                        .replace(/^https?:\/\//i, "")
                        .replace(/^\*\./, ""),
                    })
                  }
                  placeholder="admin.example.com"
                />
                <small>仅填写域名，不填协议和路径</small>
              </label>
              <label>
                反代地址
                <div className="domain-prefix-input">
                  <span>*.</span>
                  <input
                    disabled={locked("accessDomain")}
                    value={draft.accessDomain}
                    onChange={(event) =>
                      patch({
                        accessDomain: event.target.value.replace(/^\*\./, ""),
                      })
                    }
                    placeholder="admin.example.com"
                  />
                </div>
                <small>每个 Web 访问会话使用独立子域名</small>
              </label>
            </div>
          </section>

          <DataManagementSettings onToast={onToast} />
        </div>
      )}
    </>
  );
}

function DataManagementSettings({
  onToast,
}: {
  onToast: (value: string) => void;
}) {
  return (
    <section className="settings-card data-management-card">
      <div>
        <span className="settings-icon">⇄</span>
        <div>
          <h2>平台数据</h2>
          <p>下载 SQLite 在线一致性快照</p>
        </div>
      </div>
      <div className="data-facts">
        <span>
          <b>SQLite</b>
          <small>单实例 · WAL 模式</small>
        </span>
        <span>
          <b>一致性备份</b>
          <small>通过 SQLite VACUUM INTO 生成</small>
        </span>
      </div>
      <div className="data-management-actions">
        <button
          type="button"
          className="btn primary"
          onClick={() => {
            window.location.href = "/api/v1/data/backup";
            onToast("正在生成并下载一致性备份");
          }}
        >
          下载完整备份
        </button>
      </div>
      <small className="data-warning">
        备份包含平台业务配置、密码哈希和密钥引用，不包含引用指向的明文密钥。恢复属于停机维护操作，部署时使用管理命令执行，避免在线覆盖数据库。
      </small>
    </section>
  );
}

function DiscoveryView({
  project,
  active,
  progress,
  imported,
  ignored,
  candidates,
  onCandidatesChange,
  onIgnoredChange,
  onStart,
  onCancel,
  onImport,
}: {
  project: ProjectView;
  active: boolean;
  progress: number;
  imported: number[];
  ignored: number[];
  candidates: DiscoveryResult[];
  onCandidatesChange: (items: DiscoveryResult[]) => void;
  onIgnoredChange: (items: number[]) => void;
  onStart: (ports: APIDiscoveryPort[]) => Promise<void>;
  onCancel: () => Promise<void>;
  onImport: (index: number, item: DiscoveryResult) => void;
}) {
  const [scanPorts, setScanPorts] = useState<EditableDiscoveryPort[]>(() =>
    DEFAULT_DISCOVERY_PORTS.map((item) => ({ ...item })),
  );
  const [configError, setConfigError] = useState("");
  const [starting, setStarting] = useState(false);
  const [savingPorts, setSavingPorts] = useState(false);
  const [portsDirty, setPortsDirty] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  useEffect(() => {
    if (!project.id) return;
    let cancelled = false;
    void api
      .projectScanPorts(project.id)
      .then((ports) => {
        if (cancelled) return;
        setScanPorts(
          ports.map((port, index) => ({
            ...port,
            id: `${port.protocol}-${port.port}-${index}`,
          })),
        );
        setPortsDirty(false);
      })
      .catch((reason) => {
        if (!cancelled)
          setConfigError(
            reason instanceof Error ? reason.message : "读取项目扫描端口失败",
          );
      });
    return () => {
      cancelled = true;
    };
  }, [project.id]);
  const results = progress === 100 ? candidates : [];
  const updateResult = (index: number, patch: Partial<DiscoveryResult>) =>
    onCandidatesChange(
      candidates.map((item, itemIndex) =>
        itemIndex === index ? { ...item, ...patch } : item,
      ),
    );
  const updateService = (
    resultIndex: number,
    serviceId: string,
    patch: Partial<DiscoveryService>,
  ) =>
    onCandidatesChange(
      candidates.map((item, itemIndex) =>
        itemIndex === resultIndex
          ? {
              ...item,
              services: item.services.map((service) =>
                service.id === serviceId ? { ...service, ...patch } : service,
              ),
            }
          : item,
      ),
    );
  const addService = (resultIndex: number) =>
    onCandidatesChange(
      candidates.map((item, itemIndex) =>
        itemIndex === resultIndex
          ? {
              ...item,
              services: [
                ...item.services,
                {
                  id: `manual-${Date.now()}`,
                  name: `自定义服务 ${item.services.length + 1}`,
                  protocol: "tcp",
                  port: "",
                  evidence: "手动补充",
                  selected: true,
                },
              ],
            }
          : item,
      ),
    );
  const removeService = (resultIndex: number, serviceId: string) =>
    onCandidatesChange(
      candidates.map((item, itemIndex) =>
        itemIndex === resultIndex
          ? {
              ...item,
              services: item.services.filter(
                (service) => service.id !== serviceId,
              ),
            }
          : item,
      ),
    );
  const pendingCount = results.filter(
    (_, index) => !imported.includes(index) && !ignored.includes(index),
  ).length;
  const visibleResults = results
    .map((item, index) => ({ item, index }))
    .filter(({ index }) => !ignored.includes(index));
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visibleResults.length / pageSize)),
  );
  const pagedResults = visibleResults.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  const serviceCount = candidates.reduce(
    (total, item) => total + item.services.length,
    0,
  );
  const startConfiguredScan = async () => {
    if (!project.networks.length) {
      setConfigError("请先在项目设置中填写至少一个扫描内网 IP 段");
      return;
    }
    if (portsDirty) {
      setConfigError("扫描端口已经修改，请先保存后再开始扫描");
      return;
    }
    const ports = scanPorts.map(({ name, protocol, port }) => ({
      name: name.trim(),
      protocol,
      port: Number(port),
    }));
    const invalid = ports.find(
      (item) =>
        !item.name ||
        !Number.isInteger(item.port) ||
        item.port < 1 ||
        item.port > 65535,
    );
    const keys = new Set<string>();
    const duplicate = ports.find((item) => {
      const key = `${item.protocol}:${item.port}`;
      if (keys.has(key)) return true;
      keys.add(key);
      return false;
    });
    if (!ports.length) {
      setConfigError("至少保留一个需要探测的服务端口");
      return;
    }
    if (invalid) {
      setConfigError("每个扫描项都必须填写服务名称和 1-65535 的目标端口");
      return;
    }
    if (duplicate) {
      setConfigError(
        `扫描配置中重复了 ${duplicate.protocol.toUpperCase()} ${duplicate.port}`,
      );
      return;
    }
    setConfigError("");
    setStarting(true);
    try {
      await onStart(ports);
    } finally {
      setStarting(false);
    }
  };
  const saveScanPorts = async () => {
    if (!project.id) {
      setConfigError("项目尚未写入后台");
      return;
    }
    const ports = scanPorts.map(({ name, protocol, port }) => ({
      name: name.trim(),
      protocol,
      port: Number(port),
    }));
    const invalid = ports.find(
      (item) =>
        !item.name ||
        !Number.isInteger(item.port) ||
        item.port < 1 ||
        item.port > 65535,
    );
    const keys = new Set<string>();
    const duplicate = ports.find((item) => {
      const key = `${item.protocol}:${item.port}`;
      if (keys.has(key)) return true;
      keys.add(key);
      return false;
    });
    if (!ports.length) {
      setConfigError("至少保留一个扫描端口");
      return;
    }
    if (invalid) {
      setConfigError("每个扫描项都必须填写服务名称和 1-65535 的目标端口");
      return;
    }
    if (duplicate) {
      setConfigError(
        `扫描配置中重复了 ${duplicate.protocol.toUpperCase()} ${duplicate.port}`,
      );
      return;
    }
    setSavingPorts(true);
    setConfigError("");
    try {
      const saved = await api.updateProjectScanPorts(project.id, ports);
      setScanPorts(
        saved.map((port, index) => ({
          ...port,
          id: `${port.protocol}-${port.port}-${index}`,
        })),
      );
      setPortsDirty(false);
    } catch (reason) {
      setConfigError(
        reason instanceof Error ? reason.message : "保存项目扫描端口失败",
      );
    } finally {
      setSavingPorts(false);
    }
  };
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">
            <span>{project.name}</span>
            <b>/</b>设备发现
          </div>
          <h1>内网设备发现</h1>
          <p>通过项目托管 SOCKS 对项目设置中的内网 IP 段执行协议探测</p>
        </div>
        <button
          className={`btn ${active ? "secondary" : "primary"}`}
          disabled={
            starting || (!active && (!project.networks.length || portsDirty))
          }
          onClick={() =>
            active ? void onCancel() : void startConfiguredScan()
          }
        >
          {active
            ? "× 取消扫描"
            : starting
              ? "正在创建任务…"
              : !project.networks.length
                ? "请先配置扫描网段"
                : portsDirty
                  ? "请先保存扫描端口"
                  : "⌁ 开始扫描"}
        </button>
      </div>
      {!project.networks.length && (
        <div className="route-note discovery-network-required">
          <span>i</span>
          <div>
            <strong>尚未配置扫描内网 IP 段</strong>
            <small>
              点击页面上方“项目设置”，填写一个或多个 IPv4 CIDR 后即可开始扫描。
            </small>
          </div>
        </div>
      )}
      <details
        className="discovery-scan-config"
        open={progress === 0 && !active}
      >
        <summary>
          <div>
            <strong>扫描范围与服务端口</strong>
            <small>
              {project.networks.length} 个扫描网段 · {scanPorts.length}{" "}
              个协议探针
            </small>
          </div>
          <span>{active ? "扫描期间锁定" : "点击展开配置"}⌄</span>
        </summary>
        <div className="discovery-scan-config-body">
          <div className="scan-network-boundary">
            <span className="label-with-help">
              扫描内网 IP 段{" "}
              <HelpTip text="扫描范围来自项目设置中保存的 IPv4 CIDR。" />
            </span>
            <div>
              {project.networks.length ? (
                project.networks.map((network) => (
                  <code key={network}>{network}</code>
                ))
              ) : (
                <small>未配置</small>
              )}
            </div>
          </div>
          <div className="scan-port-editor">
            <div className="scan-port-header">
              <span>服务名称</span>
              <span>协议探针</span>
              <span>目标端口</span>
              <span />
            </div>
            {scanPorts.map((item) => (
              <div className="scan-port-row" key={item.id}>
                <input
                  aria-label={`${item.id} 服务名称`}
                  disabled={active}
                  value={item.name}
                  onChange={(event) => {
                    setPortsDirty(true);
                    setScanPorts((items) =>
                      items.map((port) =>
                        port.id === item.id
                          ? { ...port, name: event.target.value }
                          : port,
                      ),
                    );
                  }}
                  placeholder="例如：AdGuard Home"
                />
                <select
                  aria-label={`${item.name} 协议探针`}
                  disabled={active}
                  value={item.protocol}
                  onChange={(event) => {
                    setPortsDirty(true);
                    setScanPorts((items) =>
                      items.map((port) =>
                        port.id === item.id
                          ? {
                              ...port,
                              protocol: event.target
                                .value as APIDiscoveryPort["protocol"],
                            }
                          : port,
                      ),
                    );
                  }}
                >
                  <option value="auto">自动识别 Web</option>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                  <option value="ssh">SSH</option>
                  <option value="rtsp">RTSP</option>
                  <option value="rdp">RDP</option>
                  <option value="mysql">MySQL</option>
                  <option value="postgresql">PostgreSQL</option>
                  <option value="tcp">TCP Banner</option>
                </select>
                <input
                  aria-label={`${item.name} 扫描端口`}
                  disabled={active}
                  type="number"
                  min="1"
                  max="65535"
                  value={item.port}
                  onChange={(event) => {
                    setPortsDirty(true);
                    setScanPorts((items) =>
                      items.map((port) =>
                        port.id === item.id
                          ? {
                              ...port,
                              port: event.target.value
                                ? Number(event.target.value)
                                : "",
                            }
                          : port,
                      ),
                    );
                  }}
                />
                <button
                  type="button"
                  aria-label={`删除扫描端口 ${item.name}`}
                  disabled={active || scanPorts.length === 1}
                  onClick={() => {
                    setPortsDirty(true);
                    setScanPorts((items) =>
                      items.filter((port) => port.id !== item.id),
                    );
                  }}
                >
                  ×
                </button>
              </div>
            ))}
          </div>
          <div className="scan-config-actions">
            <div>
              <b>按项目保存扫描端口</b>
              <span>
                默认仅扫描 80、443、3000、3001 和
                22；后续新增、修改或删除后需要保存。
              </span>
            </div>
            <div className="scan-config-buttons">
              <button
                type="button"
                className="btn secondary"
                disabled={active}
                onClick={() => {
                  setPortsDirty(true);
                  setScanPorts((items) => [
                    ...items,
                    {
                      id: `custom-${Date.now()}`,
                      name: `自定义服务 ${items.length + 1}`,
                      protocol: "auto",
                      port: 8080,
                    },
                  ]);
                }}
              >
                ＋ 添加扫描端口
              </button>
              <button
                type="button"
                className="btn primary"
                disabled={active || savingPorts || !portsDirty}
                onClick={() => void saveScanPorts()}
              >
                {savingPorts
                  ? "正在保存…"
                  : portsDirty
                    ? "保存扫描端口"
                    : "已保存"}
              </button>
            </div>
          </div>
          {configError && (
            <div className="form-error" role="alert">
              {configError}
            </div>
          )}
        </div>
      </details>
      <div className="scan-panel">
        <div className="scan-visual">
          <div className={`radar ${active ? "scanning" : ""}`}>
            <i />
            <b>⌁</b>
            <span className="ping ping-one" />
            <span className="ping ping-two" />
            <span className="ping ping-three" />
          </div>
        </div>
        <div className="scan-content">
          <div className="scan-title">
            <div>
              <Tag tone={active ? "blue" : progress === 100 ? "green" : "gray"}>
                {active ? "扫描中" : progress === 100 ? "已完成" : "等待任务"}
              </Tag>
              <h2>
                {project.networks.length
                  ? project.networks.join(" · ")
                  : "等待配置扫描网段"}
              </h2>
              <p>项目扫描内网 IP 段</p>
            </div>
            <strong>{progress}%</strong>
          </div>
          <div className="progress">
            <i style={{ width: `${progress}%` }} />
          </div>
          <div className="scan-facts">
            <span>
              网段 <b>{project.networks.length}</b>
            </span>
            <span>
              任务进度 <b>{progress}%</b>
            </span>
            <span>
              已返回设备 <b>{candidates.length}</b>
            </span>
            <span>
              已验证服务 <b>{serviceCount}</b>
            </span>
            <span>
              并发 <b>32</b>
            </span>
          </div>
        </div>
      </div>
      <div className="content-card discovery-results-card">
        <div className="card-header">
          <div>
            <h2>待确认设备与服务</h2>
            <p>
              {active
                ? "扫描完成后统一开放导入，当前统计来自后端实时结果"
                : "一个设备可包含多个命名服务；逐项确认协议、端口和是否导入"}
            </p>
          </div>
          <div className="discovery-result-summary">
            <span>
              {results.length} 台设备 ·{" "}
              {results.reduce((total, item) => total + item.services.length, 0)}{" "}
              个服务
            </span>
            <Tag tone={active ? "blue" : pendingCount ? "amber" : "green"}>
              {active
                ? "等待扫描完成"
                : pendingCount
                  ? `${pendingCount} 台待处理`
                  : "已全部处理"}
            </Tag>
          </div>
        </div>
        <div className="discovery-list">
          {pagedResults.map(({ item, index }) => {
            const locked = imported.includes(index);
            const selectedServices = item.services.filter(
              (service) =>
                service.selected &&
                typeof service.port === "number" &&
                service.port > 0 &&
                service.name.trim(),
            );
            return (
              <article
                className={`discovery-device-card ${locked ? "is-imported" : ""}`}
                key={item.host}
              >
                <header className="discovery-device-head">
                  <div className="discovery-device-identity">
                    <div className="device-symbol device-camera">⌁</div>
                    <div>
                      <div>
                        <strong>{item.host}</strong>
                        <Tag tone="blue">{item.services.length} 个端口</Tag>
                      </div>
                      <small>
                        {item.fingerprint} · {item.evidence}
                      </small>
                    </div>
                  </div>
                  <label className="discovery-device-name">
                    <span>设备名称</span>
                    <input
                      value={item.title}
                      disabled={locked}
                      onChange={(event) =>
                        updateResult(index, { title: event.target.value })
                      }
                    />
                  </label>
                  <div className="discovery-confidence">
                    <span>识别置信度</span>
                    <div>
                      <i>
                        <em style={{ width: `${item.confidence}%` }} />
                      </i>
                      <b>{item.confidence}%</b>
                    </div>
                  </div>
                  <div className="discovery-device-actions">
                    <button
                      className={locked ? "imported" : "btn primary small"}
                      disabled={locked || selectedServices.length === 0}
                      onClick={() => onImport(index, item)}
                    >
                      {locked
                        ? "✓ 已导入"
                        : `导入设备（${selectedServices.length}）`}
                    </button>
                    {!locked && (
                      <button
                        className="btn secondary small"
                        onClick={() => onIgnoredChange([...ignored, index])}
                      >
                        忽略设备
                      </button>
                    )}
                  </div>
                </header>
                <div className="discovery-service-editor">
                  <div className="discovery-service-header">
                    <span>导入</span>
                    <span className="label-with-help">
                      服务名称{" "}
                      <HelpTip text="用于访问门户、设备详情和审计记录展示。自动识别的名称可以在导入前修改。" />
                    </span>
                    <span>服务类型</span>
                    <span>目标端口</span>
                    <span>识别依据</span>
                    <span />
                  </div>
                  {item.services.map((service) => (
                    <div
                      className={`discovery-service-row ${service.selected ? "selected" : ""}`}
                      key={service.id}
                    >
                      <label className="service-check">
                        <input
                          type="checkbox"
                          aria-label={`导入服务 ${service.name}`}
                          checked={service.selected}
                          disabled={locked}
                          onChange={(event) =>
                            updateService(index, service.id, {
                              selected: event.target.checked,
                            })
                          }
                        />
                        <i />
                      </label>
                      <input
                        aria-label={`${item.host} 服务名称`}
                        value={service.name}
                        disabled={locked || !service.selected}
                        placeholder="为服务命名"
                        onChange={(event) =>
                          updateService(index, service.id, {
                            name: event.target.value,
                          })
                        }
                      />
                      <select
                        aria-label={`${service.name} 服务类型`}
                        value={service.protocol}
                        disabled={locked || !service.selected}
                        onChange={(event) =>
                          updateService(index, service.id, {
                            protocol: event.target.value as ServiceProtocol,
                          })
                        }
                      >
                        <option value="http">Web · HTTP</option>
                        <option value="https">Web · HTTPS</option>
                        <option value="ssh">SSH</option>
                        <option value="rtsp">RTSP 视频流</option>
                        <option value="rdp">RDP 远程桌面</option>
                        <option value="mysql">MySQL</option>
                        <option value="postgresql">PostgreSQL</option>
                        <option value="tcp">其他 TCP</option>
                      </select>
                      <input
                        aria-label={`${service.name} 目标端口`}
                        type="number"
                        min="1"
                        max="65535"
                        value={service.port}
                        disabled={locked || !service.selected}
                        placeholder="1-65535"
                        onChange={(event) =>
                          updateService(index, service.id, {
                            port: event.target.value
                              ? Number(event.target.value)
                              : "",
                          })
                        }
                      />
                      <div className="service-evidence">
                        <Tag
                          tone={
                            service.evidence === "手动补充" ? "gray" : "green"
                          }
                        >
                          {service.evidence === "手动补充" ? "手动" : "已验证"}
                        </Tag>
                        <span>{service.evidence}</span>
                      </div>
                      <button
                        type="button"
                        className="service-remove"
                        aria-label={`删除服务 ${service.name}`}
                        disabled={locked}
                        onClick={() => removeService(index, service.id)}
                      >
                        ×
                      </button>
                    </div>
                  ))}
                  {!item.services.length && (
                    <div className="empty-inline">
                      暂无服务，请手动添加端口后再导入
                    </div>
                  )}
                </div>
                <footer className="discovery-device-foot">
                  <button
                    type="button"
                    className="inline-add"
                    disabled={locked}
                    onClick={() => addService(index)}
                  >
                    ＋ 添加服务端口
                  </button>
                  <span>
                    将导入 <b>{selectedServices.length}</b> 个服务；Web
                    服务经托管 SOCKS 访问，SSH/RTSP/TCP
                    仅登记目标，按需另建端口转发。
                  </span>
                </footer>
              </article>
            );
          })}
        </div>
        {visibleResults.length > 0 && (
          <PaginationFooter
            total={visibleResults.length}
            page={safePage}
            pageSize={pageSize}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            noun="台设备"
          />
        )}
      </div>
    </>
  );
}

function LogsView({
  logs,
  onToast,
}: {
  logs: APIAuditLog[];
  onToast: (value: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const visibleLogs = logs.filter((log) =>
    `${log.actor}${log.resourceType}${log.resourceId}${log.action}${log.result}${log.sourceIp}`
      .toLowerCase()
      .includes(query.toLowerCase()),
  );
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(visibleLogs.length / pageSize)),
  );
  const pagedLogs = visibleLogs.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="breadcrumb">安全审计</div>
          <h1>访问记录</h1>
          <p>跟踪项目 Web、WebSSH、扫描和端口转发操作</p>
        </div>
        <button
          className="btn secondary"
          onClick={() => {
            window.location.href = `/api/v1/audit-logs/export?search=${encodeURIComponent(query)}`;
            onToast(`正在导出 ${visibleLogs.length} 条可见记录`);
          }}
        >
          导出记录
        </button>
      </div>
      <div className="content-card">
        <div className="card-header">
          <div>
            <h2>审计日志</h2>
            <p>敏感凭据和会话内容不会记录</p>
          </div>
          <div className="table-search">
            <span>⌕</span>
            <input
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(1);
              }}
              placeholder="搜索用户、资源或操作"
            />
          </div>
        </div>
        {visibleLogs.length ? (
          <>
            <div className="table-wrap">
              <table className="device-table">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>用户</th>
                    <th>资源</th>
                    <th>操作</th>
                    <th>来源 IP</th>
                    <th>结果</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedLogs.map((log) => (
                    <tr key={log.id}>
                      <td>
                        <code>
                          {new Date(log.createdAt).toLocaleString("zh-CN")}
                        </code>
                      </td>
                      <td>
                        <strong>{log.actor}</strong>
                      </td>
                      <td>
                        {log.resourceType} · {log.resourceId || "—"}
                      </td>
                      <td>
                        <Tag
                          tone={
                            log.action.includes("access") ? "violet" : "neutral"
                          }
                        >
                          {log.action}
                        </Tag>
                      </td>
                      <td>
                        <code>{log.sourceIp || "—"}</code>
                      </td>
                      <td>
                        <Tag
                          tone={
                            log.result === "success"
                              ? "green"
                              : log.result === "failed"
                                ? "amber"
                                : "gray"
                          }
                        >
                          {log.result}
                        </Tag>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <PaginationFooter
              total={visibleLogs.length}
              page={safePage}
              pageSize={pageSize}
              onPageChange={setPage}
              onPageSizeChange={setPageSize}
              noun="条记录"
            />
          </>
        ) : (
          <EmptyState
            title="没有匹配的记录"
            detail="请调整用户、资源或操作关键词"
            onClear={() => setQuery("")}
          />
        )}
      </div>
    </>
  );
}

function ModalFrame({
  children,
  onClose,
  wide = false,
  extraWide = false,
  standalone = false,
}: {
  children: React.ReactNode;
  onClose: () => void;
  wide?: boolean;
  extraWide?: boolean;
  standalone?: boolean;
}) {
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);
  if (standalone) return <div className="standalone-frame">{children}</div>;
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div
        className={`modal ${extraWide ? "modal-extra-wide" : wide ? "modal-wide" : ""}`}
        role="dialog"
        aria-modal="true"
        onMouseDown={(event) => event.stopPropagation()}
      >
        {children}
      </div>
    </div>
  );
}

function ProjectSettingsModal({
  project,
  userNames,
  onClose,
  onSave,
  onDelete,
}: {
  project: ProjectView;
  userNames: string[];
  onClose: () => void;
  onSave: (project: ProjectView) => Promise<void>;
  onDelete?: () => Promise<void>;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  return (
    <ModalFrame onClose={onClose}>
      <form
        className="form-modal"
        onSubmit={async (event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setSubmitting(true);
          setError("");
          try {
            const networks = parseIPv4Cidrs(String(form.get("networks") || ""));
            if (!networks.length || !networks.every(isValidIPv4Cidr)) {
              setError(
                "请填写合法的扫描内网 IP 段，例如 192.168.1.0/24；多个网段可换行或用逗号分隔",
              );
              setSubmitting(false);
              return;
            }
            await onSave({
              ...project,
              name: String(form.get("name") || project.name),
              owner: String(form.get("owner") || project.owner),
              networks,
            });
          } catch (saveError) {
            setError(
              saveError instanceof Error
                ? saveError.message
                : "项目设置保存失败",
            );
            setSubmitting(false);
          }
        }}
      >
        <div className="form-head">
          <div>
            <h2>项目设置</h2>
            <p>{project.code} · 修改项目名称与负责人</p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="route-note">
          <span>i</span>
          <div>
            <strong>项目只绑定已有 Client</strong>
            <small>删除项目不会修改或删除节点中的 Client 与 SOCKS 代理。</small>
          </div>
        </div>
        <div className="form-grid">
          <label className="full">
            项目名称
            <input name="name" required defaultValue={project.name} />
          </label>
          <label>
            项目编号
            <input className="generated-field" readOnly value={project.code} />
          </label>
          <label>
            负责人
            <select name="owner" required defaultValue={project.owner}>
              {[...new Set([project.owner, ...userNames])]
                .filter(Boolean)
                .map((owner) => (
                  <option key={owner}>{owner}</option>
                ))}
            </select>
          </label>
          <label>
            接入节点
            <input className="generated-field" readOnly value={project.node} />
          </label>
          <label>
            Client ID
            <input
              className="generated-field"
              readOnly
              value={project.clientId}
            />
          </label>
          <label className="full">
            <span className="field-label-help">
              扫描内网 IP 段{" "}
              <HelpTip text="设备发现只扫描这里配置的 IPv4 CIDR；支持多个网段，每行一个或使用逗号分隔。" />
            </span>
            <textarea
              name="networks"
              required
              rows={4}
              defaultValue={project.networks.join("\n")}
              placeholder={"192.168.1.0/24\n10.10.0.0/16"}
            />
          </label>
        </div>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          {onDelete && (
            <ConfirmButton
              className="danger-link"
              disabled={submitting}
              label="删除项目"
              confirmLabel="确认永久删除？"
              onConfirm={() => {
                setSubmitting(true);
                setError("");
                void onDelete().catch((deleteError) => {
                  setError(
                    deleteError instanceof Error
                      ? deleteError.message
                      : "项目删除失败",
                  );
                  setSubmitting(false);
                });
              }}
            />
          )}
          <button
            type="button"
            className="btn secondary"
            onClick={onClose}
            disabled={submitting}
          >
            取消
          </button>
          <button type="submit" className="btn primary" disabled={submitting}>
            {submitting ? "正在提交…" : "保存项目设置"}
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}

function PortForwardModal({
  project,
  devices,
  existing,
  onClose,
  onChanged,
}: {
  project: ProjectView;
  devices: Device[];
  existing?: APIPortForward;
  onClose: () => void;
  onChanged: (message: string) => Promise<void>;
}) {
  const endpoints = devices.flatMap((device) =>
    (device.serviceEndpoints || [])
      .filter(
        (endpoint) =>
          !["http", "https"].includes(endpoint.protocol) && endpoint.id,
      )
      .map((endpoint) => ({
        ...endpoint,
        deviceName: device.name,
        host: device.host,
      })),
  );
  const [allocation, setAllocation] = useState<"auto" | "manual">("auto");
  const [expiry, setExpiry] = useState<"permanent" | "day" | "week" | "custom">(
    "permanent",
  );
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const run = async (operation: () => Promise<unknown>, message: string) => {
    setSubmitting(true);
    setError("");
    try {
      await operation();
      await onChanged(message);
    } catch (operationError) {
      setError(
        operationError instanceof Error
          ? operationError.message
          : "端口转发操作失败",
      );
      setSubmitting(false);
    }
  };
  if (existing)
    return (
      <ModalFrame onClose={onClose}>
        <div className="form-modal">
          <div className="form-head">
            <div>
              <h2>管理端口转发</h2>
              <p>
                {existing.deviceName} · {existing.endpointName}
              </p>
            </div>
            <button type="button" aria-label="关闭" onClick={onClose}>
              ×
            </button>
          </div>
          <div className="route-note">
            <span>⌁</span>
            <div>
              <strong>
                {existing.target} → {existing.serverPort}
              </strong>
              <small>
                停止会保留端口与配置；删除会同时删除节点任务并释放端口。
              </small>
            </div>
          </div>
          <div className="detail-grid">
            <div>
              <span>运行状态</span>
              <strong>
                {existing.status === "running" ? "运行中" : "已停止"}
              </strong>
            </div>
            <div>
              <span>到期时间</span>
              <strong>
                {existing.expiresAt
                  ? new Date(existing.expiresAt).toLocaleString("zh-CN")
                  : "永久"}
              </strong>
            </div>
          </div>
          {error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
          <div className="form-actions">
            <ConfirmButton
              className="danger-link"
              disabled={submitting}
              label="删除并释放端口"
              confirmLabel="再次确认删除"
              onConfirm={() =>
                void run(
                  () => api.deletePortForward(existing.id),
                  `${existing.endpointName} 已删除`,
                )
              }
            />
            <button
              type="button"
              className="btn secondary"
              disabled={submitting}
              onClick={() =>
                void run(
                  () =>
                    api.setPortForward(
                      existing.id,
                      existing.status !== "running",
                    ),
                  `${existing.endpointName} 已${existing.status === "running" ? "停止" : "启动"}`,
                )
              }
            >
              {existing.status === "running" ? "停止转发" : "启动转发"}
            </button>
            <button type="button" className="btn primary" onClick={onClose}>
              完成
            </button>
          </div>
        </div>
      </ModalFrame>
    );
  return (
    <ModalFrame onClose={onClose}>
      <form
        className="form-modal"
        onSubmit={(event) => {
          event.preventDefault();
          if (!project.id) {
            setError("项目尚未写入后台");
            return;
          }
          const form = new FormData(event.currentTarget);
          const endpointId = String(form.get("endpointId") || "");
          const serverPort =
            allocation === "manual" ? Number(form.get("serverPort")) : 0;
          let expiresAt: string | null = null;
          if (expiry === "day" || expiry === "week")
            expiresAt = new Date(
              Date.now() + (expiry === "day" ? 1 : 7) * 86400000,
            ).toISOString();
          if (expiry === "custom") {
            const value = String(form.get("expiresAt") || "");
            if (!value) {
              setError("请选择自定义到期时间");
              return;
            }
            expiresAt = new Date(value).toISOString();
          }
          void run(
            () =>
              api.createPortForward(project.id!, {
                endpointId,
                serverPort,
                expiresAt,
              }),
            "端口转发已创建并同步至接入节点",
          );
        }}
      >
        <div className="form-head">
          <div>
            <h2>新建端口转发</h2>
            <p>{project.name} · 选择已经登记的非 Web 服务</p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="route-note">
          <span>i</span>
          <div>
            <strong>Web 后台不创建端口转发</strong>
            <small>
              此处只用于 SSH、RTSP 与其他 TCP
              原生客户端；目标主机和端口来自设备命名服务。
            </small>
          </div>
        </div>
        {endpoints.length ? (
          <div className="form-grid">
            <label className="full">
              <span className="field-label-help">
                设备服务{" "}
                <HelpTip text="先在内网设备中登记服务名称、协议和实际目标端口，再在此选择，避免重复手输内网地址。" />
              </span>
              <select name="endpointId" required defaultValue="">
                <option value="" disabled>
                  请选择设备与服务
                </option>
                {endpoints.map((endpoint) => (
                  <option key={endpoint.id} value={endpoint.id}>
                    {endpoint.deviceName} · {endpoint.name}（
                    {endpoint.protocol.toUpperCase()} · {endpoint.host}:
                    {endpoint.port}）
                  </option>
                ))}
              </select>
            </label>
            <label>
              端口分配方式
              <select
                value={allocation}
                onChange={(event) =>
                  setAllocation(event.target.value as "auto" | "manual")
                }
              >
                <option value="auto">从节点端口池自动分配</option>
                <option value="manual">指定节点端口</option>
              </select>
            </label>
            <label>
              公网端口
              <input
                name="serverPort"
                type="number"
                min="1"
                max="65535"
                required={allocation === "manual"}
                disabled={allocation === "auto"}
                placeholder={
                  allocation === "auto" ? "由平台自动分配" : "1-65535"
                }
              />
            </label>
            <label>
              有效期
              <select
                value={expiry}
                onChange={(event) =>
                  setExpiry(event.target.value as typeof expiry)
                }
              >
                <option value="permanent">永久</option>
                <option value="day">24 小时</option>
                <option value="week">7 天</option>
                <option value="custom">自定义到期时间</option>
              </select>
            </label>
            <label>
              自定义到期
              <input
                name="expiresAt"
                type="datetime-local"
                disabled={expiry !== "custom"}
                required={expiry === "custom"}
              />
            </label>
          </div>
        ) : (
          <EmptyState
            title="没有可转发的设备服务"
            detail="请先在项目的内网设备中添加 SSH、RTSP 或其他 TCP 服务"
          />
        )}
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          <button
            type="button"
            className="btn secondary"
            onClick={onClose}
            disabled={submitting}
          >
            取消
          </button>
          <button
            type="submit"
            className="btn primary"
            disabled={submitting || !endpoints.length}
          >
            {submitting ? "正在创建…" : "创建端口转发"}
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}

function CreateProjectModal({
  nodes,
  userNames,
  onClose,
  onCreated,
}: {
  nodes: NodeView[];
  userNames: string[];
  onClose: () => void;
  onCreated: (input: {
    name: string;
    ownerName: string;
    nodeId: string;
    clientId: number;
    networks: string[];
  }) => Promise<void>;
}) {
  const [nodeId, setNodeId] = useState("");
  const [clients, setClients] = useState<APINodeClient[]>([]);
  const [clientIdInput, setClientIdInput] = useState("");
  const [clientMenuOpen, setClientMenuOpen] = useState(false);
  const [loadingClients, setLoadingClients] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const visibleClients = useMemo(() => {
    const query = clientIdInput.trim().toLocaleLowerCase("zh-CN");
    if (!query) return clients;
    return clients.filter(
      (client) =>
        String(client.id).includes(query) ||
        client.remark.toLocaleLowerCase("zh-CN").includes(query),
    );
  }, [clientIdInput, clients]);
  const selectNode = async (value: string) => {
    setNodeId(value);
    setClients([]);
    setClientIdInput("");
    setClientMenuOpen(false);
    setError("");
    if (!value) return;
    setLoadingClients(true);
    try {
      setClients(await api.nodeClients(value));
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "读取节点 Client 失败",
      );
    } finally {
      setLoadingClients(false);
    }
  };
  return (
    <ModalFrame onClose={onClose}>
      <form
        className="form-modal project-create-simple"
        onSubmit={async (event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          const clientId = Number(form.get("clientId"));
          const networks = parseIPv4Cidrs(String(form.get("networks") || ""));
          if (!nodeId) {
            setError("请选择接入节点");
            return;
          }
          if (!Number.isInteger(clientId) || clientId < 1) {
            setError("请选择 Client 或手动输入合法 Client ID");
            return;
          }
          if (!networks.length || !networks.every(isValidIPv4Cidr)) {
            setError(
              "请填写合法的扫描内网 IP 段，例如 192.168.1.0/24；多个网段可换行或用逗号分隔",
            );
            return;
          }
          setSubmitting(true);
          setError("");
          try {
            await onCreated({
              name: String(form.get("name") || "").trim(),
              ownerName: String(form.get("ownerName") || ""),
              nodeId,
              clientId,
              networks,
            });
          } catch (reason) {
            setError(reason instanceof Error ? reason.message : "项目创建失败");
            setSubmitting(false);
          }
        }}
      >
        <div className="form-head">
          <div>
            <h2>创建客户项目</h2>
            <p>填写项目并绑定接入节点已有的 Client</p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="form-grid">
          <label className="full">
            <span className="field-label-help">
              项目名称{" "}
              <HelpTip text="用于区分客户或现场项目；项目编号由平台自动生成。" />
            </span>
            <input
              name="name"
              required
              autoFocus
              placeholder="例如：星港智慧园区"
            />
          </label>
          <label>
            <span className="field-label-help">
              负责人 <HelpTip text="负责该项目日常管理的平台用户。" />
            </span>
            <select name="ownerName" required defaultValue="">
              <option value="" disabled>
                请选择负责人
              </option>
              {userNames.map((name) => (
                <option key={name}>{name}</option>
              ))}
            </select>
          </label>
          <label>
            <span className="field-label-help">
              接入节点 <HelpTip text="选择 Client 和 SOCKS 代理所在的节点。" />
            </span>
            <select
              name="nodeId"
              required
              value={nodeId}
              onChange={(event) => void selectNode(event.target.value)}
            >
              <option value="" disabled>
                请选择接入节点
              </option>
              {nodes
                .filter((node): node is NodeView & { id: string } =>
                  Boolean(node.id),
                )
                .map((node) => (
                  <option key={node.id} value={node.id}>
                    {node.name}
                  </option>
                ))}
            </select>
          </label>
          <div className="form-field full project-client-field">
            <span className="field-label-help">
              Client{" "}
              <HelpTip text="可以从节点 Client 列表选择，也可以直接输入 Client ID；后台会核对同 ID 的 Client 与 SOCKS 代理。" />
            </span>
            <div
              className={`project-client-combobox${clientMenuOpen ? " open" : ""}`}
            >
              <div className="project-client-input-row">
                <input
                  name="clientId"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]+"
                  required
                  value={clientIdInput}
                  disabled={!nodeId || loadingClients}
                  placeholder={
                    loadingClients
                      ? "正在读取 Client…"
                      : nodeId
                        ? "选择 Client 或手动输入 ID"
                        : "请先选择接入节点"
                  }
                  role="combobox"
                  aria-autocomplete="list"
                  aria-expanded={clientMenuOpen}
                  aria-controls="project-client-list"
                  onFocus={() =>
                    setClientMenuOpen(Boolean(nodeId && !loadingClients))
                  }
                  onBlur={() =>
                    window.setTimeout(() => setClientMenuOpen(false), 120)
                  }
                  onChange={(event) => {
                    setClientIdInput(event.target.value.replace(/\D/g, ""));
                    setClientMenuOpen(true);
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Escape") setClientMenuOpen(false);
                  }}
                />
                <button
                  type="button"
                  aria-label={
                    clientMenuOpen ? "收起 Client 列表" : "展开 Client 列表"
                  }
                  disabled={!nodeId || loadingClients}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => setClientMenuOpen((open) => !open)}
                >
                  {clientMenuOpen ? "⌃" : "⌄"}
                </button>
              </div>
              {clientMenuOpen && (
                <div
                  id="project-client-list"
                  className="project-client-options"
                  role="listbox"
                >
                  {visibleClients.length ? (
                    visibleClients.map((client) => (
                      <button
                        type="button"
                        role="option"
                        aria-selected={String(client.id) === clientIdInput}
                        className={
                          String(client.id) === clientIdInput ? "selected" : ""
                        }
                        key={client.id}
                        onMouseDown={(event) => event.preventDefault()}
                        onClick={() => {
                          setClientIdInput(String(client.id));
                          setClientMenuOpen(false);
                        }}
                      >
                        <b>#{client.id}</b>
                        <span>{client.remark || `Client ${client.id}`}</span>
                        <i className={client.connected ? "online" : "offline"}>
                          {client.connected ? "已连接" : "离线"}
                        </i>
                      </button>
                    ))
                  ) : (
                    <div className="project-client-empty">
                      没有匹配项，可继续手动输入此 ID
                    </div>
                  )}
                </div>
              )}
            </div>
            {nodeId && !loadingClients && (
              <small className="field-hint">
                共 {clients.length} 个 Client · 支持选择或手动输入 ID
              </small>
            )}
          </div>
          <label className="full">
            <span className="field-label-help">
              扫描内网 IP 段{" "}
              <HelpTip text="填写客户现场允许扫描的 IPv4 CIDR；支持多个网段，每行一个或使用逗号分隔。" />
            </span>
            <textarea
              name="networks"
              required
              rows={4}
              placeholder={"192.168.1.0/24\n10.10.0.0/16"}
            />
            <small className="field-hint">
              保存后可直接在“设备发现”中扫描这些网段
            </small>
          </label>
        </div>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          <button
            type="button"
            className="btn secondary"
            onClick={onClose}
            disabled={submitting}
          >
            取消
          </button>
          <button
            type="submit"
            className="btn primary"
            disabled={submitting || loadingClients}
          >
            {submitting ? "正在创建…" : "确认创建"}
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}

function ResourceModal({
  kind,
  initialName = "",
  initialValues: suppliedInitialValues = {},
  projectNames,
  userNames,
  onClose,
  onSubmit,
  onDelete,
}: {
  kind: ConfigModalKind;
  initialName?: string;
  initialValues?: Record<string, string | string[]>;
  projectNames: string[];
  userNames: string[];
  onClose: () => void;
  onSubmit: (
    label: string,
    values: Record<string, string | string[]>,
  ) => Promise<void>;
  onDelete?: () => Promise<void>;
}) {
  const editing = kind.startsWith("edit-");
  const config: Record<
    ConfigModalKind,
    { title: string; label: string; fields: string[][] }
  > = {
    "create-node": {
      title: "添加接入节点",
      label: "节点",
      fields: [
        ["节点名称", "例如：华北接入节点"],
        ["API 地址", "https://access-bj.example.com:6443"],
        ["TLS 校验主机名", "证书 SAN 覆盖的域名"],
        ["认证账号", "节点管理账号"],
        ["认证密码", "节点管理密码"],
        ["端口池", "26000-27999"],
      ],
    },
    "create-policy": {
      title: "创建访问策略",
      label: "策略",
      fields: [
        ["策略名称", "例如：供应商临时访问"],
        ["作用项目", "选择客户项目"],
        ["授权用户", "选择平台用户"],
        ["授权能力", "选择最小必要能力"],
        ["有效时间", "永久有效"],
      ],
    },
    "create-user": {
      title: "添加平台用户",
      label: "用户",
      fields: [
        ["姓名", "例如：张工"],
        ["登录账号", "zhang.gong"],
        ["初始密码", "至少 12 个字符"],
        ["角色", "项目管理员 / 运维用户"],
        ["授权项目", "选择一个或多个客户项目"],
      ],
    },
    "edit-node": {
      title: "配置接入节点",
      label: "节点",
      fields: [
        ["节点名称", "节点名称"],
        ["API 地址", "节点 API 地址"],
        ["TLS 校验主机名", "证书 SAN 覆盖的域名"],
        ["认证账号", "留空保留现有账号"],
        ["认证密码", "已配置；留空保持不变"],
        ["端口池", "例如 22000-23999"],
        ["节点状态", "启用或维护中"],
      ],
    },
    "edit-policy": {
      title: "编辑访问策略",
      label: "策略",
      fields: [
        ["策略名称", "策略名称"],
        ["作用项目", "选择客户项目"],
        ["授权用户", "选择临时用户"],
        ["授权能力", "选择 Web 或 WebSSH"],
        ["有效时间", "保持现有有效期"],
      ],
    },
    "edit-user": {
      title: "编辑用户权限",
      label: "用户",
      fields: [
        ["姓名", "用户姓名"],
        ["登录账号", "登录账号"],
        ["角色", "系统管理员 / 项目管理员 / 运维用户"],
        ["授权项目", "选择一个或多个客户项目"],
        ["新密码（选填）", "留空保留现有密码"],
      ],
    },
  };
  const current = config[kind];
  const initialValues = editing
    ? { [current.fields[0][0]]: initialName, ...suppliedInitialValues }
    : suppliedInitialValues;
  const [multiChoices, setMultiChoices] = useState<Record<string, string[]>>(
    () =>
      Object.fromEntries(
        current.fields
          .filter(([label]) => MULTI_CHOICE_FIELDS.has(label))
          .map(([label]) => [
            label,
            Array.isArray(initialValues[label]) ? initialValues[label] : [],
          ]),
      ),
  );
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  return (
    <ModalFrame onClose={onClose}>
      <form
        className="form-modal"
        onSubmit={async (event) => {
          event.preventDefault();
          const missingMulti = current.fields.find(
            ([label]) =>
              MULTI_CHOICE_FIELDS.has(label) &&
              !(multiChoices[label] || []).length,
          );
          if (missingMulti) {
            setFormError(`请选择${missingMulti[0]}`);
            return;
          }
          const form = new FormData(event.currentTarget);
          const fieldValue = (label: string) => {
            const index = current.fields.findIndex(
              ([fieldLabel]) => fieldLabel === label,
            );
            return index >= 0 ? String(form.get(`field-${index}`) || "") : "";
          };
          if (
            kind === "create-node" &&
            (!fieldValue("认证账号") || !fieldValue("认证密码"))
          ) {
            setFormError("请填写节点认证账号和密码");
            return;
          }
          const first = String(form.get("field-0") || current.label);
          const values = Object.fromEntries(
            current.fields.map(([label], index) => [
              label,
              MULTI_CHOICE_FIELDS.has(label)
                ? multiChoices[label] || []
                : String(form.get(`field-${index}`) || ""),
            ]),
          );
          setSubmitting(true);
          setFormError("");
          try {
            await onSubmit(first, values);
          } catch (error) {
            setFormError(error instanceof Error ? error.message : "提交失败");
            setSubmitting(false);
          }
        }}
      >
        <div className="form-head">
          <div>
            <h2>{current.title}</h2>
            <p>{editing ? `修改${current.label}` : `创建${current.label}`}</p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="form-grid">
          {current.fields.map(([label, placeholder], index) => {
            const options =
              label === "授权用户"
                ? userNames
                : label === "作用项目" || label === "授权项目"
                  ? ["全部项目", ...projectNames]
                  : label === "有效时间" && editing
                    ? ["保持现有有效期", "永久有效", "24 小时", "7 天"]
                    : FIELD_OPTIONS[label];
            const immutableLogin = editing && label === "登录账号";
            const selectedChoices = multiChoices[label] || [];
            const initialValue = initialValues[label];
            const required = !OPTIONAL_RESOURCE_FIELDS.has(label);
            const passwordField = label.includes("密码");
            const passwordMinLength =
              label === "初始密码" || label === "新密码（选填）"
                ? 12
                : undefined;
            return (
              <div
                key={label}
                className={`form-field ${index === 0 ? "full" : ""}`}
              >
                <span className="field-label-help">
                  {label}
                  {FIELD_HELP[label] && <HelpTip text={FIELD_HELP[label]} />}
                </span>
                {options && MULTI_CHOICE_FIELDS.has(label) ? (
                  <details className="multi-choice">
                    <summary>
                      {selectedChoices.length
                        ? selectedChoices.join("、")
                        : `请选择${label}`}
                    </summary>
                    <div>
                      {options.map((option) => {
                        const selected = selectedChoices.includes(option);
                        return (
                          <button
                            type="button"
                            key={option}
                            className={selected ? "selected" : ""}
                            onClick={() => {
                              setFormError("");
                              setMultiChoices((currentChoices) => {
                                const current = currentChoices[label] || [];
                                if (option === "全部项目")
                                  return {
                                    ...currentChoices,
                                    [label]: selected ? [] : [option],
                                  };
                                const withoutAll = current.filter(
                                  (item) => item !== "全部项目",
                                );
                                return {
                                  ...currentChoices,
                                  [label]: selected
                                    ? withoutAll.filter(
                                        (item) => item !== option,
                                      )
                                    : [...withoutAll, option],
                                };
                              });
                            }}
                          >
                            <i>{selected ? "✓" : ""}</i>
                            {option}
                          </button>
                        );
                      })}
                    </div>
                    <input
                      type="hidden"
                      name={`field-${index}`}
                      value={selectedChoices.join(",")}
                    />
                  </details>
                ) : options ? (
                  <select
                    aria-label={label}
                    name={`field-${index}`}
                    required={required}
                    defaultValue={
                      typeof initialValue === "string" ? initialValue : ""
                    }
                  >
                    <option value="" disabled>
                      请选择{label}
                    </option>
                    {options.map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    aria-label={label}
                    name={`field-${index}`}
                    type={passwordField ? "password" : "text"}
                    minLength={passwordMinLength}
                    autoComplete={passwordField ? "new-password" : undefined}
                    required={required}
                    readOnly={immutableLogin}
                    className={immutableLogin ? "generated-field" : ""}
                    defaultValue={
                      typeof initialValue === "string" ? initialValue : ""
                    }
                    placeholder={placeholder}
                  />
                )}
              </div>
            );
          })}
        </div>
        {formError && (
          <div className="form-error" role="alert">
            {formError}
          </div>
        )}
        <div className="form-actions">
          {onDelete && (
            <ConfirmButton
              className="danger-link"
              disabled={submitting}
              label="删除资源"
              confirmLabel="再次确认删除"
              onConfirm={() => {
                setSubmitting(true);
                setFormError("");
                void onDelete().catch((error) => {
                  setFormError(
                    error instanceof Error ? error.message : "删除失败",
                  );
                  setSubmitting(false);
                });
              }}
            />
          )}
          <button
            type="button"
            className="btn secondary"
            onClick={onClose}
            disabled={submitting}
          >
            取消
          </button>
          <button type="submit" className="btn primary" disabled={submitting}>
            {submitting ? "正在提交…" : editing ? "保存更改" : "确认创建"}
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}

function NodeClientsModal({
  node,
  canCreate,
  onClose,
  onCountChange,
}: {
  node: NodeView & { id: string };
  canCreate: boolean;
  onClose: () => void;
  onCountChange: (count: number) => void;
}) {
  const [clients, setClients] = useState<APINodeClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState("");
  const [created, setCreated] = useState<APINodeClientCreateResult | null>(
    null,
  );
  const [selected, setSelected] = useState<APINodeClient | null>(null);
  const [credentials, setCredentials] = useState<
    Record<number, APINodeClientCredentials>
  >({});
  const [credentialLoading, setCredentialLoading] = useState<number | null>(
    null,
  );
  const [visibleKeys, setVisibleKeys] = useState<Record<number, boolean>>({});
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const safePage = Math.min(
    page,
    Math.max(1, Math.ceil(clients.length / pageSize)),
  );
  const pagedClients = clients.slice(
    (safePage - 1) * pageSize,
    safePage * pageSize,
  );
  useEffect(() => {
    let cancelled = false;
    api
      .nodeClients(node.id)
      .then((items) => {
        if (!cancelled) {
          setClients(items);
          setPage(1);
          setLoading(false);
        }
      })
      .catch((reason) => {
        if (!cancelled) {
          setError(
            reason instanceof Error ? reason.message : "读取 Client 失败",
          );
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [node.id]);

  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
  };
  const loadCredentials = async (client: APINodeClient) => {
    setSelected(client);
    if (credentials[client.id]) return;
    setCredentialLoading(client.id);
    setError("");
    try {
      const value = await api.nodeClientCredentials(node.id, client.id);
      setCredentials((items) => ({ ...items, [client.id]: value }));
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "读取 Client 认证信息失败",
      );
    } finally {
      setCredentialLoading(null);
    }
  };
  const revealKey = async (client: APINodeClient) => {
    if (!credentials[client.id]) {
      setCredentialLoading(client.id);
      try {
        const value = await api.nodeClientCredentials(node.id, client.id);
        setCredentials((items) => ({ ...items, [client.id]: value }));
      } catch (reason) {
        setError(
          reason instanceof Error ? reason.message : "读取唯一验证密钥失败",
        );
        return;
      } finally {
        setCredentialLoading(null);
      }
    }
    setVisibleKeys((items) => ({ ...items, [client.id]: !items[client.id] }));
  };
  const selectedCredentials = selected ? credentials[selected.id] : undefined;

  return (
    <ModalFrame onClose={onClose} extraWide>
      <div className="form-modal node-clients-modal">
        <div className="form-head">
          <div>
            <h2>
              {selected
                ? `${selected.remark || `Client ${selected.id}`} 详情`
                : `${node.name} Client`}
            </h2>
            <p>
              {selected
                ? `Client ID ${selected.id} · 认证信息默认隐藏`
                : "节点实时返回的 Client 列表 · 只读"}
            </p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        {selected ? (
          <>
            <button
              type="button"
              className="back-link"
              onClick={() => {
                setSelected(null);
                setError("");
              }}
            >
              ← 返回 Client 列表
            </button>
            <div className="client-detail-summary">
              <div>
                <span>Client ID</span>
                <strong>{selected.id}</strong>
              </div>
              <div>
                <span>连接地址</span>
                <strong>
                  <code>{selected.address || "—"}</code>
                </strong>
              </div>
              <div>
                <span>状态</span>
                <Tag
                  tone={
                    selected.connected
                      ? "green"
                      : selected.enabled
                        ? "amber"
                        : "gray"
                  }
                >
                  {selected.connected
                    ? "已连接"
                    : selected.enabled
                      ? "离线"
                      : "未启用"}
                </Tag>
              </div>
              <div>
                <span>版本</span>
                <strong>{selected.version || "—"}</strong>
              </div>
            </div>
            {credentialLoading === selected.id ? (
              <div className="empty-inline">正在读取认证信息…</div>
            ) : selectedCredentials ? (
              <div className="client-credential-grid">
                <div>
                  <span>Basic 认证用户名</span>
                  <SensitiveValue
                    value={selectedCredentials.basicUsername}
                    label="Basic 认证用户名"
                    onCopy={copy}
                  />
                </div>
                <div>
                  <span>Basic 认证密码</span>
                  <SensitiveValue
                    value={selectedCredentials.basicPassword}
                    label="Basic 认证密码"
                    onCopy={copy}
                  />
                </div>
                <div className="full">
                  <span>唯一验证密钥</span>
                  <SensitiveValue
                    value={selectedCredentials.verifyKey}
                    label="唯一验证密钥"
                    onCopy={copy}
                  />
                </div>
              </div>
            ) : null}
            {error && (
              <div className="form-error" role="alert">
                {error}
              </div>
            )}
            <div className="form-actions">
              <button
                type="button"
                className="btn secondary"
                onClick={() => setSelected(null)}
              >
                返回列表
              </button>
              <button type="button" className="btn primary" onClick={onClose}>
                关闭
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="route-note">
              <span>◉</span>
              <div>
                <strong>现有 Client 只读</strong>
                <small>
                  平台不提供修改、启停或删除操作；只允许查看和新增。
                </small>
              </div>
            </div>
            <div className="client-list-toolbar">
              <div>
                <strong>{clients.length}</strong>
                <span> 个 Client</span>
              </div>
              {canCreate && (
                <button
                  type="button"
                  className="btn primary"
                  onClick={() => {
                    setShowCreate((value) => !value);
                    setCreated(null);
                    setError("");
                  }}
                >
                  ＋ 新增 Client
                </button>
              )}
            </div>
            {showCreate && (
              <form
                className="inline-client-form"
                onSubmit={async (event) => {
                  event.preventDefault();
                  const form = new FormData(event.currentTarget);
                  const input = {
                    remark: String(form.get("remark") || "").trim(),
                    basicUsername: String(
                      form.get("basicUsername") || "",
                    ).trim(),
                    basicPassword: String(form.get("basicPassword") || ""),
                    verifyKey: String(form.get("verifyKey") || "").trim(),
                  };
                  if (
                    !input.remark ||
                    !input.basicUsername ||
                    (input.verifyKey && input.verifyKey.length < 8)
                  ) {
                    setError(
                      "请填写 Client 名称和 Basic 认证用户名；手动输入的唯一验证密钥不能少于 8 位",
                    );
                    return;
                  }
                  setCreating(true);
                  setError("");
                  try {
                    const result = await api.createNodeClient(node.id, input);
                    const next = [...clients, result.client];
                    setClients(next);
                    onCountChange(next.length);
                    setCreated(result);
                    setCredentials((items) => ({
                      ...items,
                      [result.client.id]: result.credentials,
                    }));
                    setShowCreate(false);
                  } catch (reason) {
                    setError(
                      reason instanceof Error
                        ? reason.message
                        : "新增 Client 失败",
                    );
                  } finally {
                    setCreating(false);
                  }
                }}
              >
                <div className="client-create-heading">
                  <div>
                    <strong>新增 Client</strong>
                    <small>填写必要信息，留空的凭据由平台安全生成</small>
                  </div>
                  <span>密码与密钥可留空</span>
                </div>
                <div className="client-create-grid">
                  <label>
                    Client 名称
                    <input
                      name="remark"
                      required
                      maxLength={120}
                      placeholder="例如：上海园区网关"
                      autoFocus
                    />
                  </label>
                  <label>
                    <span className="field-label-help">
                      Basic 认证用户名{" "}
                      <HelpTip text="SOCKS5 代理认证使用的用户名，必须填写；不是节点管理后台账号。" />
                    </span>
                    <input
                      name="basicUsername"
                      required
                      maxLength={120}
                      autoComplete="off"
                      placeholder="必填"
                    />
                  </label>
                  <label>
                    <span className="field-label-help">
                      Basic 认证密码{" "}
                      <HelpTip text="SOCKS5 代理认证使用的密码。留空时生成 16 位小写字母与数字组合，与节点默认密钥格式同级。" />
                    </span>
                    <input
                      name="basicPassword"
                      type="password"
                      maxLength={256}
                      autoComplete="new-password"
                      placeholder="留空自动生成"
                    />
                  </label>
                  <label>
                    <span className="field-label-help">
                      唯一验证密钥{" "}
                      <HelpTip text="客户端连接节点时使用的 vkey，节点内必须唯一。留空时按节点默认格式生成 16 位小写字母与数字组合。" />
                    </span>
                    <input
                      name="verifyKey"
                      type="password"
                      minLength={8}
                      maxLength={256}
                      autoComplete="off"
                      placeholder="留空自动生成"
                    />
                  </label>
                </div>
                <div className="client-create-actions">
                  <button
                    type="button"
                    className="btn secondary"
                    onClick={() => setShowCreate(false)}
                  >
                    取消
                  </button>
                  <button
                    type="submit"
                    className="btn primary"
                    disabled={creating}
                  >
                    {creating ? "正在创建…" : "创建 Client"}
                  </button>
                </div>
              </form>
            )}
            {created && (
              <div className="client-bootstrap">
                <div className="route-note">
                  <span>✓</span>
                  <div>
                    <strong>Client 创建成功</strong>
                    <small>认证信息可从该 Client 详情中再次查看。</small>
                  </div>
                </div>
                <button
                  type="button"
                  className="btn secondary"
                  onClick={() => void loadCredentials(created.client)}
                >
                  查看 Client 认证信息
                </button>
              </div>
            )}
            {error && (
              <div className="form-error" role="alert">
                {error}
              </div>
            )}
            {loading ? (
              <div className="empty-inline">正在读取节点 Client…</div>
            ) : clients.length ? (
              <>
                <div className="table-wrap node-client-table">
                  <table className="device-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Client 名称</th>
                        <th>连接地址</th>
                        <th>状态</th>
                        <th>版本</th>
                        <th>唯一验证密钥</th>
                        <th>流量</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pagedClients.map((client) => (
                        <tr
                          className="clickable-client-row"
                          tabIndex={0}
                          aria-label={`查看 ${client.remark || `Client ${client.id}`} 详情`}
                          key={client.id}
                          onClick={() => void loadCredentials(client)}
                          onKeyDown={(event) => {
                            if (event.key === "Enter" || event.key === " ")
                              void loadCredentials(client);
                          }}
                        >
                          <td>
                            <code>{client.id}</code>
                          </td>
                          <td>
                            <strong>
                              {client.remark || `Client ${client.id}`}
                            </strong>
                          </td>
                          <td>
                            <code>{client.address || "—"}</code>
                          </td>
                          <td>
                            <Tag
                              tone={
                                client.connected
                                  ? "green"
                                  : client.enabled
                                    ? "amber"
                                    : "gray"
                              }
                            >
                              {client.connected
                                ? "已连接"
                                : client.enabled
                                  ? "离线"
                                  : "未启用"}
                            </Tag>
                          </td>
                          <td>{client.version || "—"}</td>
                          <td>
                            <div className="masked-secret">
                              <code>
                                {visibleKeys[client.id]
                                  ? credentials[client.id]?.verifyKey ||
                                    "正在读取…"
                                  : "••••••••"}
                              </code>
                              <button
                                type="button"
                                aria-label={`${visibleKeys[client.id] ? "隐藏" : "显示"} ${client.remark || `Client ${client.id}`} 唯一验证密钥`}
                                disabled={credentialLoading === client.id}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  void revealKey(client);
                                }}
                              >
                                {visibleKeys[client.id] ? "◉" : "◉"}
                              </button>
                            </div>
                          </td>
                          <td>
                            <small>
                              入 {formatBytes(client.inletFlow)} · 出{" "}
                              {formatBytes(client.exportFlow)}
                            </small>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <PaginationFooter
                  total={clients.length}
                  page={safePage}
                  pageSize={pageSize}
                  onPageChange={setPage}
                  onPageSizeChange={setPageSize}
                  noun="个 Client"
                />
              </>
            ) : (
              <EmptyState
                title="该节点暂无 Client"
                detail="可使用右上角按钮新增 Client"
              />
            )}
            <div className="form-actions">
              <button type="button" className="btn secondary" onClick={onClose}>
                关闭
              </button>
            </div>
          </>
        )}
      </div>
    </ModalFrame>
  );
}

function SensitiveValue({
  value,
  label,
  onCopy,
}: {
  value: string;
  label: string;
  onCopy: (value: string) => Promise<void>;
}) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="sensitive-value">
      <code>{visible ? value || "—" : "••••••••••••"}</code>
      <button
        type="button"
        aria-label={`${visible ? "隐藏" : "显示"}${label}`}
        onClick={() => setVisible((current) => !current)}
      >
        {visible ? "隐藏" : "显示"}
      </button>
      <button
        type="button"
        aria-label={`复制${label}`}
        onClick={() => void onCopy(value)}
      >
        复制
      </button>
    </div>
  );
}

function SocksDetailModal({
  name,
  projects,
  nodes,
  onClose,
}: {
  name: string;
  projects: ProjectView[];
  nodes: NodeView[];
  onClose: () => void;
}) {
  const project = projects.find((item) => item.name === name) || projects[0];
  const node = nodes.find((item) => item.name === project?.node) || nodes[0];
  if (!project || !node) return null;
  return (
    <ModalFrame onClose={onClose}>
      <div className="form-modal">
        <div className="form-head">
          <div>
            <h2>托管通道详情</h2>
            <p>
              {project.name} · Client ID {project.clientId}
            </p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="route-note">
          <span>⌁</span>
          <div>
            <strong>Client ID 与 SOCKS ID 一致</strong>
            <small>平台直接使用节点已有代理，不创建或删除节点 Client。</small>
          </div>
        </div>
        <div className="detail-grid">
          <div>
            <span>接入节点</span>
            <strong>{node.name}</strong>
            <small>{node.tlsName}</small>
          </div>
          <div>
            <span>内部访问地址</span>
            <strong>{projectSocksAddress(project, nodes)}</strong>
            <small>由节点返回的 SOCKS 端口确定</small>
          </div>
          <div>
            <span>关联 Client</span>
            <strong>Client ID {project.clientId}</strong>
            <small>{project.clientStatus}</small>
          </div>
          <div>
            <span>设备发现网段</span>
            <strong>
              {project.networks.length
                ? project.networks.join(" · ")
                : "尚未配置"}
            </strong>
            <small>只用于控制自动扫描范围</small>
          </div>
        </div>
        <div className="form-actions">
          <button type="button" className="btn primary" onClick={onClose}>
            完成
          </button>
        </div>
      </div>
    </ModalFrame>
  );
}

function WebServiceEditor({
  rows,
  setRows,
  onAdd,
}: {
  rows: EditableWebRow[];
  setRows: Dispatch<SetStateAction<EditableWebRow[]>>;
  onAdd: () => void;
}) {
  const update = (id: EditableWebRow["id"], values: Partial<EditableWebRow>) =>
    setRows((items) =>
      items.map((item) => (item.id === id ? { ...item, ...values } : item)),
    );
  return (
    <div className="form-section">
      <div>
        <strong>Web 服务入口</strong>
        <button type="button" className="inline-add" onClick={onAdd}>
          ＋ 添加 Web 服务
        </button>
      </div>
      <div className="web-service-editor">
        {rows.map((row, index) => (
          <div className="web-service-row" key={row.id}>
            <label>
              服务名称
              <input
                name="webServiceName"
                required
                value={row.name}
                onChange={(event) =>
                  update(row.id, { name: event.target.value })
                }
                placeholder="例如 AdGuard Home"
              />
            </label>
            <label>
              协议
              <select
                name="webProtocol"
                value={row.protocol}
                onChange={(event) =>
                  update(row.id, {
                    protocol: event.target.value,
                    allowInsecureTls: event.target.value === "https",
                    ...(event.target.value === "http"
                      ? { tlsServerName: "" }
                      : {}),
                  })
                }
              >
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
              </select>
            </label>
            <label>
              目标端口
              <input
                name="webPort"
                type="number"
                min="1"
                max="65535"
                value={row.port}
                onChange={(event) =>
                  update(row.id, { port: event.target.value })
                }
                placeholder="80 / 3000 / 9443"
                required
              />
            </label>
            <button
              type="button"
              aria-label={`删除 Web 服务 ${index + 1}`}
              onClick={() =>
                setRows((items) => items.filter((item) => item.id !== row.id))
              }
            >
              ×
            </button>
            <input
              type="hidden"
              name="webTlsServerName"
              value={row.tlsServerName}
            />
            <input
              type="hidden"
              name="webAllowInsecureTls"
              value={String(row.protocol === "https")}
            />
            {row.protocol === "https" && (
              <div className="web-tls-options">
                <label>
                  <span className="field-label-help">
                    TLS 校验主机名{" "}
                    <HelpTip text="该 HTTPS 服务证书中的域名；直接使用 IP 且证书签发给 IP 时可留空。" />
                  </span>
                  <input
                    value={row.tlsServerName}
                    onChange={(event) =>
                      update(row.id, { tlsServerName: event.target.value })
                    }
                    placeholder="例如 router.lan"
                  />
                </label>
              </div>
            )}
          </div>
        ))}
        {!rows.length && (
          <div className="empty-inline">
            暂无 Web 服务，可只登记 SSH 或其他服务
          </div>
        )}
      </div>
    </div>
  );
}

type DeviceModalSection = "basic" | "web" | "ssh" | "other";
function DeviceModalNav({
  section,
  setSection,
  webCount,
  otherCount,
}: {
  section: DeviceModalSection;
  setSection: Dispatch<SetStateAction<DeviceModalSection>>;
  webCount: number;
  otherCount: number;
}) {
  const items: Array<[DeviceModalSection, string, number | null]> = [
    ["basic", "基本信息", null],
    ["web", "Web 服务", webCount],
    ["ssh", "WebSSH", null],
    ["other", "其他服务", otherCount],
  ];
  return (
    <nav className="device-modal-nav" aria-label="设备配置分类">
      {items.map(([value, label, count]) => (
        <button
          type="button"
          key={value}
          className={section === value ? "active" : ""}
          onClick={() => setSection(value)}
        >
          {label}
          {count !== null && <span>{count}</span>}
        </button>
      ))}
    </nav>
  );
}

function AddDeviceModal({
  onClose,
  onSubmit,
}: {
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const [webRows, setWebRows] = useState<EditableWebRow[]>([
    {
      id: 1,
      name: "设备管理后台",
      protocol: "http",
      port: "8080",
      tlsServerName: "",
      allowInsecureTls: false,
    },
  ]);
  const [otherRows, setOtherRows] = useState<
    { id: number; name: string; protocol: OtherServiceProtocol; port: string }[]
  >([]);
  const [section, setSection] = useState<"basic" | "web" | "ssh" | "other">(
    "basic",
  );
  const [sshEnabled, setSshEnabled] = useState(true);
  const [sshAuthMethod, setSshAuthMethod] = useState<"password" | "key">(
    "password",
  );
  return (
    <ModalFrame onClose={onClose} wide>
      <form className="form-modal device-modal" onSubmit={onSubmit}>
        <div className="form-head">
          <div>
            <h2>手工添加设备</h2>
            <p>同一台设备可以配置多个 Web、SSH、RTSP 与 TCP 服务</p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <DeviceModalNav
          section={section}
          setSection={setSection}
          webCount={webRows.length}
          otherCount={otherRows.length}
        />
        <div className={`device-panel ${section === "basic" ? "active" : ""}`}>
          <div className="form-grid">
            <label className="full">
              设备名称
              <input
                name="name"
                required
                placeholder="例如：OpenWrt 边缘网关"
              />
            </label>
            <label>
              <span className="field-label-help">
                内网 IPv4{" "}
                <HelpTip text="填写该设备在客户内网中的实际 IPv4 地址，不受设备发现网段限制。" />
              </span>
              <input
                name="host"
                required
                inputMode="decimal"
                placeholder="192.168.10.42"
              />
            </label>
            <label>
              设备类型
              <select name="type">
                <option>网络设备</option>
                <option>视频监控</option>
                <option>门禁设备</option>
                <option>工业控制</option>
                <option>其他设备</option>
              </select>
            </label>
            <label className="full">
              厂商与型号
              <input name="vendor" placeholder="例如：OpenWrt 24.10" />
            </label>
          </div>
        </div>
        <div className={`device-panel ${section === "web" ? "active" : ""}`}>
          <WebServiceEditor
            rows={webRows}
            setRows={setWebRows}
            onAdd={() =>
              setWebRows((rows) => [
                ...rows,
                {
                  id: Date.now(),
                  name: `Web 服务 ${rows.length + 1}`,
                  protocol: "http",
                  port: "",
                  tlsServerName: "",
                  allowInsecureTls: false,
                },
              ])
            }
          />
        </div>
        <div className={`device-panel ${section === "ssh" ? "active" : ""}`}>
          <div className="form-grid">
            <label className="checkbox">
              <input
                type="checkbox"
                name="ssh"
                checked={sshEnabled}
                onChange={(event) => setSshEnabled(event.target.checked)}
              />
              <span>启用 WebSSH</span>
            </label>
            <label>
              SSH 目标端口
              <input
                name="sshPort"
                type="number"
                min="1"
                max="65535"
                disabled={!sshEnabled}
                defaultValue="22"
              />
            </label>
            <label>
              SSH 登录方式
              <select
                name="sshAuthMethod"
                disabled={!sshEnabled}
                value={sshAuthMethod}
                onChange={(event) =>
                  setSshAuthMethod(event.target.value as "password" | "key")
                }
              >
                <option value="password">密码登录</option>
                <option value="key">密钥登录</option>
              </select>
            </label>
            <label>
              SSH 用户名
              <input
                name="sshUsername"
                disabled={!sshEnabled}
                required={sshEnabled}
                placeholder="例如 root"
                autoComplete="off"
              />
            </label>
            {sshAuthMethod === "password" ? (
              <label className="full">
                SSH 密码
                <input
                  name="sshPassword"
                  type="password"
                  disabled={!sshEnabled}
                  required={sshEnabled}
                  placeholder="保存后不回显"
                  autoComplete="new-password"
                />
              </label>
            ) : (
              <label className="full">
                SSH 私钥文件路径
                <input
                  name="sshKeyPath"
                  disabled={!sshEnabled}
                  required={sshEnabled}
                  placeholder="/run/secrets/device_ssh_key"
                  autoComplete="off"
                />
              </label>
            )}
            <label className="full">
              <span className="field-label-help">
                SSH 主机密钥指纹{" "}
                <HelpTip text="留空可正常连接；填写 SHA256 指纹后会严格校验设备身份。" />
              </span>
              <input
                name="sshHostKeyFingerprint"
                disabled={!sshEnabled}
                placeholder="SHA256:..."
                autoComplete="off"
              />
            </label>
          </div>
        </div>
        <div className={`device-panel ${section === "other" ? "active" : ""}`}>
          <div className="form-section">
            <div>
              <strong>其他服务</strong>
              <button
                type="button"
                className="inline-add"
                onClick={() =>
                  setOtherRows((rows) => [
                    ...rows,
                    {
                      id: Date.now(),
                      name: `其他服务 ${rows.length + 1}`,
                      protocol: "tcp",
                      port: "",
                    },
                  ])
                }
              >
                ＋ 添加原生服务
              </button>
            </div>
            <div className="web-service-editor">
              {otherRows.map((row, index) => (
                <div className="web-service-row" key={row.id}>
                  <label>
                    服务名称
                    <input
                      name="otherServiceName"
                      required
                      value={row.name}
                      onChange={(event) =>
                        setOtherRows((rows) =>
                          rows.map((item) =>
                            item.id === row.id
                              ? { ...item, name: event.target.value }
                              : item,
                          ),
                        )
                      }
                    />
                  </label>
                  <label>
                    协议
                    <select
                      name="otherProtocol"
                      value={row.protocol}
                      onChange={(event) =>
                        setOtherRows((rows) =>
                          rows.map((item) =>
                            item.id === row.id
                              ? {
                                  ...item,
                                  protocol: event.target
                                    .value as OtherServiceProtocol,
                                }
                              : item,
                          ),
                        )
                      }
                    >
                      <option value="rtsp">RTSP</option>
                      <option value="rdp">RDP</option>
                      <option value="mysql">MySQL</option>
                      <option value="postgresql">PostgreSQL</option>
                      <option value="tcp">其他 TCP</option>
                    </select>
                  </label>
                  <label>
                    目标端口
                    <input
                      name="otherPort"
                      type="number"
                      min="1"
                      max="65535"
                      required
                      value={row.port}
                      onChange={(event) =>
                        setOtherRows((rows) =>
                          rows.map((item) =>
                            item.id === row.id
                              ? { ...item, port: event.target.value }
                              : item,
                          ),
                        )
                      }
                    />
                  </label>
                  <button
                    type="button"
                    aria-label={`删除其他服务 ${index + 1}`}
                    onClick={() =>
                      setOtherRows((rows) =>
                        rows.filter((item) => item.id !== row.id),
                      )
                    }
                  >
                    ×
                  </button>
                </div>
              ))}
              {!otherRows.length && (
                <div className="empty-inline">暂无其他服务</div>
              )}
            </div>
          </div>
        </div>
        <div className="form-actions">
          <button type="button" className="btn secondary" onClick={onClose}>
            取消
          </button>
          <button type="submit" className="btn primary">
            添加设备
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}

function ManageDeviceModal({
  device,
  onClose,
  onSave,
  onDelete,
}: {
  device: Device;
  onClose: () => void;
  onSave: (device: Device) => Promise<void>;
  onDelete: () => Promise<void>;
}) {
  const parseService = (service: WebService, index: number): EditableWebRow => {
    const url = new URL(service.url);
    return {
      id: service.endpointId || `existing-web-${index}`,
      endpointId: service.endpointId,
      name: service.name,
      protocol: url.protocol.replace(":", ""),
      port: url.port || (url.protocol === "https:" ? "443" : "80"),
      tlsServerName: service.tlsServerName || "",
      allowInsecureTls: url.protocol === "https:",
    };
  };
  const [webRows, setWebRows] = useState(() =>
    device.webServices.map(parseService),
  );
  const [sshEnabled, setSshEnabled] = useState(device.ssh);
  const sshEndpoint = (device.serviceEndpoints || []).find(
    (service) => service.protocol === "ssh",
  );
  const [sshAuthMethod, setSshAuthMethod] = useState<"password" | "key">(
    sshEndpoint?.sshAuthMethod === "key" ? "key" : "password",
  );
  const [otherRows, setOtherRows] = useState(() =>
    (device.serviceEndpoints || [])
      .filter((service) => !["http", "https", "ssh"].includes(service.protocol))
      .map((service, index) => ({
        id: service.id || `existing-other-${index}`,
        endpointId: service.id,
        name: service.name,
        protocol: service.protocol as OtherServiceProtocol,
        port: String(service.port),
      })),
  );
  const [section, setSection] = useState<DeviceModalSection>("basic");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const host = String(form.get("host") || device.host);
    const webServices = webRows
      .filter((row) => Number(row.port) > 0)
      .map((row) => ({
        name: row.name,
        url: `${row.protocol}://${host}:${row.port}`,
        endpointId: row.endpointId,
        tlsServerName: row.tlsServerName,
        allowInsecureTls: row.protocol === "https",
      }));
    const sshPort = sshEnabled ? Number(form.get("sshPort") || 22) : null;
    const sshUsername = String(form.get("sshUsername") || "").trim();
    const sshPassword = String(form.get("sshPassword") || "");
    const sshKeyPath = String(form.get("sshKeyPath") || "").trim();
    if (
      sshEnabled &&
      (!sshUsername ||
        (sshAuthMethod === "password"
          ? !sshPassword && !sshEndpoint?.credentialConfigured
          : !sshKeyPath))
    ) {
      setError(
        sshAuthMethod === "password"
          ? "请填写 SSH 用户名和密码"
          : "请填写 SSH 用户名和私钥文件路径",
      );
      return;
    }
    const serviceEndpoints: DeviceServiceEndpoint[] = [
      ...webRows
        .filter((row) => Number(row.port) > 0)
        .map((row) => ({
          id: row.endpointId,
          name: row.name,
          protocol: row.protocol as ServiceProtocol,
          port: Number(row.port),
          tlsServerName: row.tlsServerName,
          allowInsecureTls: row.protocol === "https",
        })),
      ...(sshEnabled && sshPort
        ? [
            {
              id: device.sshEndpointId,
              name: "WebSSH",
              protocol: "ssh" as const,
              port: sshPort,
              sshHostKeyFingerprint: String(
                form.get("sshHostKeyFingerprint") || "",
              ).trim(),
              sshCredential: {
                method: sshAuthMethod,
                username: sshUsername,
                password:
                  sshAuthMethod === "password" ? sshPassword : undefined,
                keyPath: sshAuthMethod === "key" ? sshKeyPath : undefined,
              },
            },
          ]
        : []),
      ...otherRows
        .filter((row) => Number(row.port) > 0)
        .map((row) => ({
          id: row.endpointId,
          name: row.name,
          protocol: row.protocol,
          port: Number(row.port),
        })),
    ];
    setSubmitting(true);
    setError("");
    try {
      await onSave({
        ...device,
        name: String(form.get("name") || device.name),
        host,
        type: String(form.get("type") || device.type),
        vendor: String(form.get("vendor") || device.vendor),
        web: webServices[0]?.url || null,
        webServices,
        ssh: sshEnabled,
        sshPort,
        services: serviceEndpoints.length,
        serviceEndpoints,
      });
    } catch (saveError) {
      setError(
        saveError instanceof Error ? saveError.message : "设备配置保存失败",
      );
      setSubmitting(false);
    }
  };
  return (
    <ModalFrame onClose={onClose} wide>
      <form className="form-modal device-modal" onSubmit={submit}>
        <div className="form-head">
          <div>
            <h2>管理设备与访问入口</h2>
            <p>
              {device.projectCode} · 设备 ID {device.id}
            </p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <DeviceModalNav
          section={section}
          setSection={setSection}
          webCount={webRows.length}
          otherCount={otherRows.length}
        />
        <div className={`device-panel ${section === "basic" ? "active" : ""}`}>
          <div className="form-grid">
            <label className="full">
              设备名称
              <input name="name" required defaultValue={device.name} />
            </label>
            <label>
              <span className="field-label-help">
                内网 IPv4 <HelpTip text="设备登记地址不受设备发现网段限制。" />
              </span>
              <input
                name="host"
                required
                inputMode="decimal"
                defaultValue={device.host}
              />
            </label>
            <label>
              设备类型
              <select name="type" defaultValue={device.type}>
                <option>网络设备</option>
                <option>视频监控</option>
                <option>门禁设备</option>
                <option>工业控制</option>
                <option>自动发现设备</option>
                <option>其他设备</option>
              </select>
            </label>
            <label className="full">
              厂商与型号
              <input name="vendor" defaultValue={device.vendor} />
            </label>
          </div>
        </div>
        <div className={`device-panel ${section === "web" ? "active" : ""}`}>
          <WebServiceEditor
            rows={webRows}
            setRows={setWebRows}
            onAdd={() =>
              setWebRows((rows) => [
                ...rows,
                {
                  id: `new-web-${Date.now()}`,
                  endpointId: undefined,
                  name: `Web 服务 ${rows.length + 1}`,
                  protocol: "http",
                  port: "",
                  tlsServerName: "",
                  allowInsecureTls: false,
                },
              ])
            }
          />
        </div>
        <div className={`device-panel ${section === "ssh" ? "active" : ""}`}>
          <div className="device-ssh-note">
            <span>✓</span>
            <div>
              <strong>
                {sshEndpoint?.credentialConfigured
                  ? "SSH 登录信息已配置"
                  : "配置后可直接连接"}
              </strong>
              <small>
                密码加密保存且不回显；未配置时，WebSSH
                会请求用户输入本次临时凭据。
              </small>
            </div>
          </div>
          <div className="form-grid">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={sshEnabled}
                onChange={(event) => setSshEnabled(event.target.checked)}
              />
              <span>启用 WebSSH</span>
            </label>
            <label>
              SSH 目标端口
              <input
                name="sshPort"
                type="number"
                min="1"
                max="65535"
                disabled={!sshEnabled}
                defaultValue={device.sshPort || 22}
              />
            </label>
            <label>
              SSH 登录方式
              <select
                name="sshAuthMethod"
                disabled={!sshEnabled}
                value={sshAuthMethod}
                onChange={(event) =>
                  setSshAuthMethod(event.target.value as "password" | "key")
                }
              >
                <option value="password">密码登录</option>
                <option value="key">密钥登录</option>
              </select>
            </label>
            <label>
              SSH 用户名
              <input
                name="sshUsername"
                disabled={!sshEnabled}
                required={sshEnabled}
                defaultValue={sshEndpoint?.sshUsername || ""}
                placeholder="例如 root"
                autoComplete="off"
              />
            </label>
            {sshAuthMethod === "password" ? (
              <label className="full">
                SSH 密码
                <input
                  name="sshPassword"
                  type="password"
                  disabled={!sshEnabled}
                  placeholder={
                    sshEndpoint?.credentialConfigured
                      ? "已配置，留空保持不变"
                      : "输入密码，保存后不回显"
                  }
                  autoComplete="new-password"
                />
              </label>
            ) : (
              <label className="full">
                SSH 私钥文件路径
                <input
                  name="sshKeyPath"
                  disabled={!sshEnabled}
                  required={sshEnabled}
                  defaultValue={sshEndpoint?.sshKeyPath || ""}
                  placeholder="/run/secrets/device_ssh_key"
                  autoComplete="off"
                />
              </label>
            )}
            <label className="full">
              <span className="field-label-help">
                SSH 主机密钥指纹{" "}
                <HelpTip text="留空可正常连接；填写 SHA256 指纹后会严格校验设备身份。" />
              </span>
              <input
                name="sshHostKeyFingerprint"
                disabled={!sshEnabled}
                defaultValue={sshEndpoint?.sshHostKeyFingerprint || ""}
                placeholder="SHA256:..."
                autoComplete="off"
              />
            </label>
          </div>
        </div>
        <div className={`device-panel ${section === "other" ? "active" : ""}`}>
          <div className="form-section">
            <div>
              <strong>其他服务端口</strong>
              <button
                type="button"
                className="inline-add"
                onClick={() =>
                  setOtherRows((rows) => [
                    ...rows,
                    {
                      id: `new-other-${Date.now()}`,
                      endpointId: undefined,
                      name: `其他服务 ${rows.length + 1}`,
                      protocol: "tcp",
                      port: "",
                    },
                  ])
                }
              >
                ＋ 添加原生服务
              </button>
            </div>
            <div className="web-service-editor">
              {otherRows.map((row, index) => (
                <div className="web-service-row" key={row.id}>
                  <label>
                    服务名称
                    <input
                      required
                      value={row.name}
                      onChange={(event) =>
                        setOtherRows((rows) =>
                          rows.map((item) =>
                            item.id === row.id
                              ? { ...item, name: event.target.value }
                              : item,
                          ),
                        )
                      }
                    />
                  </label>
                  <label>
                    协议
                    <select
                      value={row.protocol}
                      onChange={(event) =>
                        setOtherRows((rows) =>
                          rows.map((item) =>
                            item.id === row.id
                              ? {
                                  ...item,
                                  protocol: event.target
                                    .value as OtherServiceProtocol,
                                }
                              : item,
                          ),
                        )
                      }
                    >
                      <option value="rtsp">RTSP</option>
                      <option value="rdp">RDP</option>
                      <option value="mysql">MySQL</option>
                      <option value="postgresql">PostgreSQL</option>
                      <option value="tcp">其他 TCP</option>
                    </select>
                  </label>
                  <label>
                    目标端口
                    <input
                      type="number"
                      min="1"
                      max="65535"
                      required
                      value={row.port}
                      onChange={(event) =>
                        setOtherRows((rows) =>
                          rows.map((item) =>
                            item.id === row.id
                              ? { ...item, port: event.target.value }
                              : item,
                          ),
                        )
                      }
                    />
                  </label>
                  <button
                    type="button"
                    aria-label={`删除其他服务 ${index + 1}`}
                    onClick={() =>
                      setOtherRows((rows) =>
                        rows.filter((item) => item.id !== row.id),
                      )
                    }
                  >
                    ×
                  </button>
                </div>
              ))}
              {!otherRows.length && (
                <div className="empty-inline">暂无其他服务</div>
              )}
            </div>
          </div>
        </div>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          <ConfirmButton
            className="danger-link"
            disabled={submitting}
            label="删除设备"
            confirmLabel="确认永久删除？"
            onConfirm={() => {
              setSubmitting(true);
              setError("");
              void onDelete().catch((deleteError) => {
                setError(
                  deleteError instanceof Error
                    ? deleteError.message
                    : "设备删除失败",
                );
                setSubmitting(false);
              });
            }}
          />
          <button
            type="button"
            className="btn secondary"
            onClick={onClose}
            disabled={submitting}
          >
            取消
          </button>
          <button type="submit" className="btn primary" disabled={submitting}>
            {submitting ? "正在提交…" : "保存配置"}
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}

function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"' && quoted && line[index + 1] === '"') {
      current += '"';
      index += 1;
    } else if (character === '"') quoted = !quoted;
    else if (character === "," && !quoted) {
      result.push(current.trim());
      current = "";
    } else current += character;
  }
  result.push(current.trim());
  return result;
}

function ImportDevicesModal({
  project,
  onClose,
  onImport,
}: {
  project: ProjectView;
  onClose: () => void;
  onImport: (inputs: Record<string, unknown>[]) => Promise<void>;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  return (
    <ModalFrame onClose={onClose}>
      <form
        className="form-modal"
        onSubmit={async (event) => {
          event.preventDefault();
          setSubmitting(true);
          setError("");
          try {
            const file = new FormData(event.currentTarget).get("file");
            if (!(file instanceof File)) throw new Error("请选择 CSV 文件");
            const lines = (await file.text())
              .replace(/^\uFEFF/, "")
              .split(/\r?\n/)
              .filter((line) => line.trim());
            if (lines.length < 2)
              throw new Error("CSV 至少需要表头和一行服务数据");
            const headers = parseCSVLine(lines[0]).map((value) =>
              value.toLowerCase(),
            );
            const required = [
              "name",
              "host",
              "service_name",
              "protocol",
              "port",
            ];
            for (const field of required)
              if (!headers.includes(field))
                throw new Error(`CSV 缺少字段：${field}`);
            const grouped = new Map<
              string,
              {
                name: string;
                host: string;
                deviceType: string;
                vendor: string;
                source: string;
                endpoints: {
                  name: string;
                  protocol: string;
                  targetPort: number;
                }[];
              }
            >();
            for (let lineIndex = 1; lineIndex < lines.length; lineIndex += 1) {
              const values = parseCSVLine(lines[lineIndex]);
              const row = Object.fromEntries(
                headers.map((header, index) => [header, values[index] || ""]),
              );
              if (
                ![
                  "http",
                  "https",
                  "ssh",
                  "rtsp",
                  "tcp",
                  "rdp",
                  "mysql",
                  "postgresql",
                ].includes(row.protocol)
              )
                throw new Error(`第 ${lineIndex + 1} 行协议不受支持`);
              const port = Number(row.port);
              if (!Number.isInteger(port) || port < 1 || port > 65535)
                throw new Error(`第 ${lineIndex + 1} 行端口无效`);
              const device = grouped.get(row.host) || {
                name: row.name,
                host: row.host,
                deviceType: row.type || "other",
                vendor: row.vendor || "",
                source: "import",
                endpoints: [],
              };
              if (
                device.endpoints.some(
                  (endpoint) =>
                    endpoint.protocol === row.protocol &&
                    endpoint.targetPort === port,
                )
              )
                throw new Error(
                  `第 ${lineIndex + 1} 行与同主机已有协议端口重复`,
                );
              device.endpoints.push({
                name: row.service_name,
                protocol: row.protocol,
                targetPort: port,
              });
              grouped.set(row.host, device);
            }
            await onImport([...grouped.values()]);
          } catch (importError) {
            setError(
              importError instanceof Error
                ? importError.message
                : "CSV 导入失败",
            );
            setSubmitting(false);
          }
        }}
      >
        <div className="form-head">
          <div>
            <h2>批量导入设备</h2>
            <p>{project.name} · 导入已知内网设备，不受设备发现网段限制</p>
          </div>
          <button type="button" aria-label="关闭" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="route-note">
          <span>⇧</span>
          <div>
            <strong>CSV 字段</strong>
            <small>
              name, host, type, vendor, service_name, protocol, port；同一 host
              的多行服务自动合并为一台设备
            </small>
          </div>
        </div>
        <div className="form-grid">
          <label className="full">
            选择 CSV 文件
            <input name="file" type="file" accept=".csv,text/csv" required />
          </label>
        </div>
        <div className="route-note">
          <span>✓</span>
          <div>
            <strong>事务化导入</strong>
            <small>
              浏览器与后台共同检查
              IP、协议、端口和重复目标；整批一次提交，任一数据失败都不会留下部分设备。
            </small>
          </div>
        </div>
        {error && (
          <div className="form-error" role="alert">
            {error}
          </div>
        )}
        <div className="form-actions">
          <button
            type="button"
            className="btn secondary"
            onClick={onClose}
            disabled={submitting}
          >
            取消
          </button>
          <button type="submit" className="btn primary" disabled={submitting}>
            {submitting ? "正在导入…" : "校验并导入"}
          </button>
        </div>
      </form>
    </ModalFrame>
  );
}
