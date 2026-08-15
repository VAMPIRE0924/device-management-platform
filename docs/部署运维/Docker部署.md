# Docker 正式部署

本文适用于 `vampirerune/device-management-platform:v1.0.2`。生产形态为单容器、单实例 SQLite；不支持多个应用实例同时写同一数据卷。

## 1. 前置条件

- Linux 服务器，推荐 2 核 CPU、2 GB 内存和 10 GB 可用磁盘；
- Docker Engine 24+、Docker Compose v2；
- 一个面板域名，例如 `admin.example.com`；
- 同根泛域名 `*.admin.example.com`；
- 面板域名和泛域名均解析到部署服务器；
- 可覆盖上述两个域名的可信 TLS 证书；
- 服务器能够访问 NPS API 和需要接入的网络。

Web 会话必须使用泛域名。每个会话会生成独立子域名，从而正确处理设备后台的根路径资源、Cookie、重定向、动态 API 和 WebSocket。

## 2. 准备目录

```bash
git clone https://github.com/VAMPIRE0924/device-management-platform.git device-management-platform
cd device-management-platform
cp .env.example .env
cp conf/device-management-platform.conf.example conf/device-management-platform.conf
```

`.env` 建议保持：

```dotenv
DMP_IMAGE=vampirerune/device-management-platform:v1.0.2
DMP_BIND_ADDRESS=127.0.0.1
DMP_HOST_PORT=8088
TZ=Asia/Shanghai
```

平台不需要手工生成部署令牌。生产容器首次启动时会自动生成内部管理 API 令牌，并以 `0600` 权限保存在 `/data/api.token`；后续重启和升级会继续使用同一令牌。

## 3. 配置平台

编辑 `conf/device-management-platform.conf`：

```ini
app_name = 设备管理平台
run_mode = pro
listen_addr = 0.0.0.0:8088
data_dir = /data
database_path = /data/platform.db
settings_override_file = /data/settings.override.conf
mfa_enabled = false
mfa_methods = totp,email
mfa_key_file = /data/mfa.key
mfa_email_code_ttl = 10m

cookie_secure = true
```

容器启动后，再在系统设置中填写面板域名和 Web 反代域名，无需把域名写入 Docker Compose。

系统设置中的“反代地址”会显示为 `*.admin.example.com`，配置文件只填写基础域名，不写 `*.`。

若反向代理位于独立容器网络或其他主机，才配置实际代理来源网段：

```ini
trusted_proxy_cidrs = 172.20.0.0/24
```

该项只决定平台是否信任代理提交的真实用户 IP，不参与设备发现，也不限制已登记设备访问。不要填写宽泛的客户内网段。

## 4. HTTPS 反向代理

面板域名和所有会话子域名必须转发到同一个 设备管理平台 端口，并保留原始 `Host`。

### Nginx

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl http2;
    server_name admin.example.com *.admin.example.com;

    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}

server {
    listen 80;
    server_name admin.example.com *.admin.example.com;
    return 301 https://$host$request_uri;
}
```

### Caddy

泛域名证书通常需要 DNS challenge。以下示例假定 Caddy 已安装对应 DNS provider 模块：

```caddyfile
admin.example.com, *.admin.example.com {
    tls {
        dns <provider> {$DNS_API_TOKEN}
    }
    reverse_proxy 127.0.0.1:8088
}
```

不要把 DNS API Token 写入仓库或 Caddyfile。

## 5. 启动与初始化

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 platform
```

容器状态应变为 `healthy`。随后访问面板，直接设置首个系统管理员的显示名称、登录账号和密码。完成初始化后再次调用初始化接口会被拒绝。

基础检查：

```bash
curl -fsS https://admin.example.com/health/live
curl -fsS https://admin.example.com/health/ready
```

## 6. 接入节点

在“接入节点”页面填写：

- 节点名称；
- NPS API 地址；
- TLS 校验主机名；
- 认证账号和认证密码；
- 端口池和启用状态。

认证密码加密写入 SQLite，页面再次打开时不回显。节点 Client 只允许查看和新增，不能从平台修改或删除。项目只绑定既有 Client；Client ID 与重构版 NPS 的 SOCKS ID 必须一致。

如需文件方式管理外部节点或 SSH 凭据，将 JSON 放入 `secrets/nodes/`，在平台填写 `file:///run/secrets/platform-nodes/<文件名>.json`。文件必须保持 `0600`，且必须与数据库一起备份。

## 7. SMTP 与 MFA

SMTP 端口决定连接方式：

- 465：隐式 TLS；
- 其他端口（通常 587）：STARTTLS，服务器不支持加密升级时发送失败。

先在“系统设置”完成 SMTP、发件人和测试投递，再启用 MFA。SMTP 密码写入数据卷中的 `0600` 文件，读取接口不会回显。

## 8. 升级

升级前先从“系统设置”下载 SQLite 一致性备份，并备份以下文件：

- Docker volume `device-management-platform_platform-data`；
- `conf/device-management-platform.conf` 和 `.env`；
- `secrets/` 中全部 Secret；
- 反向代理配置和 TLS 证书。

然后修改 `.env` 中的固定版本：

```bash
DMP_IMAGE=vampirerune/device-management-platform:v1.0.2
```

执行：

```bash
docker compose pull
docker compose up -d
docker compose ps
```

不要在生产环境长期使用不可追溯的本地镜像。`latest` 便于首次试用，正式部署建议固定完整版本号。

## 9. 备份与恢复

在线运行时只能通过平台下载 SQLite 一致性快照，不能直接复制 WAL 模式下的数据库文件。

恢复必须停服：

```bash
docker compose down
docker run --rm \
  -v device-management-platform_platform-data:/data \
  -v "$PWD/backup:/backup:ro" \
  -v "$PWD/conf/device-management-platform.conf:/etc/device-management-platform/platform.conf:ro" \
  -e DMP_CONFIG_FILE=/etc/device-management-platform/platform.conf \
  vampirerune/device-management-platform:v1.0.2 \
  restore /backup/device-management-platform-backup.db
docker compose up -d
```

数据库、`/data/api.token`、`/data/credentials.key`、`/data/mfa.key`、外部 Secret 和配置必须来自同一备份批次。缺少节点凭据主密钥时，数据库中的节点和 SSH 密文无法解密。

## 10. 卸载

停止但保留数据：

```bash
docker compose down
```

删除容器和网络但仍保留命名卷不会丢失数据。只有确认备份可恢复后，才可执行以下不可逆操作：

```bash
docker compose down --volumes
```
