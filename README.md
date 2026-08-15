# Device Management Platform（设备管理平台）

面向客户内网设备的远程管理平台。系统接入重构版 NPS 节点，项目绑定既有 Client，并通过同 ID 的 SOCKS 通道完成设备发现、Web 服务访问和 WebSSH 运维。

[Docker Hub](https://hub.docker.com/r/vampirerune/device-management-platform) · [部署说明](./docs/部署运维/Docker部署.md) · [运维与备份](./docs/部署运维/构建部署与备份.md) · [登录安全](./docs/部署运维/登录安全与双重认证.md) · [安全边界](./docs/安全边界.md)

## 主要功能

- 管理 NPS 接入节点，节点认证信息加密保存。
- 查看和新增 NPS Client；项目只绑定既有 Client，不代替 NPS 管理 Client 生命周期。
- 平台控制 SOCKS 通道启停，远程访问时自动启动；NPS 负责空闲关闭。
- 按项目配置多个扫描网段与端口，发现 HTTP、HTTPS、SSH 等内网服务。
- 每台设备可配置多个 Web 服务，HTTPS 参数按服务独立保存。
- 基于独立泛域名代理 Web 服务，支持独立反代证书、可选独立端口、Cookie、重定向、动态接口和 WebSocket。
- WebSSH 支持保存的密码或本地密钥，也支持单次临时凭据。
- 提供用户权限、访问策略、运行监控、操作审计、MFA、备份和恢复。

## Docker 快速部署

要求 Docker Engine 24+ 与 Docker Compose v2。

```bash
git clone https://github.com/VAMPIRE0924/device-management-platform.git
cd device-management-platform

docker compose pull
docker compose up -d
docker compose ps
```

Compose 不设置宿主机 `ports` 映射。容器默认监听 HTTP 80；在系统设置中配置证书后，同时监听 HTTPS 443。请为容器网络配置可达路由，然后直接访问容器 IP。大多数设置保存后立即生效；监听端口、证书或运行组件发生变化时，页面会显示“重载面板”按钮，由平台自行平滑重载，无需手工重启 Docker。

正式部署应配置面板域名和对应泛域名，例如：

- `admin.example.com`
- `*.admin.example.com`

首次打开面板时直接创建系统管理员，无需部署令牌。平台内部 API 令牌由容器自动生成并持久化到 `/data/api.token`。完整配置见 [Docker 部署说明](./docs/部署运维/Docker部署.md)。

## 镜像

```bash
docker pull vampirerune/device-management-platform:v1.0.8
```

已发布 `linux/amd64` 与 `linux/arm64` 镜像。生产环境建议固定完整版本号，不要长期依赖 `latest`。

## 数据与安全

- `/data` 使用 Docker volume 持久化；SQLite 只允许单实例写入。
- 内部 API 令牌、节点凭据、SMTP 密码、证书私钥和 SSH 私钥不会提交到 Git。
- 节点和 SSH 密码写入数据库前使用数据目录中的独立主密钥加密。
- 数据库、主密钥、配置与外部 Secret 必须按同一批次备份和恢复。
- 正式环境必须启用 HTTPS、安全 Cookie，并正确限制可信反向代理来源。
- 登录会话默认闲置 15 分钟退出，最长 12 小时；可在系统设置中调整。

## 从源码构建

```bash
docker build \
  --build-arg VERSION=v1.0.8 \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t device-management-platform:v1.0.8 .
```

仓库未声明开源许可证。未经许可，不授予复制、修改或再分发权利。
