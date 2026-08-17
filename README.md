# Device Management Platform（设备管理平台）

[![Release](https://img.shields.io/github/v/release/VAMPIRE0924/device-management-platform?display_name=tag)](https://github.com/VAMPIRE0924/device-management-platform/releases/latest)
[![Verify](https://github.com/VAMPIRE0924/device-management-platform/actions/workflows/verify.yml/badge.svg?branch=main)](https://github.com/VAMPIRE0924/device-management-platform/actions/workflows/verify.yml)
[![Docker Image](https://img.shields.io/badge/docker-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/vampirerune/device-management-platform)

面向客户内网设备的远程管理平台。平台通过重构版 NPS 的 HMAC-SHA256 管理 API 接入既有 Client 和 SOCKS隧道，提供设备发现、隔离 Web 访问、WebSocket、WebSSH、权限控制与访问审计。

- 当前正式版本：[`v2.0.0`](https://github.com/VAMPIRE0924/device-management-platform/releases/tag/v2.0.0)
- Docker 镜像：[`vampirerune/device-management-platform`](https://hub.docker.com/r/vampirerune/device-management-platform)
- 更新记录：[`CHANGELOG.md`](https://github.com/VAMPIRE0924/device-management-platform/blob/main/CHANGELOG.md)

## v2.0 主要能力

- 使用 HTTPS、TLS 主机名校验和 HMAC-SHA256 请求签名连接新版 NPS API。
- 管理 NPS 接入节点与既有 Client；项目绑定 Client，不代替 NPS 管理 Client 生命周期。
- 统一展示 SOCKS隧道运行状态、流量活跃状态、空闲剩余时长、预计关闭时间与累计流量。
- SOCKS 空闲倒计时由浏览器本地逐秒更新，仅在进入页面或手动刷新时同步节点，不持续轮询 NPS。
- 按项目配置扫描网段与端口，发现 HTTP、HTTPS、SSH 等内网服务。
- 每台设备可配置多个 Web 服务，HTTPS 参数按服务独立保存。
- 每个 Web 会话使用独立随机子域名，支持原生 Cookie、重定向、动态接口、WebSocket 和独立证书。
- WebSSH 支持已保存凭据、本地密钥和单次临时凭据。
- 提供系统管理员、项目管理员、运维用户和临时用户四级权限，以及访问策略、MFA、运行监控、操作审计、备份与恢复。
- 登录用户可自助修改密码；敏感信息按最小权限返回，节点和 SSH 凭据加密保存。

## 快速部署

要求 Docker Engine 24+ 与 Docker Compose v2。生产环境建议固定完整版本号：

```bash
git clone https://github.com/VAMPIRE0924/device-management-platform.git
cd device-management-platform

export DMP_IMAGE=vampirerune/device-management-platform:v2.0.0
docker compose pull
docker compose up -d
docker compose ps
```

容器变为 `healthy` 后访问 `http://<容器IP>/`，首次打开页面时创建系统管理员。平台会自动生成内部 API 令牌、SQLite 数据库和凭据加密主密钥，不需要手工设置初始化令牌。

Compose 默认不映射宿主机端口：容器监听 HTTP 80，配置证书后同时监听 HTTPS 443。部署环境应为容器网络配置可达路由；确实无法直达容器 IP 时，再自行增加端口映射。

## 域名与远程访问

正式环境需要分别配置面板域名与 Web 反代泛域名，例如：

- 面板：`dmp.example.com`
- Web 反代：`*.console.example.com`

两者形成严格的 Host 隔离边界。面板域名不承载目标设备页面，只有平台为有效访问会话分配的随机反代子域名才能进入 Web 网关。外部反向代理必须保留原始 `Host`、`X-Forwarded-Proto` 和 WebSocket Upgrade 请求头。

创建访问会话时，平台按需启动对应 SOCKS隧道。Web、WebSocket 与 WebSSH 的真实流量会更新活动时间；平台和 NPS 均按最长 30 分钟无流量回收。拨号失败或会话过期后不会擅自恢复旧授权。

## 镜像与版本

| Docker 标签 | 用途 | 建议 |
|---|---|---|
| `v2.0.0` | 当前固定正式版本 | 生产环境推荐 |
| `main` | 最新正式版本的滚动标签 | 接受人工拉取时跟随 |
| `dev` | `dev` 分支的开发测试镜像 | 不得连接生产数据目录 |

正式镜像包含 `linux/amd64` 与 `linux/arm64`。项目不发布 `latest` 标签，避免部署端在未明确选择渠道时自动跨版本升级。

```bash
docker pull vampirerune/device-management-platform:v2.0.0
docker buildx imagetools inspect vampirerune/device-management-platform:v2.0.0
```

## 数据、安全与备份

- `/data` 持久化 SQLite 数据库、内部 API 令牌、凭据主密钥和网页覆盖配置；只允许单实例写入同一数据目录。
- NPS API 密钥、节点与 SSH 密码、SMTP 密码、MFA 密钥、TLS 私钥和 SSH 私钥不会提交到 Git。
- 节点和 SSH 凭据写入数据库前使用数据目录中的独立主密钥加密。
- 数据库、凭据主密钥、配置和外部 Secret 必须按同一批次备份与恢复。
- 正式环境必须启用 HTTPS、安全 Cookie，并把可信反向代理限制为明确的地址或网段。
- 登录会话默认闲置 15 分钟退出、最长 12 小时；具体策略可在系统设置中调整。
- 升级前先从系统设置下载一致性数据库备份，并备份完整 `/data` 与外部证书、密钥。

升级固定版本时修改 `DMP_IMAGE` 后重新创建容器：

```bash
export DMP_IMAGE=vampirerune/device-management-platform:v2.0.0
docker compose pull
docker compose up -d
docker compose ps
```

## 从源码构建与验证

```bash
docker build \
  --build-arg VERSION=v2.0.0 \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t device-management-platform:v2.0.0 .
```

开发环境使用 Go 1.26.6、Node.js 22 和 Docker。完整检查入口：

```bash
cd frontend && npm ci && cd ..
./scripts/verify.sh
./scripts/acceptance-local.sh
./scripts/acceptance-container.sh
```

验证包含 Go race 测试、静态检查、依赖漏洞检查、前端类型与 ESLint、渲染契约、单二进制构建、本地/容器黑盒、备份恢复和容器漏洞扫描。

## 许可

仓库未声明开源许可证。未经许可，不授予复制、修改或再分发权利。
