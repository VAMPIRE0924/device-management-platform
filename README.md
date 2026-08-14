# I5CLOUD 远程管理平台

I5CLOUD 是面向客户内网设备的远程管理平台。平台接入重构版 NPS 节点，以项目绑定既有 Client，并通过同 ID 的 SOCKS 通道完成设备发现、Web 管理入口和 WebSSH 访问。

[Docker Hub](https://hub.docker.com/r/vampirerune/i5cloud) · [部署文档](./docs/部署运维/Docker部署.md) · [产品资料](./docs/README.md) · [验收标准](./docs/验收标准/README.md)

## 当前版本

- 正式版本：`v1.0.0`
- Docker 镜像：`vampirerune/i5cloud:v1.0.0`
- 运行形态：React SPA 嵌入 Go 单二进制，SQLite 持久化，单容器部署
- 支持架构：`linux/amd64`、`linux/arm64`

## 核心能力

- 管理 NPS 接入节点，节点账号和密码加密保存；查看或新增 NPS Client。
- 客户项目绑定既有 Client，Client ID 与 SOCKS ID 一致。
- 平台控制 SOCKS 通道启停，远程访问时自动启动；NPS 负责空闲关闭策略。
- 按项目 CIDR 和自定义端口发现内网服务，不限制已登记设备的访问。
- 每台设备可配置多个 HTTP/HTTPS 服务；每个 HTTPS 服务独立配置校验主机名。
- Web 服务通过独立泛域名反向代理，兼容根路径资源、Cookie、WebSocket 和重定向。
- WebSSH 支持管理员保存的密码或本地密钥，也支持用户临时输入凭据且不保存。
- 用户、访问策略、会话监控、操作审计、MFA、在线备份和离线恢复。

## 快速部署

要求：Docker Engine 24+ 和 Docker Compose v2。

```bash
git clone https://github.com/VAMPIRE0924/-.git i5cloud
cd i5cloud
cp .env.example .env
cp conf/i5cloud.conf.example conf/i5cloud.conf

umask 077
openssl rand -hex 32 > secrets/i5cloud_api_token
openssl rand -hex 24 > secrets/i5cloud_setup_token

# 修改 conf/i5cloud.conf 中的 panel_domain、access_domain 和证书/代理配置
docker compose pull
docker compose up -d
docker compose ps
```

默认仅监听 `127.0.0.1:8088`，应由 HTTPS 反向代理对外提供服务。正式环境必须同时解析：

- 面板域名，例如 `admin.example.com`；
- 泛域名，例如 `*.admin.example.com`，供每个 Web 会话使用独立子域名。

首次打开面板后，使用 `secrets/i5cloud_setup_token` 的内容创建系统管理员。完整步骤、Nginx/Caddy 示例、升级与恢复方式见 [Docker 部署](./docs/部署运维/Docker部署.md)。

## 数据与安全

- `/data` 使用 Docker volume 持久化，SQLite 只允许单实例写入。
- API 令牌、初始化令牌、节点凭据、SMTP 密码、TLS 私钥和 SSH 私钥不得提交到 Git。
- 节点和 SSH 密码写入 SQLite 前使用数据目录中的独立主密钥加密。
- 下载的数据库备份不包含解密主密钥、MFA 主密钥和外部 Secret，恢复时必须成组提供。
- 正式环境必须使用 HTTPS、安全 Cookie 和可信反向代理来源限制。

## 本地构建与质量门

```bash
./scripts/verify.sh
./scripts/acceptance-local.sh
./scripts/acceptance-container.sh
```

从源码构建镜像：

```bash
docker build \
  --build-arg VERSION=v1.0.0 \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -t i5cloud:v1.0.0 .
```

## 项目结构

```text
backend/       Go API、网关、WebSSH、SQLite 与节点适配器
frontend/      React/TypeScript 管理界面
conf/          正式配置模板
docs/          产品、架构、验收和部署资料
scripts/       构建与验收脚本
secrets/       本地 Secret 说明；真实内容被 Git 忽略
compose.yaml   正式 Docker Compose 部署文件
```

本仓库未声明开源许可证。未经许可，不授予复制、修改或再分发权利。
