# Docker 正式部署

本文适用于 `vampirerune/device-management-platform:v1.0.4`。平台是单容器、单实例 SQLite 应用，不允许多个容器同时写同一个数据目录。

## 最简 Compose

```yaml
services:
  platform:
    image: vampirerune/device-management-platform:v1.0.4
    container_name: device-management-platform
    restart: unless-stopped
    volumes:
      - ./platform-data:/data
```

Compose 不需要部署令牌、域名、端口或数据库参数，也不声明宿主机 `ports` 映射。容器首次启动会自动创建内部 API 令牌、SQLite 数据库和加密主密钥；首次打开页面时由用户创建系统管理员。

使用目录挂载时，容器入口会把专用 `/data` 目录校正给运行用户，然后以非 root 用户启动平台。不要把 `/data` 指向包含其他文件的共享目录。

## 网络与端口

- HTTP 默认监听容器的 `80` 端口。
- 配置证书后，HTTPS 同时监听容器的 `443` 端口。
- 系统设置可以分别修改 HTTP、HTTPS 端口；保存后重启容器生效。
- 上面的 Compose 不发布宿主机端口。请给容器网络配置静态路由，直接通过容器 IP 访问。

若部署环境没有通往容器 IP 的路由，才需要自行增加端口映射；这不是仓库默认部署方式。

## 启动与首次初始化

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 platform
```

容器状态变为 `healthy` 后，访问 `http://<容器IP>/`，填写显示名称、管理员账号和密码即可。平台不会要求手工填写内部令牌。

## HTTPS、面板域名与反代域名

在“系统设置”中分开配置：

- 证书文件路径与私钥文件路径；
- 面板地址，例如 `admin.example.com`；
- 反代地址，例如 `*.admin.example.com`，界面中的 `*.` 为固定前缀。

证书文件需要通过额外 volume 挂载到容器内，然后在系统设置中填写容器内路径。保存端口或证书设置后重启容器：

```bash
docker compose restart platform
```

平台直管证书时可直接访问 `https://<容器IP>/` 或配置好的面板域名。若由外部 Nginx、Caddy、网关或路由器终止 TLS，则把面板域名和 `*.反代域名` 一并转发到容器 HTTP 80，并保留原始 `Host`、WebSocket Upgrade 和 `X-Forwarded-Proto`。

## 数据与备份

持久化目录至少包含：

- `platform.db`：SQLite 数据库；
- `api.token`：自动生成的内部 API 令牌；
- `credentials.key`：节点与 SSH 密码加密主密钥；
- `settings.override.conf`：网页保存的系统设置；
- `smtp-password`、`mfa.key`：启用相关功能后生成。

在线运行时请从“系统设置”下载 SQLite 一致性备份。迁移或恢复时，数据库、加密主密钥和配置必须来自同一个备份批次。

## 升级

```bash
docker compose pull
docker compose up -d
docker compose ps
```

`latest` 始终指向最新正式镜像；需要严格控制升级时间时固定 `v1.0.4` 这类完整版本号。

## 常见问题

### `/data` permission denied 并无限重启

先拉取最新镜像并重新创建容器：

```bash
docker compose pull
docker compose up -d --force-recreate
```

当前镜像会在启动阶段修复专用数据目录所有权。若仍失败，检查宿主机共享目录 ACL 是否明确禁止容器 root 修改目录所有者。

### HTTP 登录后仍停留在登录页

v1.0.4 起，登录 Cookie 会按实际访问协议自动设置：HTTP 不带 `Secure`，HTTPS 自动带 `Secure`。旧版本请升级并强制重新创建容器。
