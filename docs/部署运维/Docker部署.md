# Docker 正式部署

本文适用于 `vampirerune/device-management-platform:v1.0.11`。平台是单容器、单实例 SQLite 应用，不允许多个容器同时写同一个数据目录。

## 最简 Compose

```yaml
services:
  platform:
    image: vampirerune/device-management-platform:v1.0.11
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
- 系统设置可以分别修改 HTTP、HTTPS 端口。涉及监听器或证书的变更保存后会出现“重载面板”按钮，由平台自行平滑重载。
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

- 面板地址、面板证书和私钥路径；
- 反代地址，例如 `*.console.example.com`，界面中的 `*.` 为固定且不可编辑的前缀；
- 反代泛域名的证书和私钥路径。若面板证书已覆盖该泛域名，可留空复用；
- 反代端口默认复用面板 HTTP/HTTPS 端口，也可成对配置独立端口。

证书文件需要通过 volume 只读挂载到容器内，再在系统设置中填容器内路径。两套证书可位于同一挂载目录的不同子目录，也可分别挂载。平台可直接读取群晖 root-only 挂载，不修改、复制或放宽宿主机证书权限。

复用同一 HTTPS 端口时，平台根据 TLS SNI 为面板域名和反代子域名选择对应证书。保存端口或证书设置后，在系统设置页点击“重载面板”即可，不需要进入 Docker 管理器。平台重载时会重新读取保存的配置并重建 HTTP、HTTPS、反代、SMTP 与登录会话组件。

面板地址与反代地址同时配置后会成为严格的 Host 边界：面板 API 和页面只接受面板地址，反代根域及其任意非法子域直接返回 404，只有平台分配的反代入口可进入 Web 网关。面板地址不得等于反代地址，也不得位于反代泛域名之下。

证书挂载保持只读即可。容器入口仅在 NAS 的证书 ACL 不允许非 root 读取时，以只读方式预先打开证书文件，再以非 root 用户运行平台；平台不会复制、修改证书或要求写权限。若修改为另一个证书路径，新路径必须在容器内可读，否则重载会明确失败而不会继续误用旧证书。

配置面板地址后必须通过该面板域名访问，容器 IP 仅保留 `/health/live` 和 `/health/ready` 本机健康检查，不再提供面板。若由外部 Nginx、Caddy、网关或路由器终止 TLS，则把面板域名和 `*.反代域名` 一并转发到容器 HTTP 80，并保留原始 `Host`、WebSocket Upgrade 和 `X-Forwarded-Proto`。

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

`latest` 始终指向最新正式镜像；需要严格控制升级时间时固定 `v1.0.11` 这类完整版本号。`dev` 是测试镜像，可能随 `dev` 分支的每次推送变化，不得用于生产部署。

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

### 为什么反代地址偶尔被 Chrome 标记为“危险网站”

这是 Chrome Safe Browsing 的站点声誉或内容判定页面，不是 TLS 证书错误，不能仅凭域名前缀长度直接定因。v1.0.11 每次创建 Web 访问会话都会生成新的短随机 `web-*` 子域（例如 `web-k7m2x9p4`），不存在固定入口池、用户/设备派生域名或全局数量上限。随机域名本身不授权；访问仍必须通过一次性授权、来源绑定和有效平台登录，设备 Cookie 由每个随机 Origin 自然隔离。已被 Google 标记的历史主机不会因升级立即清除记录；若当前随机主机仍被提示，应记录完整主机名、时间、目标服务和 Chrome 警告详情，再由域名所有者通过 Search Console 的“安全性问题”提交复核。
