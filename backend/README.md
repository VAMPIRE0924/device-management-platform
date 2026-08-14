# I5CLOUD 后端

完整项目介绍和部署方式见 [根目录 README](../README.md) 与 [Docker 正式部署](../docs/部署运维/Docker部署.md)。

Go 控制面基线，目标是生成可嵌入前端资源的单一二进制，并在 Docker 中使用 SQLite 持久化。

## 当前能力

- SQLite WAL、外键、版本化迁移和事务审计；
- 健康检查与生产模式配置校验；
- Bearer 管理令牌保护的 `/api/v1`；
- 接入节点和客户项目的创建、列表与字段校验；
- 项目实际 CIDR 与客户端 Docker/宿主机运行地址分离；
- 设备、Endpoint、访问会话、发现任务、转发、用户、策略和审计的 V1 数据表。

## 启动

```bash
go run ./cmd/i5cloud serve
```

默认监听 `127.0.0.1:8088`，数据库为 `./data/i5cloud.db`。

生产模式必须提供至少 32 字符的平台 API 令牌：

```bash
I5CLOUD_MODE=pro \
I5CLOUD_LISTEN_ADDR=0.0.0.0:8088 \
I5CLOUD_DATA_DIR=/data \
I5CLOUD_API_TOKEN_FILE=/run/secrets/i5cloud_api_token \
I5CLOUD_SETUP_TOKEN_FILE=/run/secrets/i5cloud_setup_token \
./i5cloud serve
```

生产模式同时要求至少 24 字符的首次初始化令牌，且两个令牌必须不同。开发环境也可以直接设置环境变量；生产环境优先使用 Secret 文件，避免把密钥写入命令历史。

正式部署必须配置会话子域名：

```bash
I5CLOUD_ACCESS_DOMAIN=remote.example.com
I5CLOUD_ACCESS_SCHEME=https
```

同时把 `*.remote.example.com` 的 wildcard DNS 和证书指向平台。每个 Web 会话拥有独立站点根路径，可兼容根路径资源、动态 API 和 WebSocket。路径前缀只保留为无泛域名时的受限后备路径，不作为生产部署方案。

平台位于反向代理后方时，只应信任实际代理网段提供的来源地址头：

```bash
I5CLOUD_TRUSTED_PROXY_CIDRS=172.20.0.0/24
```

未配置或请求来源不属于该范围时，平台忽略 `X-Forwarded-For`，防止客户端伪造审计来源 IP。生产入口必须由 HTTPS 反向代理提供，且 `I5CLOUD_COOKIE_SECURE=true`；生产模式仅在监听回环地址的本地验收场景允许显式关闭安全 Cookie。配置访问子域名时，生产模式强制使用 HTTPS。

系统管理员可从 `/api/v1/data/backup` 下载 SQLite 在线一致性快照。快照包含密码哈希和密钥引用，应按敏感备份保存。

恢复只能在平台停服后执行：

```bash
I5CLOUD_MODE=pro \
I5CLOUD_DB_PATH=/data/i5cloud.db \
I5CLOUD_API_TOKEN_FILE=/run/secrets/i5cloud_api_token \
I5CLOUD_SETUP_TOKEN_FILE=/run/secrets/i5cloud_setup_token \
./i5cloud restore /backup/i5cloud-backup.db
```

命令会校验备份完整性和 schema 版本；已有数据库会先保留 `.before-restore-<UTC>.db` 安全快照。检测到数据库仍在使用时会拒绝恢复。

## 检查

```bash
go test ./...
go vet ./...
go build ./cmd/i5cloud
```
