# 运行密钥

在此目录创建仅本机可读的 `i5cloud_api_token`（至少 32 个随机字符）和 `i5cloud_setup_token`（至少 24 个随机字符）。初始化令牌只用于首次创建系统管理员，平台完成初始化后仍应保留该 Secret 以保证容器配置可重复启动，但接口会拒绝再次初始化。两个文件都已被根目录 `.gitignore` 忽略，不能提交到代码库。

示例：

```bash
umask 077
openssl rand -hex 32 > secrets/i5cloud_api_token
openssl rand -hex 24 > secrets/i5cloud_setup_token
docker compose pull
docker compose up -d
```

## 节点与 SSH 凭据

Compose 会把 `secrets/nodes` 只读挂载到容器内 `/run/secrets/i5cloud-nodes`。每个节点或 SSH 服务使用独立 JSON 文件，不要复用平台 API/初始化令牌。

节点管理会话示例（文件内容不能提交）：

```json
{"type":"session","username":"管理账号","password":"轮换后的管理密码"}
```

SSH 授权凭据示例：

```json
{"username":"root","password":"设备密码"}
```

Linux 主机建议由部署管理员创建并限制为容器 uid 10001 只读：

```bash
sudo install -o 10001 -g 10001 -m 0400 /dev/null secrets/nodes/node_hq.json
sudoedit secrets/nodes/node_hq.json
```

在平台表单中填写 `file:///run/secrets/i5cloud-nodes/node_hq.json`。更新文件后无需把内容重新提交到平台；密钥引用保持不变。生产备份不包含这些外部密钥文件，备份与恢复时必须单独管理。
