# I5CLOUD 前端

React + TypeScript 管理界面，已接入真实 `/api/v1`，不包含预置业务数据。生产构建输出静态资源并嵌入 Go 单二进制。

```bash
npm ci
npm run dev
npm run typecheck:spa
npm run lint
npm run build:spa
```

页面与产品边界见 [产品决策](../docs/产品决策/README.md)，完整部署方式见 [Docker 正式部署](../docs/部署运维/Docker部署.md)。正式镜像只使用 `build:spa` 输出，不运行前端开发服务器。
