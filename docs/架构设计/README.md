# 架构设计索引

| 文档 | 内容 |
|---|---|
| [系统架构](./系统架构.md) | 进程、组件、数据流和信任边界 |
| [数据模型](./数据模型.md) | SQLite 实体、约束、迁移和删除语义 |
| [节点适配器](./节点适配器.md) | 节点能力映射、鉴权和状态一致性 |

架构文档描述当前实现，不用于宣布未来能力已经完成。数据库的最终事实以 `backend/internal/store/migrations.go` 为准，API 的最终事实以 `backend/internal/api` 和前端 `frontend/lib/api.ts` 为准。
