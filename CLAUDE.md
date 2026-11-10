# VPass — 自用零知识密码管理器

## 项目是什么
Cloudflare Workers + D1 全栈托管的网页版密码管理器（PWA），给自己和朋友用。服务器只存密文，所有加解密在浏览器完成。

## 必读
- docs/crypto-spec.md — 唯一密码学依据，任何加密相关代码必须与它一致
- docs/threat-model.md — 防什么、不防什么
- docs/decisions.md — 蓝图没写明、实现时做出的补充决定（待确认项）

## 绝对禁止
- 自己实现或修改密码学算法；引入 libsodium-wrappers-sumo 与 WebCrypto 以外的加密库
- 未经我确认修改 crypto-spec.md 或 packages/crypto 的公开接口
- 让明文、密钥、Secret Key、authHash 进入：服务端、日志、错误信息、URL、localStorage、sessionStorage
- Math.random / eval / new Function / dangerouslySetInnerHTML / 第三方 CDN 脚本
- 把任何密钥写进 wrangler.toml 或提交到仓库（用 wrangler secret）
- 为了让测试通过而删除或放宽安全测试

## 遇到以下情况停下来问我
- 规范没写明的密码学细节
- 需要新增依赖
- 需要改数据库结构或 API 契约

## 工作方式
- 先写测试再实现；packages/crypto 覆盖率必须 100%
- 每个带 :vid 的路由必须校验 vault_members 权限，并有越权测试
- 提交前运行：pnpm lint && pnpm typecheck && pnpm test
- 提交信息用中文，说明改了什么、为什么

## 常用命令
- pnpm dev — 本地启动（构建前端 + wrangler dev，含本地 D1），打开 http://localhost:8787
- pnpm test — 全部单元与集成测试
- pnpm e2e — Playwright
- pnpm db:migrate:local / db:migrate:remote
- pnpm invite:local — 生成一个本地邀请码

## 技术栈
TypeScript strict · Vite + React · Hono · Cloudflare Workers + D1 · zod · Vitest · Playwright · pnpm workspace
