# VPass

自用零知识密码管理器（PWA）。Cloudflare Workers + D1 全栈托管，服务器只存密文，所有加解密在浏览器完成。

- 密码学规范：[docs/crypto-spec.md](docs/crypto-spec.md)
- 威胁模型：[docs/threat-model.md](docs/threat-model.md)
- 补充决定（待确认）：[docs/decisions.md](docs/decisions.md)
- 上线前差距清单：[docs/gap-list.md](docs/gap-list.md)

## 本地开发

```bash
pnpm install
cp apps/api/.dev.vars.example apps/api/.dev.vars   # 填入两段随机 base64（openssl rand -base64 32）
pnpm dev                                           # http://localhost:8787
pnpm invite:local                                  # 生成一个邀请码，用它注册（ADMIN_EMAILS 里的邮箱是管理员）
```

`pnpm dev` 跑的是真实的 Worker（含 CSP、Trusted Types 和本地 D1），不是 Vite 开发服务器。

## 测试

```bash
pnpm lint && pnpm typecheck && pnpm test   # 加密包（覆盖率 100%）、Worker 集成、前端单元
pnpm e2e                                   # Playwright：哨兵字符串、锁定、共享与密钥轮换、响应头
```

Playwright 浏览器装在 `E:\ms-playwright`：运行前设置 `PLAYWRIGHT_BROWSERS_PATH=E:\ms-playwright`。

## 首次部署（约半小时）

1. `pnpm --filter @vpass/api exec wrangler d1 create vpass-apac --location apac`，把返回的 `database_id` 填进 `apps/api/wrangler.toml`
2. `pnpm db:migrate:remote`
3. `wrangler secret put AUTH_PEPPER` 和 `wrangler secret put TOTP_ENC_KEY`（各用 `openssl rand -base64 32` 生成，**离线备份 AUTH_PEPPER**：丢了所有人都登不上）
4. 注册后，把你的用户 ID（`users.id`）写进 `wrangler.toml` 的 `ADMIN_USER_IDS`，重新部署
5. `pnpm build && pnpm --filter @vpass/api exec wrangler deploy` → 绑定自定义域名（`workers_dev = false` 已关闭 workers.dev 入口）
6. Cloudflare：SSL Full (strict)、Always Use HTTPS、最低 TLS 1.2；关闭 Rocket Loader、Email Obfuscation 等改写 HTML/JS 的功能；Access 邮箱白名单；WAF 限流覆盖 `/api/auth/*`
7. `pnpm invite:remote` 生成第一个邀请码 → 注册 → 打印应急卡
8. 用 securityheaders.com 和 SSL Labs 自测

之后合并到 `main` 并通过 CI，`deploy.yml` 自动部署（需在 GitHub Environment `production` 配 `CLOUDFLARE_API_TOKEN` 并设人工审批）。每次部署会在 GitHub Release 发布构建产物的 SHA-256 清单。
