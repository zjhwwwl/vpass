# 差距清单（P5 自查，对照蓝图第 2、4、7、9 节）

## 已完成并有测试覆盖

- 第 4 节密码学：Argon2id（与 argon2-cffi 向量一致）、HKDF（RFC 5869）、XChaCha20-Poly1305 + AAD + 256 字节填充、X25519 密封箱、指纹、2SKD、恢复码、TOTP（RFC 6238）；`packages/crypto` 覆盖率 100%
- 第 6 节 API：全部接口、中间件顺序、CSRF/Origin、会话 Cookie、限流与锁定、假 salt、409 冲突、轮换原子性（D1 batch + 事务内断言）；越权矩阵测试
- 第 7 节前端：密钥只在 VaultSession 内存；锁定清零；自动锁定 + Alt+L；剪贴板 30 秒清空；URL 仅 http(s) + noopener；无 innerHTML/eval；Argon2 在 Web Worker；IndexedDB 只存密文和不可导出的 CryptoKey
- 第 8 节共享：指纹核验存为加密联系人；公钥不一致阻止并红色警告；移人必轮换
- 第 9 节响应头：所有响应（含静态资源）统一添加，有自动化测试
- 第 10 节：哨兵端到端测试（请求、响应、IndexedDB、D1 全量）通过；ESLint 禁用规则生效

## 未完成 / 需要你决定

| 项 | 说明 |
|---|---|
| 补充决定 D-01…D-22 | 全部按 decisions.md 实现，需要你逐条确认，尤其 D-01（Secret Key 多 1 位校验字符）；D-22 改名已确认 |
| 应急卡 PDF | 用浏览器“打印 → 另存为 PDF”，没有引入 PDF 库（避免新依赖） |
| 新设备扫码 | 页面内不调用摄像头（Permissions-Policy 禁止），改为系统相机扫码后粘贴（D-13） |
| HIBP 泄露检测 | 未实现：需要放开 CSP 的 connect-src 到第三方域名，与“无第三方连接”冲突。安全报告只做本地弱密码/重复密码 |
| Turnstile | 未接入（可选项），依赖第三方脚本 |
| Workers Rate Limiting 绑定 | 用 D1 审计日志实现（D-10）；生产仍建议加 WAF 规则 |
| Service Worker 缓存 index.html | 为了离线可打开，缓存了“当前构建版本”的 index.html（与 SW 版本绑定），仅在网络失败时使用 |
| 部署链路 | 硬件密钥 2FA、分支保护、Environment 审批、自定义域名、Access、WAF 需要在 Cloudflare/GitHub 控制台手动配置 |
| P6 独立安全审查 | 尚未进行，按蓝图应在新会话里由干净的审计者执行 |
| P7 浏览器插件 | v2 |
