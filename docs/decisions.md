# 补充决定（待确认）

蓝图里没写明、实现时必须定下来的细节。全部已经按下表实现；如果你不同意某一条，改这里并通知 Claude 同步修改代码和测试。

| 编号 | 主题 | 决定 | 理由 |
|---|---|---|---|
| D-01 | Secret Key 编码 | 字母表 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`（去掉 I L O U）；128 位 → 26 个数据字符（末尾补 2 个 0 位）+ 1 个校验字符，显示为 `VP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX`；校验字符 = Σ(2i+1)·vᵢ mod 32（任意单字符错误必被发现）；输入时忽略大小写、空格和连字符，O→0、I/L→1 | 蓝图写「26 位 Base32 + 校验位」，但 26 位只有 130 位容量，放不下 128 位密钥 + 校验，所以多 1 位 |
| D-02 | AAD 里的 ID | UUID 一律小写；AAD 字符串按 UTF-8 编码 | 避免大小写导致解不开 |
| D-03 | 恢复包裹 | `recoveryWrappedKey = AEAD(recoveryKey, accountKey, AAD="recovery-key\|v1\|<userId>")` | 蓝图未给 AAD |
| D-04 | 共享库名称 | `AEAD(vaultKey, pad(名称), AAD="vault-name\|v1\|<vaultId>")`；个人库 name_enc 为空 | 蓝图未给 AAD |
| D-05 | 联系人条目 | 条目 type 增加 `contact`，带 `contact: {userId,email,publicKey,verifiedAt}` | 第 8 节要求核验结果存进个人保管库 |
| D-06 | 假 salt | `HMAC(PEPPER, "fake-salt\|v1\|" + 小写邮箱)` 前 16 字节，参数用默认值 | 同一邮箱每次相同，防枚举 |
| D-07 | 恢复接口 | 拆成两步：`POST /api/auth/recover/start`（email + recoveryAuth → userId、recoveryWrappedKey、公钥材料）和 `POST /api/auth/recover`（提交新密钥包） | 客户端必须先拿到 recoveryWrappedKey 才能解开 accountKey |
| D-08 | 增量同步参数 | `GET /api/sync?since=<vid>.<rev>,<vid>.<rev>`；未列出的库全量返回；keyEpoch 变化时客户端丢弃该库缓存 | revision 是按库计的，单个数字无法表达 |
| D-09 | 成员接口 | 增加 `GET /api/vaults/:vid/members`（成员可读，返回 userId、邮箱、公钥、角色）；`POST rotate` 中未列出的成员即被移除；owner 不可被移除 | 移人和轮换需要剩余成员的公钥 |
| D-10 | 限流实现 | 用 audit_log（新增索引）统计 15 分钟内同一 IP 哈希 / 同一账号的失败次数，再加 users 表的连续失败计数；生产环境另配 WAF 规则 | 本地 D1 可测，不依赖付费绑定；不改表结构，只加索引 |
| D-11 | 管理员 | `wrangler.toml` 的普通变量 `ADMIN_EMAILS`（逗号分隔），不是密钥 | 只有管理员能生成邀请码 |
| D-12 | 重新生成恢复码 | `POST /api/auth/recovery-code`（会话 + authHash） | 设置页需要 |
| D-13 | Secret Key 二维码 | Permissions-Policy 禁了摄像头，所以页面内不扫码：新设备用系统相机扫已登录设备上的二维码，复制粘贴到输入框。本机另存一份 `AEAD(accountKey, SecretKey, AAD="device-secret-key\|v1\|<userId>")` 到 IndexedDB，仅解锁后用来显示二维码 | 不可导出的 CryptoKey 无法再显示原文 |
| D-14 | 会话时长 | 绝对 30 天，闲置 14 天过期 | 蓝图未定 |
| D-15 | 服务端 TOTP 密钥 | AES-256-GCM（WebCrypto），密钥 `TOTP_ENC_KEY`，AAD `totp\|v1\|<userId>`；验证允许 ±1 个时间窗 | Worker 端不加载 libsodium |
| D-16 | 加密导出 | 导出密码 → Argon2id（默认参数、新 salt）→ AEAD，AAD `export\|v1`；文件含 salt 和参数 | 与主密码派生方式一致 |
| D-17 | 软删除 | `deleted=1` 且 `data` 置为空串 | 不留无用密文 |
| D-18 | kdf_params | `{"alg":"argon2id13","ops":3,"mem":67108864,"v":1}` | |
| D-19 | 单词短语 | EFF 短词表 1（1296 词，CC BY 3.0），`randombytes_uniform` 抽取 | libsodium 内部做拒绝采样 |
| D-20 | 注册确认恢复码 | 随机抽一组（4 个字符）让用户输入 | 「任意 4 位确认」 |
| D-21 | Bitwarden JSON 导入 | 只支持未加密的导出 | 加密导出需要 Bitwarden 的 KDF |
| D-22 | 程序更名为 VPass | 全部改名：包名 `@vpass/*`、Worker/D1 名 `vpass`、CSRF 头值 `vpass`、导出格式 `vpass-export`；HKDF info 标签改为 `vpass/v1/*`，Secret Key 前缀改为 `VP1-`，邀请码前缀改为 `VPI-`（2026-11-11 经确认，尚无真实数据） | 用户确认 |
