# VPass 密码学规范（v1）

本文件是整个项目唯一的密码学依据。实现只能照它来，任何偏离都要先改这里、经项目负责人确认。
蓝图没写明、实现时补充的细节集中在 [decisions.md](decisions.md)，标注为「补充」的条目同样有约束力。

## 4.1 算法与参数

| 用途 | 算法 | 参数 |
|---|---|---|
| 主密码 → 主密钥 | Argon2id（libsodium `crypto_pwhash`） | opslimit 3，memlimit 64 MiB，salt 16 字节随机，输出 32 字节；参数按用户存储，可升级 |
| 子密钥派生 | HKDF-SHA256（WebCrypto） | salt 为空（除 skPart 外），info 带版本号，输出 32 字节 |
| 对称加密 | XChaCha20-Poly1305 IETF | 每次 24 字节随机 nonce，必须带 AAD |
| 公钥加密 | X25519 密封箱（`crypto_box_seal`） | 每个用户一对密钥 |
| 公钥指纹 | SHA-256(publicKey) 前 20 字节 | 显示为 10 组、每组 4 位十六进制 |
| 服务端认证存储 | HMAC-SHA256 | 密钥为 Worker Secret `AUTH_PEPPER`，用 timingSafeEqual 比较 |
| 随机数 | `crypto.getRandomValues` / `randombytes_buf` | 禁用 `Math.random` |

主密码先做 Unicode NFKC 归一化再以 UTF-8 输入 Argon2id。

## 4.2 密钥层级

```
pwPart     = Argon2id(NFKC(主密码), kdfSalt)                                32 字节
skPart     = HKDF(SecretKey, salt=kdfSalt, info="vpass/v1/secret-key")  32 字节
masterKey  = pwPart XOR skPart
encKey     = HKDF(masterKey, info="vpass/v1/enc")    只用来包裹 accountKey
authHash   = HKDF(masterKey, info="vpass/v1/auth")   发给服务器登录用
accountKey = 随机 32 字节
wrappedAccountKey = AEAD(encKey, accountKey, AAD="account-key|v1|<userId>")
X25519 密钥对：公钥明文存；wrappedPrivateKey = AEAD(accountKey, sk, AAD="private-key|v1|<userId>")
vaultKey   = 每个保管库随机 32 字节；sealedVaultKey = crypto_box_seal(vaultKey, 成员公钥)
条目       = AEAD(vaultKey, pad(JSON), AAD="item|v1|<vaultId>|<itemId>")
恢复码     = 随机 20 字节，Base32 显示一次
recoveryKey  = HKDF(code, info="vpass/v1/recovery")       另外包裹一份 accountKey
recoveryAuth = HKDF(code, info="vpass/v1/recovery-auth")  供服务器校验
```

- `recoveryWrappedKey = AEAD(recoveryKey, accountKey, AAD="recovery-key|v1|<userId>")`（补充 D-03）
- 共享库名称：`nameEnc = AEAD(vaultKey, pad(UTF-8 名称), AAD="vault-name|v1|<vaultId>")`（补充 D-04）
- Secret Key：浏览器生成 16 字节随机数，从不上传服务器；编码见补充 D-01。
- 设备上的 Secret Key 以不可导出的 HKDF `CryptoKey` 存入 IndexedDB，绝不写入 localStorage。
- 中间多一层 accountKey：改主密码或用恢复码重置时，只需重新包裹 32 字节。

## 4.3 加密信封格式

```json
{ "v": 1, "alg": "xc20p", "n": "<24 字节 nonce>", "c": "<密文+16 字节标签>" }
```

- 字段为 Base64url（无填充）。
- 明文先用 `sodium_pad` 填充到 256 字节的倍数。
- AAD 不存进信封，由调用方根据上下文重新拼出（UTF-8 编码）。
- `v` 留给将来升级算法，解密时遇到未知版本或未知 `alg` 直接报错。

条目明文 JSON：

```json
{ "type": "login" | "note" | "card" | "contact",
  "name": "", "username": "", "password": "",
  "urls": [""], "totp": "", "notes": "",
  "fields": [{ "label": "", "value": "", "hidden": true }],
  "favorite": false, "passwordHistory": [{ "value": "", "changedAt": "" }] }
```

`contact` 类型（补充 D-05）额外带 `contact: { userId, email, publicKey, verifiedAt }`。

## 4.4 流程

- **注册**：客户端生成 userId（UUIDv4）、kdfSalt、Secret Key、accountKey、密钥对、个人保管库及其 vaultKey、恢复码；将全部密文、公钥、authHash 和邀请码一次性提交；本地生成应急卡（邮箱 + Secret Key + 恢复码，留白手写主密码），要求下载或打印。
- **登录**：prelogin 拿 salt 和参数 → 读取本机 Secret Key → 本地派生 → login 发送 authHash（及 TOTP）→ 拿到会话 Cookie 和密钥包 → 依次解开 accountKey、私钥、各 vaultKey。
- **新设备首次登录**：额外输入 Secret Key；带校验位，输错时本地直接提示，不消耗登录次数。登录成功后存入本机。
- **解锁**：只在本地重新派生 encKey 解开 accountKey，不经过服务器。
- **改主密码**：生成新 salt，用新主密码和原 Secret Key 派生新 encKey，包裹同一个 accountKey → 提交旧 authHash、新 authHash、新密钥包 → 服务器注销其他所有会话。
- **轮换 Secret Key**：生成新 Secret Key → 重新派生并包裹 accountKey → 注销所有其他会话 → 打印新应急卡。
- **恢复**：输入恢复码 → 用 recoveryAuth 向服务器证明身份 → 用 recoveryKey 解开 accountKey → 设置新主密码，同时生成新 Secret Key 和新恢复码 → 注销所有会话。

## 4.5 硬性规则

- 只用 libsodium 和 WebCrypto，禁止自己实现任何密码学原语，禁止引入其他加密库。
- 每次加密都重新生成 nonce；任何解密失败都抛异常，不允许静默返回空值。
- 密钥只以 Uint8Array 存在内存中，用完调用 `sodium.memzero`（尽力而为）。
- 任何密钥、明文、Secret Key、authHash 都不得进入日志、错误信息、URL、localStorage、sessionStorage。
