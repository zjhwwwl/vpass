import { CSRF_HEADER, CSRF_VALUE, type KeyBundleDto, type MemberDto, type SessionInfo, type SyncRes, type ItemDto } from '@vpass/shared';
import type { KdfParams } from '@vpass/crypto';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly body: Record<string, unknown>,
  ) {
    super(code);
  }
}

/** Offline (network failure), as opposed to a server error. */
export class OfflineError extends Error {
  constructor() {
    super('offline');
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers: {
        ...(method !== 'GET' ? { [CSRF_HEADER]: CSRF_VALUE } : {}),
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new OfflineError();
  }
  let data: Record<string, unknown> = {};
  try {
    data = (await res.json()) as Record<string, unknown>;
  } catch {
    /* empty body */
  }
  if (!res.ok) throw new ApiError(res.status, typeof data.error === 'string' ? data.error : 'internal', data);
  return data as T;
}

export interface Credentials {
  kdfSalt: string;
  kdfParams: KdfParams;
  authHash: string;
  wrappedAccountKey: string;
}

export const api = {
  prelogin: (email: string) => call<{ kdfSalt: string; kdfParams: KdfParams }>('POST', '/api/auth/prelogin', { email }),
  register: (payload: unknown) => call<KeyBundleDto>('POST', '/api/auth/register', payload),
  login: (email: string, authHash: string, totp?: string, deviceLabel?: string) =>
    call<KeyBundleDto>('POST', '/api/auth/login', { email, authHash, ...(totp ? { totp } : {}), ...(deviceLabel ? { deviceLabel } : {}) }),
  me: () => call<KeyBundleDto>('GET', '/api/auth/me'),
  logout: () => call<{ ok: true }>('POST', '/api/auth/logout'),
  sessions: () => call<{ sessions: SessionInfo[] }>('GET', '/api/auth/sessions'),
  revokeSession: (id: string) => call<{ ok: true }>('DELETE', `/api/auth/sessions/${encodeURIComponent(id)}`),
  changePassword: (oldAuthHash: string, creds: Credentials) => call<KeyBundleDto>('POST', '/api/auth/password', { oldAuthHash, ...creds }),
  recoveryCode: (authHash: string, recoveryWrappedKey: string, recoveryAuth: string) =>
    call<{ ok: true }>('POST', '/api/auth/recovery-code', { authHash, recoveryWrappedKey, recoveryAuth }),
  recoverStart: (email: string, recoveryAuth: string) =>
    call<{ userId: string; recoveryWrappedKey: string; publicKey: string; wrappedPrivateKey: string }>('POST', '/api/auth/recover/start', { email, recoveryAuth }),
  recover: (body: unknown) => call<KeyBundleDto>('POST', '/api/auth/recover', body),
  totpSetup: () => call<{ secret: string; uri: string }>('POST', '/api/auth/totp/setup'),
  totpEnable: (code: string) => call<{ ok: true }>('POST', '/api/auth/totp/enable', { code }),
  totpDisable: (authHash: string) => call<{ ok: true }>('POST', '/api/auth/totp/disable', { authHash }),
  sync: (since: string) => call<SyncRes>('GET', `/api/sync${since ? `?since=${since}` : ''}`),
  putItem: (vid: string, iid: string, data: string, keyEpoch: number, expectedRevision: number | null) =>
    call<{ revision: number; vaultRevision: number }>('PUT', `/api/vaults/${vid}/items/${iid}`, { data, keyEpoch, expectedRevision }),
  deleteItem: (vid: string, iid: string, expectedRevision: number) =>
    call<{ revision: number; vaultRevision: number }>('DELETE', `/api/vaults/${vid}/items/${iid}`, { expectedRevision }),
  createVault: (id: string, nameEnc: string, sealedVaultKey: string) => call<{ id: string }>('POST', '/api/vaults', { id, nameEnc, sealedVaultKey }),
  members: (vid: string) => call<{ members: MemberDto[] }>('GET', `/api/vaults/${vid}/members`),
  putMember: (vid: string, uid: string, sealedVaultKey: string, role: 'editor' | 'viewer', keyEpoch: number) =>
    call<{ ok: true }>('PUT', `/api/vaults/${vid}/members/${uid}`, { sealedVaultKey, role, keyEpoch }),
  rotate: (vid: string, body: unknown) => call<{ ok: true; removed: string[] }>('POST', `/api/vaults/${vid}/rotate`, body),
  lookup: (email: string) => call<{ userId: string; email: string; publicKey: string }>('GET', `/api/users/lookup?email=${encodeURIComponent(email)}`),
  createInvite: () => call<{ code: string; expiresAt: number }>('POST', '/api/invites'),
};

export type { ItemDto };

const MESSAGES: Record<string, string> = {
  invalid_credentials: '邮箱、主密码或 Secret Key 不正确',
  totp_required: '请输入二次验证码',
  rate_limited: '尝试次数过多，请 15 分钟后再试',
  account_locked: '账号已暂时锁定，请 15 分钟后再试',
  invalid_invite: '邀请码无效或已被使用',
  email_taken: '该邮箱已注册',
  conflict: '数据已在别处被修改',
  forbidden: '没有权限',
  not_found: '找不到',
  unauthorized: '登录已过期，请重新登录',
  csrf: '请求被拒绝',
  bad_request: '请求格式不正确',
  offline: '网络不可用',
  decrypt_failed: '解密失败：主密码或 Secret Key 不正确',
  secret_key_format: 'Secret Key 格式不对（应以 VP1- 开头）',
  secret_key_checksum: 'Secret Key 校验失败，请检查是否抄错',
  recovery_code_format: '恢复码格式不对',
};

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError || e instanceof OfflineError || e instanceof Error) return MESSAGES[e.message] ?? `出错了（${e.message}）`;
  return '出错了';
}
