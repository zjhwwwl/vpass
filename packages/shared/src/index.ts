// Request/response contracts shared by apps/web and apps/api. Everything sensitive here is ciphertext,
// a public key, or a high-entropy hash; never plaintext.
import { z } from 'zod';

// No runtime code generation: the CSP forbids eval/new Function, so keep zod off its JIT path.
z.config({ jitless: true });

export const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const uuid = z.string().regex(UUID_V4, 'uuid_v4');
export const b64u = (min: number, max: number) =>
  z
    .string()
    .regex(/^[A-Za-z0-9_-]+$/)
    .min(min)
    .max(max);
/** 32 bytes, base64url, no padding = 43 chars. */
export const b64u32 = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const salt16 = z.string().regex(/^[A-Za-z0-9_-]{22}$/);
/** crypto_box_seal(32-byte key) = 32 + 48 = 80 bytes → 107 chars. */
export const sealedKey = z.string().regex(/^[A-Za-z0-9_-]{107}$/);
/** Envelope JSON string. Items capped at 256 KiB. */
export const envelope = (max = 4096) =>
  z
    .string()
    .min(40)
    .max(max)
    .refine((s) => {
      try {
        const e = JSON.parse(s) as Record<string, unknown>;
        return e.v === 1 && e.alg === 'xc20p' && typeof e.n === 'string' && typeof e.c === 'string' && Object.keys(e).length === 4;
      } catch {
        return false;
      }
    }, 'envelope');
export const ITEM_MAX = 256 * 1024;

export const email = z
  .string()
  .trim()
  .toLowerCase()
  .max(254)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'email');

export const kdfParams = z.object({
  alg: z.literal('argon2id13'),
  ops: z.number().int().min(3).max(10),
  mem: z
    .number()
    .int()
    .min(64 * 1024 * 1024)
    .max(256 * 1024 * 1024),
  v: z.literal(1),
});
export type KdfParamsDto = z.infer<typeof kdfParams>;

export const role = z.enum(['owner', 'editor', 'viewer']);
export type Role = z.infer<typeof role>;
export const totpCode = z.string().regex(/^\d{6}$/);
export const deviceLabel = z.string().trim().max(80);

// ---------------------------------------------------------------- auth

export const preloginReq = z.object({ email });
export const preloginRes = z.object({ kdfSalt: salt16, kdfParams });

const credentials = {
  kdfSalt: salt16,
  kdfParams,
  authHash: b64u32,
  wrappedAccountKey: envelope(),
};

export const registerReq = z.object({
  inviteCode: z.string().trim().min(8).max(64),
  userId: uuid,
  email,
  ...credentials,
  recoveryWrappedKey: envelope(),
  recoveryAuth: b64u32,
  publicKey: b64u32,
  wrappedPrivateKey: envelope(),
  personalVault: z.object({ id: uuid, sealedVaultKey: sealedKey }),
  deviceLabel: deviceLabel.optional(),
});
export type RegisterReq = z.infer<typeof registerReq>;

export const loginReq = z.object({ email, authHash: b64u32, totp: totpCode.optional(), deviceLabel: deviceLabel.optional() });

export const keyBundle = z.object({
  userId: uuid,
  email: z.string(),
  kdfSalt: salt16,
  kdfParams,
  wrappedAccountKey: z.string(),
  publicKey: b64u32,
  wrappedPrivateKey: z.string(),
  isAdmin: z.boolean(),
  totpEnabled: z.boolean(),
});
export type KeyBundleDto = z.infer<typeof keyBundle>;

export const passwordChangeReq = z.object({ oldAuthHash: b64u32, ...credentials });

export const recoverStartReq = z.object({ email, recoveryAuth: b64u32 });
export const recoverStartRes = z.object({
  userId: uuid,
  recoveryWrappedKey: z.string(),
  publicKey: b64u32,
  wrappedPrivateKey: z.string(),
});
export const recoverReq = z.object({
  email,
  recoveryAuth: b64u32,
  ...credentials,
  newRecoveryWrappedKey: envelope(),
  newRecoveryAuth: b64u32,
  deviceLabel: deviceLabel.optional(),
});

export const recoveryCodeReq = z.object({ authHash: b64u32, recoveryWrappedKey: envelope(), recoveryAuth: b64u32 });

export const totpSetupRes = z.object({ secret: z.string(), uri: z.string() });
export const totpEnableReq = z.object({ code: totpCode, authHash: b64u32 });
export const totpDisableReq = z.object({ authHash: b64u32 });

export const sessionInfo = z.object({
  id: z.string(),
  createdAt: z.number(),
  lastSeenAt: z.number(),
  expiresAt: z.number(),
  deviceLabel: z.string().nullable(),
  current: z.boolean(),
});
export type SessionInfo = z.infer<typeof sessionInfo>;

export const inviteRes = z.object({ code: z.string(), expiresAt: z.number() });

// ---------------------------------------------------------------- vaults & sync

export const itemDto = z.object({
  id: uuid,
  data: z.string(),
  keyEpoch: z.number().int(),
  revision: z.number().int(),
  deleted: z.boolean(),
  updatedAt: z.number(),
});
export type ItemDto = z.infer<typeof itemDto>;

export const vaultDto = z.object({
  id: uuid,
  kind: z.enum(['personal', 'shared']),
  ownerId: uuid,
  nameEnc: z.string().nullable(),
  revision: z.number().int(),
  keyEpoch: z.number().int(),
  role,
  sealedVaultKey: z.string(),
  /** true when `items` is the full set (no or stale `since`), false when it is a delta. */
  full: z.boolean(),
  items: z.array(itemDto),
});
export type VaultDto = z.infer<typeof vaultDto>;

export const syncRes = z.object({ vaults: z.array(vaultDto), serverTime: z.number() });
export type SyncRes = z.infer<typeof syncRes>;

export const putItemReq = z.object({
  data: envelope(ITEM_MAX),
  keyEpoch: z.number().int().min(0),
  /** null = create; must be absent on the server. */
  expectedRevision: z.number().int().min(0).nullable(),
});
export const putItemRes = z.object({ revision: z.number().int(), vaultRevision: z.number().int() });
export const deleteItemReq = z.object({ expectedRevision: z.number().int().min(0) });

export const createVaultReq = z.object({ id: uuid, nameEnc: envelope(), sealedVaultKey: sealedKey });

export const lookupRes = z.object({ userId: uuid, email: z.string(), publicKey: b64u32 });

export const putMemberReq = z.object({ sealedVaultKey: sealedKey, role, keyEpoch: z.number().int().min(0) });

export const memberDto = z.object({ userId: uuid, email: z.string(), publicKey: b64u32, role, keyEpoch: z.number().int() });
export type MemberDto = z.infer<typeof memberDto>;

export const rotateReq = z.object({
  /** Must equal current keyEpoch + 1. */
  keyEpoch: z.number().int().min(1),
  /** The vault revision the client re-encrypted from; any concurrent write makes the rotation fail with 409. */
  expectedVaultRevision: z.number().int().min(0),
  nameEnc: envelope().nullable(),
  members: z.array(z.object({ userId: uuid, sealedVaultKey: sealedKey })).min(1).max(50),
  items: z.array(z.object({ id: uuid, data: envelope(ITEM_MAX), expectedRevision: z.number().int().min(0) })).max(5000),
});

export const ERROR_CODES = [
  'bad_request',
  'unauthorized',
  'forbidden',
  'not_found',
  'conflict',
  'invalid_credentials',
  'totp_required',
  'rate_limited',
  'invalid_invite',
  'email_taken',
  'csrf',
  'internal',
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

export const CSRF_HEADER = 'X-Requested-With';
export const CSRF_VALUE = 'vpass';
