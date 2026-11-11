import type { Context } from 'hono';
import type { KeyBundleDto, KdfParamsDto } from '@vpass/shared';
import type { AppEnv } from '../env.js';
import type { TotpState } from '../lib/crypto.js';
import { isAdmin } from '../middleware/session.js';

export interface UserRow {
  id: string;
  email: string;
  kdf_salt: string;
  kdf_params: string;
  auth_hmac: string;
  wrapped_account_key: string;
  recovery_wrapped_key: string;
  recovery_auth_hmac: string;
  public_key: string;
  wrapped_private_key: string;
  totp_secret_enc: string | null;
  failed_logins: number;
  locked_until: number | null;
  created_at: number;
}

export async function userByEmail(c: Context<AppEnv>, email: string): Promise<UserRow | null> {
  return c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<UserRow>();
}

export async function userById(c: Context<AppEnv>, id: string): Promise<UserRow | null> {
  return c.env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first<UserRow>();
}

export function totpState(u: UserRow): TotpState | null {
  return u.totp_secret_enc ? (JSON.parse(u.totp_secret_enc) as TotpState) : null;
}

export function keyBundle(c: Context<AppEnv>, u: UserRow): KeyBundleDto {
  return {
    userId: u.id,
    email: u.email,
    kdfSalt: u.kdf_salt,
    kdfParams: JSON.parse(u.kdf_params) as KdfParamsDto,
    wrappedAccountKey: u.wrapped_account_key,
    publicKey: u.public_key,
    wrappedPrivateKey: u.wrapped_private_key,
    isAdmin: isAdmin(c, u.id),
    totpEnabled: totpState(u)?.enabled === true,
  };
}
