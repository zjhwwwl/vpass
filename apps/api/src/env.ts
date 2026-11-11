export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  /** base64, 32 bytes. Worker secret. */
  AUTH_PEPPER: string;
  /** base64, 32 bytes. Worker secret. */
  TOTP_ENC_KEY: string;
  /** Comma-separated admin user IDs (UUIDs). Plain var. Not emails: an unregistered admin email could be claimed by anyone with an invite. */
  ADMIN_USER_IDS: string;
}

export interface Session {
  tokenHash: string;
  userId: string;
  email: string;
}

export interface AppVars {
  session: Session;
  ipHash: string;
}

export type AppEnv = { Bindings: Env; Variables: AppVars };
