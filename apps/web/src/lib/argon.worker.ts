/// <reference lib="webworker" />
// Runs the slow Argon2id-based operations off the main thread so the UI stays responsive.
import {
  createAccount,
  decryptExport,
  deriveLoginKeys,
  encryptExport,
  wrapAccountKeyWithPassword,
  type EncryptedExport,
  type KdfParams,
} from '@vpass/crypto';

export type WorkerRequest =
  | { op: 'deriveLoginKeys'; password: string; secretKey: Uint8Array | CryptoKey; kdfSalt: Uint8Array; params: KdfParams }
  | { op: 'createAccount'; email: string; password: string }
  | { op: 'wrapAccountKey'; userId: string; accountKey: Uint8Array; password: string; secretKey: Uint8Array | CryptoKey }
  | { op: 'encryptExport'; password: string; value: unknown }
  | { op: 'decryptExport'; password: string; file: EncryptedExport };

self.onmessage = async (ev: MessageEvent<{ id: number; req: WorkerRequest }>) => {
  const { id, req } = ev.data;
  try {
    let result: unknown;
    switch (req.op) {
      case 'deriveLoginKeys':
        result = await deriveLoginKeys(req.password, req.secretKey, req.kdfSalt, req.params);
        break;
      case 'createAccount':
        result = await createAccount(req.email, req.password);
        break;
      case 'wrapAccountKey':
        result = await wrapAccountKeyWithPassword(req.userId, req.accountKey, req.password, req.secretKey);
        break;
      case 'encryptExport':
        result = await encryptExport(req.password, req.value);
        break;
      case 'decryptExport':
        result = await decryptExport(req.password, req.file);
        break;
    }
    // postMessage clones synchronously, so the worker's own copies can be zeroed right after (P6 L5).
    (self as unknown as Worker).postMessage({ id, ok: true, result });
    wipeDeep(result);
  } catch (e) {
    // Only the error code crosses back; never inputs.
    (self as unknown as Worker).postMessage({ id, ok: false, error: e instanceof Error ? e.message : 'internal' });
  } finally {
    wipeDeep(req);
  }
};

/** Best-effort: zero every Uint8Array reachable from a value (keys, salts, hashes). */
function wipeDeep(v: unknown, seen = new Set<unknown>()): void {
  if (v === null || typeof v !== 'object' || seen.has(v)) return;
  seen.add(v);
  if (v instanceof Uint8Array) {
    v.fill(0);
    return;
  }
  for (const x of Object.values(v as Record<string, unknown>)) wipeDeep(x, seen);
}
