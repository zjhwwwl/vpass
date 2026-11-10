import type { Credentials, EncryptedExport, KdfParams, LoginKeys, Registration } from '@vpass/crypto';
import workerUrl from './argon.worker.ts?worker&url';
import { scriptUrl } from './tt.js';
import type { WorkerRequest } from './argon.worker.js';

let worker: Worker | null = null;
let seq = 0;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(scriptUrl(workerUrl), { type: 'module', name: 'argon2' });
    worker.onmessage = (ev: MessageEvent<{ id: number; ok: boolean; result?: unknown; error?: string }>) => {
      const p = pending.get(ev.data.id);
      if (!p) return;
      pending.delete(ev.data.id);
      if (ev.data.ok) p.resolve(ev.data.result);
      else p.reject(new Error(ev.data.error ?? 'internal'));
    };
    worker.onerror = () => {
      for (const p of pending.values()) p.reject(new Error('worker_failed'));
      pending.clear();
      worker?.terminate();
      worker = null;
    };
  }
  return worker;
}

function run<T>(req: WorkerRequest): Promise<T> {
  const id = ++seq;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
    getWorker().postMessage({ id, req });
  });
}

export const kdf = {
  deriveLoginKeys: (password: string, secretKey: Uint8Array | CryptoKey, kdfSalt: Uint8Array, params: KdfParams) =>
    run<LoginKeys>({ op: 'deriveLoginKeys', password, secretKey, kdfSalt, params }),
  createAccount: (email: string, password: string) => run<Registration>({ op: 'createAccount', email, password }),
  wrapAccountKey: (userId: string, accountKey: Uint8Array, password: string, secretKey: Uint8Array | CryptoKey) =>
    run<Credentials>({ op: 'wrapAccountKey', userId, accountKey, password, secretKey }),
  encryptExport: (password: string, value: unknown) => run<EncryptedExport>({ op: 'encryptExport', password, value }),
  decryptExport: <T>(password: string, file: EncryptedExport) => run<T>({ op: 'decryptExport', password, file }),
};
