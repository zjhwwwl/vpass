// AAD builders (crypto-spec 4.2, decisions D-02..D-04, D-13, D-16).
// AAD is never stored in the envelope: callers rebuild it from context, so a ciphertext moved
// to another row/vault/user fails to decrypt.

function id(s: string): string {
  return s.toLowerCase();
}

export const AAD = Object.freeze({
  accountKey: (userId: string) => `account-key|v1|${id(userId)}`,
  privateKey: (userId: string) => `private-key|v1|${id(userId)}`,
  recoveryKey: (userId: string) => `recovery-key|v1|${id(userId)}`,
  deviceSecretKey: (userId: string) => `device-secret-key|v1|${id(userId)}`,
  item: (vaultId: string, itemId: string) => `item|v1|${id(vaultId)}|${id(itemId)}`,
  vaultName: (vaultId: string) => `vault-name|v1|${id(vaultId)}`,
  export: () => 'export|v1',
});
