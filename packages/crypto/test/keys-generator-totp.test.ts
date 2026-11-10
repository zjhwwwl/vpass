import { describe, expect, it } from 'vitest';
import totpVectors from './vectors/totp-rfc6238.json';
import {
  CHARSETS,
  DEFAULT_PASSPHRASE_OPTIONS,
  DEFAULT_PASSWORD_OPTIONS,
  HUMAN_ALPHABET,
  createRecoveryCode,
  formatRecoveryCode,
  formatSecretKey,
  fromBase32Rfc4648,
  fromHex,
  generatePassphrase,
  generatePassword,
  generateSecretKey,
  hotp,
  otpauthUri,
  parseRecoveryCode,
  parseSecretKey,
  parseTotp,
  passphraseEntropyBits,
  passwordEntropyBits,
  totp,
  totpRemaining,
  verifyTotp,
  type TotpAlgorithm,
} from '../src/index.js';
import { WORDLIST } from '../src/wordlist.js';

describe('Secret Key encoding (D-01)', () => {
  it('round-trips and has the documented shape', async () => {
    for (let i = 0; i < 200; i++) {
      const raw = await generateSecretKey();
      const s = formatSecretKey(raw);
      expect(s).toMatch(/^VP1-[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){4}-[0-9A-HJKMNP-TV-Z]{2}$/);
      expect(parseSecretKey(s)).toEqual(raw);
      expect(parseSecretKey(s.toLowerCase().replace(/-/g, ' '))).toEqual(raw);
    }
  });

  it('accepts O/I/L confusables', () => {
    const raw = fromHex('00'.repeat(16));
    const s = formatSecretKey(raw);
    expect(s.startsWith('VP1-00000')).toBe(true);
    expect(parseSecretKey(s.replace(/0/g, 'O').replace('VP1', 'VP1'))).toEqual(raw);
    const one = formatSecretKey(fromHex('08' + '00'.repeat(15)));
    expect(parseSecretKey(one.replace('VP1-01', 'VP1-0l'))).toEqual(fromHex('08' + '00'.repeat(15)));
  });

  it('detects every single-character substitution locally', async () => {
    const raw = await generateSecretKey();
    const s = formatSecretKey(raw).replace(/-/g, '').slice(3);
    for (let pos = 0; pos < s.length; pos++) {
      for (const ch of HUMAN_ALPHABET) {
        if (ch === s[pos]) continue;
        const typo = 'VP1' + s.slice(0, pos) + ch + s.slice(pos + 1);
        expect(() => parseSecretKey(typo)).toThrow(/secret_key_(checksum)/);
      }
    }
  });

  it('rejects wrong prefix, length and characters', () => {
    const s = formatSecretKey(fromHex('ab'.repeat(16)));
    expect(() => parseSecretKey(s.replace('VP1', 'VP2'))).toThrow('secret_key_format');
    expect(() => parseSecretKey(s.slice(0, -1))).toThrow('secret_key_format');
    expect(() => parseSecretKey(s.slice(0, -1) + 'U')).toThrow('secret_key_format');
    expect(() => formatSecretKey(new Uint8Array(15))).toThrow('invalid_secret_key');
  });

  it('rejects non-zero padding bits even when the checksum matches', () => {
    // 26 data chars carry 130 bits; the last 2 must be zero. Craft a string with a valid check char but dirty padding.
    const data = '0'.repeat(25) + '1';
    let sum = 0;
    [...data].forEach((c, i) => (sum += (2 * i + 1) * HUMAN_ALPHABET.indexOf(c)));
    const check = HUMAN_ALPHABET[sum % 32]!;
    expect(() => parseSecretKey('VP1' + data + check)).toThrow('secret_key_checksum');
  });
});

describe('recovery code', () => {
  it('160 bits, 8 groups of 4, round-trips', async () => {
    const { raw, display } = await createRecoveryCode();
    expect(raw).toHaveLength(20);
    expect(display).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/);
    expect(parseRecoveryCode(display.toLowerCase())).toEqual(raw);
    expect(formatRecoveryCode(raw)).toBe(display);
    expect(() => parseRecoveryCode('ABC')).toThrow('recovery_code_format');
    expect(() => parseRecoveryCode('U'.repeat(32))).toThrow('recovery_code_format');
    expect(() => formatRecoveryCode(new Uint8Array(3))).toThrow('invalid_recovery_code');
  });
});

describe('password generator', () => {
  it('respects length and classes', async () => {
    for (let i = 0; i < 200; i++) {
      const pw = await generatePassword({ length: 8, lower: true, upper: true, digits: true, symbols: true });
      expect(pw).toHaveLength(8);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[0-9]/);
      expect([...pw].some((c) => CHARSETS.symbols.includes(c))).toBe(true);
    }
    expect(await generatePassword()).toHaveLength(DEFAULT_PASSWORD_OPTIONS.length);
    expect(await generatePassword({ length: 30, lower: false, upper: false, digits: true, symbols: false })).toMatch(/^\d{30}$/);
    const noAmb = await generatePassword({ length: 128, lower: true, upper: true, digits: true, symbols: false, avoidAmbiguous: true });
    expect(noAmb).not.toMatch(/[Il1O0o]/);
  });

  it('rejects bad options', async () => {
    await expect(generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 3 })).rejects.toThrow('invalid_length');
    await expect(generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 129 })).rejects.toThrow('invalid_length');
    await expect(generatePassword({ ...DEFAULT_PASSWORD_OPTIONS, length: 10.5 })).rejects.toThrow('invalid_length');
    await expect(generatePassword({ length: 10, lower: false, upper: false, digits: false, symbols: false })).rejects.toThrow('no_charset');
  });

  it('is uniform over 100,000 samples (chi-square)', async () => {
    const alphabet = CHARSETS.lower + CHARSETS.upper + CHARSETS.digits;
    const counts = new Map<string, number>();
    const n = 100_000;
    const len = 100;
    for (let i = 0; i < n / len; i++) {
      const pw = await generatePassword({ length: len, lower: true, upper: true, digits: true, symbols: false });
      for (const c of pw) counts.set(c, (counts.get(c) ?? 0) + 1);
    }
    expect(counts.size).toBe(alphabet.length);
    const expected = n / alphabet.length;
    let chi = 0;
    for (const c of alphabet) chi += ((counts.get(c) ?? 0) - expected) ** 2 / expected;
    // df = 61; p = 0.001 critical value ≈ 100.9
    expect(chi).toBeLessThan(100.9);
  });

  it('passphrases', async () => {
    const p = await generatePassphrase();
    const parts = p.split('-');
    expect(parts).toHaveLength(DEFAULT_PASSPHRASE_OPTIONS.words);
    expect(parts.filter((w) => /\d$/.test(w))).toHaveLength(1);
    expect(parts.every((w) => /^[A-Z]/.test(w))).toBe(true);
    const plain = await generatePassphrase({ words: 4, separator: ' ', capitalize: false, includeNumber: false });
    expect(plain.split(' ').every((w) => WORDLIST.includes(w))).toBe(true);
    await expect(generatePassphrase({ ...DEFAULT_PASSPHRASE_OPTIONS, words: 2 })).rejects.toThrow('invalid_length');
    await expect(generatePassphrase({ ...DEFAULT_PASSPHRASE_OPTIONS, words: 21 })).rejects.toThrow('invalid_length');
    expect(WORDLIST).toHaveLength(1296);
    expect(new Set(WORDLIST).size).toBe(1296);
  });

  it('entropy estimates', () => {
    expect(passwordEntropyBits({ length: 10, lower: false, upper: false, digits: true, symbols: false })).toBe(33);
    expect(passwordEntropyBits({ length: 10, lower: false, upper: false, digits: false, symbols: false })).toBe(0);
    expect(passwordEntropyBits({ length: 10, lower: true, upper: false, digits: false, symbols: false, avoidAmbiguous: true })).toBe(
      Math.floor(10 * Math.log2(24)),
    );
    expect(passphraseEntropyBits({ words: 6, separator: '-', capitalize: true, includeNumber: false })).toBe(62);
    expect(passphraseEntropyBits({ words: 6, separator: '-', capitalize: true, includeNumber: true })).toBe(67);
  });
});

describe('TOTP (RFC 6238 Appendix B)', () => {
  const algs: TotpAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-512'];
  for (const c of totpVectors.cases) {
    for (const alg of algs) {
      it(`${alg} @ ${c.time}`, async () => {
        const secret = fromHex(totpVectors.seeds[alg]);
        expect(await totp({ secret, digits: 8, period: 30, algorithm: alg }, c.time)).toBe(c[alg]);
      });
    }
  }

  it('hotp rejects bad digits', async () => {
    await expect(hotp(new Uint8Array(20), 0, 5)).rejects.toThrow('invalid_totp');
    await expect(hotp(new Uint8Array(20), 0, 11)).rejects.toThrow('invalid_totp');
  });

  it('parses bare secrets and otpauth URIs', () => {
    const bare = parseTotp(' JBSW Y3DP EHPK 3PXP ');
    expect(bare).toMatchObject({ digits: 6, period: 30, algorithm: 'SHA-1' });
    const uri = parseTotp('otpauth://totp/X:me?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=sha256&issuer=X');
    expect(uri).toMatchObject({ digits: 8, period: 60, algorithm: 'SHA-256' });
    expect(uri.secret).toEqual(fromBase32Rfc4648('JBSWY3DPEHPK3PXP'));
    for (const bad of [
      '',
      'otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP',
      'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
      'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4',
      'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0',
      'otpauth://totp/x?secret=JBSW',
      'otpauth://totp/x',
      'otpauth://[bad',
      'not base32 !!',
    ]) {
      expect(() => parseTotp(bad), bad).toThrow('invalid_totp');
    }
  });

  it('verifies within ±1 window, and builds a URI', async () => {
    const secret = fromHex('3132333435363738393031323334353637383930');
    const now = 1_700_000_000;
    const code = await hotp(secret, Math.floor(now / 30));
    expect(await verifyTotp(secret, code, now)).toBe(Math.floor(now / 30));
    expect(await verifyTotp(secret, code, now + 30)).toBe(Math.floor(now / 30));
    expect(await verifyTotp(secret, code, now + 90)).toBeNull();
    expect(await verifyTotp(secret, '12345', now)).toBeNull();
    expect(totpRemaining(30, 61)).toBe(29);
    const uri = otpauthUri(secret, 'me@example.com');
    expect(parseTotp(uri).secret).toEqual(secret);
    expect(otpauthUri(secret, 'a', 'Other')).toContain('issuer=Other');
  });
});
