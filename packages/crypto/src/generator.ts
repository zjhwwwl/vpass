import { getSodium } from './sodium.js';
import { WORDLIST } from './wordlist.js';

export const CHARSETS = Object.freeze({
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
});

const AMBIGUOUS = new Set('Il1O0o|`\'"');

export interface PasswordOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous?: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = Object.freeze({
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
});

/**
 * Random password. Each character is drawn with libsodium randombytes_uniform, which uses
 * rejection sampling internally, so there is no modulo bias. When several classes are enabled,
 * candidates that miss a class are rejected and redrawn (still uniform over the valid set).
 */
export async function generatePassword(opts: PasswordOptions = DEFAULT_PASSWORD_OPTIONS): Promise<string> {
  if (!Number.isInteger(opts.length) || opts.length < 4 || opts.length > 128) throw new Error('invalid_length');
  const classes = (['lower', 'upper', 'digits', 'symbols'] as const)
    .filter((k) => opts[k])
    .map((k) => [...CHARSETS[k]].filter((c) => !opts.avoidAmbiguous || !AMBIGUOUS.has(c)).join(''));
  if (classes.length === 0) throw new Error('no_charset');
  const alphabet = classes.join('');
  const sodium = await getSodium();
  for (;;) {
    let pw = '';
    for (let i = 0; i < opts.length; i++) pw += alphabet[sodium.randombytes_uniform(alphabet.length)];
    if (classes.every((cls) => [...pw].some((c) => cls.includes(c)))) return pw;
  }
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = Object.freeze({
  words: 6,
  separator: '-',
  capitalize: true,
  includeNumber: true,
});

/** Diceware-style passphrase from the EFF short wordlist (1296 words ≈ 10.3 bits/word). */
export async function generatePassphrase(opts: PassphraseOptions = DEFAULT_PASSPHRASE_OPTIONS): Promise<string> {
  if (!Number.isInteger(opts.words) || opts.words < 3 || opts.words > 20) throw new Error('invalid_length');
  const sodium = await getSodium();
  const words: string[] = [];
  for (let i = 0; i < opts.words; i++) {
    const w = WORDLIST[sodium.randombytes_uniform(WORDLIST.length)]!;
    words.push(opts.capitalize ? w[0]!.toUpperCase() + w.slice(1) : w);
  }
  if (opts.includeNumber) {
    const at = sodium.randombytes_uniform(words.length);
    words[at] = words[at]! + String(sodium.randombytes_uniform(10));
  }
  return words.join(opts.separator);
}

/** Rough entropy estimate in bits, for the UI. */
export function passwordEntropyBits(opts: PasswordOptions): number {
  const n = (['lower', 'upper', 'digits', 'symbols'] as const)
    .filter((k) => opts[k])
    .reduce((acc, k) => acc + [...CHARSETS[k]].filter((c) => !opts.avoidAmbiguous || !AMBIGUOUS.has(c)).length, 0);
  return n === 0 ? 0 : Math.floor(opts.length * Math.log2(n));
}

export function passphraseEntropyBits(opts: PassphraseOptions): number {
  return Math.floor(opts.words * Math.log2(WORDLIST.length) + (opts.includeNumber ? Math.log2(10 * opts.words) : 0));
}
