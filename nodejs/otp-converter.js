/**
 * otp-converter.js — Decrypt an Open Authenticator (.bak) backup and emit
 * otpauth://totp/ URIs, one per entry.
 *
 * Crypto scheme (reverse-engineered from the openauthenticator Flutter app):
 *   key  = Argon2id(password, salt, t=3, p=8, m=4096 KiB, 32 bytes, v=0x13)
 *   blob = AES-256-GCM: IV(12) || ciphertext || tag(16), no AAD
 *   passwordSignature = base64(HMAC-SHA256(key, utf8(password)))
 *
 * Usage:
 *   npm install hash-wasm
 *   node otp-converter.js backup.bak --password 'secret' [--out urls.txt]
 */

import { createDecipheriv, createHmac } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { argon2id } from 'hash-wasm';

// ---------------------------------------------------------------------------
// args

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--password' || a === '-p') args.password = argv[++i];
    else if (a === '--out' || a === '-o') args.out = argv[++i];
    else if (a === '--help' || a === '-h') args.help = true;
    else args._.push(a);
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));

if (args.help || args._.length !== 1) {
  console.error('Usage: node otp-converter.js <backup.bak> --password <password> [--out urls.txt]');
  process.exit(args.help ? 0 : 1);
}

if (!args.password) {
  // small nicety: read password without echo when not provided
  process.stderr.write('Enter backup password: ');
  args.password = readFileSync(0, 'utf8').replace(/[\r\n]+$/, '');
  if (!args.password) {
    console.error('\nError: empty password');
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// helpers

const IV_LEN = 12;
const TAG_LEN = 16;

function deriveKey(passwordBytes, saltBytes) {
  return argon2id({
    password: passwordBytes,
    salt: saltBytes,
    iterations: 3,          // Argon2Parameters.iterations
    parallelism: 8,         // Argon2Parameters.parallelism
    memorySize: 4096,       // Argon2Parameters.memorySize (KiB)
    hashLength: 32,
    outputType: 'binary',
  });
}

function hmacSignature(keyBytes, passwordBytes) {
  return createHmac('sha256', keyBytes).update(passwordBytes).digest('base64');
}

/** blob = IV(12) || ciphertext || tag(16) → plaintext utf8 string, or null */
function decryptBlob(keyBytes, blob) {
  if (blob.length < IV_LEN + TAG_LEN) return null;
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(IV_LEN, blob.length - TAG_LEN);
  try {
    const d = createDecipheriv('aes-256-gcm', keyBytes, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  } catch {
    return null; // wrong key / tampered data
  }
}

function decryptField(keyBytes, jsonList) {
  if (jsonList == null) return null;
  return decryptBlob(keyBytes, Buffer.from(jsonList));
}

function b32Valid(secret) {
  return /^[A-Za-z2-7]+=*$/.test(secret);
}

/** Normalize a base32 secret per RFC 4648 + draft-linuxgemini-otpauth-uri:
 *  uppercase, no padding. */
function b32Normalize(secret) {
  return b32Valid(secret) ? secret.replace(/=+$/, '').toUpperCase() : secret;
}

/** Build otpauth://totp/... URI per draft-linuxgemini-otpauth-uri-00. */
function buildUri({ label, issuer, secret, algorithm, digits, validity }) {
  const pathLabel = issuer && label ? `${issuer}:${label}` : (label ?? issuer ?? 'unknown');
  const params = [['secret', b32Normalize(secret)]];
  if (issuer) params.push(['issuer', issuer]);
  if (algorithm) params.push(['algorithm', algorithm.toUpperCase()]); // SHA1 / SHA256 / SHA512
  if (digits) params.push(['digits', String(digits)]);
  if (validity) params.push(['period', String(validity)]);
  const query = params
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`) // RFC 3986 URI-safe, not form-encoding
    .join('&');
  // keep ':' and '@' literal in the path label (matches Dart's Uri normalization
  // and the otpauth spec's conventional issuer:account form)
  const encodedLabel = encodeURIComponent(pathLabel).replace(/%3A/gi, ':').replace(/%40/g, '@');
  return `otpauth://totp/${encodedLabel}?${query}`;
}

// ---------------------------------------------------------------------------
// main

const raw = readFileSync(args._[0], 'utf8');
const data = JSON.parse(raw);

if (!Array.isArray(data.totps) || typeof data.salt !== 'string' || typeof data.passwordSignature !== 'string') {
  console.error('Error: not a valid Open Authenticator backup file');
  process.exit(1);
}

const backupSalt = Buffer.from(data.salt, 'base64');
const passwordBytes = Buffer.from(args.password, 'utf8');

const key = await deriveKey(passwordBytes, backupSalt);

// Verify password via HMAC signature before touching the entries.
const actualSig = hmacSignature(key, passwordBytes);
if (actualSig !== data.passwordSignature) {
  console.error('Error: invalid backup password (HMAC signature mismatch)');
  process.exit(1);
}

const lines = [];
let ok = 0, failed = 0;

for (const [i, e] of data.totps.entries()) {
  const name = e.issuer ? `${e.label ?? ''}@${e.issuer}` : e.label ?? e.uuid ?? `#${i}`;

  // Prefer the entry's own encryptionSalt, fall back to the backup salt.
  let entryKey = key;
  if (Array.isArray(e.encryptionSalt) && !Buffer.from(e.encryptionSalt).equals(backupSalt)) {
    entryKey = await deriveKey(passwordBytes, Buffer.from(e.encryptionSalt));
  }

  const secret = decryptField(entryKey, e.secret) ?? decryptField(key, e.secret);
  if (secret == null) {
    console.error(`Warning: failed to decrypt secret of entry ${name} (${e.uuid}) — skipped`);
    failed++;
    continue;
  }
  if (!b32Valid(secret)) {
    console.error(`Warning: secret of entry ${name} (${e.uuid}) is not valid base32 — included as-is`);
  }

  const label = decryptField(entryKey, e.label) ?? decryptField(key, e.label);
  const issuer = decryptField(entryKey, e.issuer) ?? decryptField(key, e.issuer);

  lines.push(buildUri({
    label,
    issuer,
    secret,
    algorithm: typeof e.algorithm === 'string' ? e.algorithm : null,
    digits: typeof e.digits === 'number' ? e.digits : null,
    validity: typeof e.validity === 'number' ? e.validity : null,
  }));
  ok++;
}

const output = lines.join('\n') + (lines.length ? '\n' : '');
if (args.out) {
  writeFileSync(args.out, output);
  console.error(`Wrote ${ok} URI(s) to ${args.out}${failed ? `, ${failed} failed` : ''}`);
} else {
  process.stdout.write(output);
  console.error(`\n${ok} URI(s) exported${failed ? `, ${failed} failed` : ''}`);
}

process.exit(failed && ok === 0 ? 1 : 0);
