/**
 * Browser implementation of the Sealed Secrets hybrid encryption, byte-compatible
 * with `kubeseal` (github.com/bitnami-labs/sealed-secrets, pkg/crypto HybridEncrypt):
 *
 *   uint16 BE length of RSA ciphertext
 *   RSA-OAEP(SHA-256, label) of a random 32-byte session key
 *   AES-256-GCM(session key, zero nonce) of the plaintext, including the 16-byte tag
 *
 * The output is base64 (standard encoding), exactly what `kubeseal --raw` prints.
 */

export type SealScope = 'strict' | 'namespace-wide' | 'cluster-wide';

export const SCOPES: readonly SealScope[] = ['namespace-wide', 'strict', 'cluster-wide'];

/** The OAEP label binds the ciphertext to its scope, like kubeseal's EncryptionLabel. */
export function encryptionLabel(scope: SealScope, namespace: string, name: string): string {
  switch (scope) {
    case 'strict':
      return `${namespace}/${name}`;
    case 'namespace-wide':
      return namespace;
    case 'cluster-wide':
      return '';
  }
}

const SESSION_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;

export async function sealValue(
  publicKey: CryptoKey,
  plaintext: string | Uint8Array<ArrayBuffer>,
  label: string,
): Promise<string> {
  const data = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const sessionKey = crypto.getRandomValues(new Uint8Array(SESSION_KEY_BYTES));

  const rsaCiphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'RSA-OAEP', label: new TextEncoder().encode(label) },
      publicKey,
      sessionKey,
    ),
  );

  // The session key is used exactly once, so a zero nonce is safe (same as kubeseal).
  const aesKey = await crypto.subtle.importKey('raw', sessionKey, 'AES-GCM', false, ['encrypt']);
  const aesCiphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(GCM_NONCE_BYTES) },
      aesKey,
      data,
    ),
  );
  sessionKey.fill(0);

  const out = new Uint8Array(2 + rsaCiphertext.length + aesCiphertext.length);
  new DataView(out.buffer).setUint16(0, rsaCiphertext.length);
  out.set(rsaCiphertext, 2);
  out.set(aesCiphertext, 2 + rsaCiphertext.length);
  return toBase64(out);
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
