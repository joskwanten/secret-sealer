import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { loadCertificate } from '../web/sealing/certificate.js';
import { encryptionLabel, sealValue } from '../web/sealing/seal.js';
import {
  TEST_CERTIFICATE_FINGERPRINT,
  TEST_CERTIFICATE_NOT_AFTER,
  TEST_CERTIFICATE_NOT_BEFORE,
  TEST_CERTIFICATE_PEM,
  TEST_PRIVATE_KEY_PKCS8_PEM,
} from './fixtures.js';

/** Reference HybridDecrypt, mirroring what the sealed-secrets controller does. */
async function unseal(sealed, label) {
  const pkcs8 = TEST_PRIVATE_KEY_PKCS8_PEM.replace(/-----[^-]+-----|\s+/g, '');
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    Uint8Array.from(atob(pkcs8), (c) => c.charCodeAt(0)),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  );

  const bytes = Uint8Array.from(atob(sealed), (c) => c.charCodeAt(0));
  const rsaLength = new DataView(bytes.buffer).getUint16(0);
  const sessionKey = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP', label: new TextEncoder().encode(label) },
    privateKey,
    bytes.subarray(2, 2 + rsaLength),
  );
  const aesKey = await crypto.subtle.importKey('raw', sessionKey, 'AES-GCM', false, ['decrypt']);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12) },
    aesKey,
    bytes.subarray(2 + rsaLength),
  );
  return new TextDecoder().decode(plaintext);
}

describe('encryptionLabel', () => {
  it('binds strict scope to namespace and name', () => {
    assert.equal(encryptionLabel('strict', 'team-a', 'db'), 'team-a/db');
  });

  it('binds namespace-wide scope to the namespace only', () => {
    assert.equal(encryptionLabel('namespace-wide', 'team-a', 'db'), 'team-a');
  });

  it('uses an empty label for cluster-wide scope', () => {
    assert.equal(encryptionLabel('cluster-wide', 'team-a', 'db'), '');
  });
});

describe('loadCertificate', () => {
  it('reads validity and fingerprint', async () => {
    const cert = await loadCertificate(TEST_CERTIFICATE_PEM);
    assert.equal(cert.notBefore.toISOString(), TEST_CERTIFICATE_NOT_BEFORE);
    assert.equal(cert.notAfter.toISOString(), TEST_CERTIFICATE_NOT_AFTER);
    assert.equal(cert.fingerprint, TEST_CERTIFICATE_FINGERPRINT);
  });

  it('rejects input that is not a PEM certificate', async () => {
    await assert.rejects(loadCertificate('hallo'), /PEM/);
  });
});

describe('sealValue', () => {
  it('round-trips a multi-line value', async () => {
    const { key } = await loadCertificate(TEST_CERTIFICATE_PEM);
    const value = '-----BEGIN KEY-----\nregel 1\nregel 2 met ünïcode\n-----END KEY-----\n';

    const sealed = await sealValue(key, value, 'team-a');

    assert.equal(await unseal(sealed, 'team-a'), value);
  });

  it('cannot be unsealed with a different scope label', async () => {
    const { key } = await loadCertificate(TEST_CERTIFICATE_PEM);

    const sealed = await sealValue(key, 'geheim', 'team-a/db');

    await assert.rejects(unseal(sealed, 'team-b/db'));
  });

  it('produces a different ciphertext on every call', async () => {
    const { key } = await loadCertificate(TEST_CERTIFICATE_PEM);

    const [a, b] = await Promise.all([sealValue(key, 'x', ''), sealValue(key, 'x', '')]);

    assert.notEqual(a, b);
  });
});
