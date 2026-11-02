import { readChildren, readElement, readTime } from './der';

export interface SealingCertificate {
  /** RSA-OAEP/SHA-256 public key, ready for sealing. */
  key: CryptoKey;
  notBefore: Date;
  notAfter: Date;
  /** SHA-256 over the certificate, formatted like `openssl x509 -fingerprint -sha256`. */
  fingerprint: string;
}

const SEQUENCE = 0x30;
const EXPLICIT_VERSION = 0xa0;

/** Decodes the first certificate in a PEM bundle to DER. */
export function pemToDer(pem: string): Uint8Array<ArrayBuffer> {
  const match = pem.match(
    /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/,
  );
  if (!match) {
    throw new Error('Geen PEM-certificaat gevonden (verwacht "-----BEGIN CERTIFICATE-----")');
  }
  const binary = atob(match[1].replace(/\s+/g, ''));
  const der = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    der[i] = binary.charCodeAt(i);
  }
  return der;
}

export async function loadCertificate(pem: string): Promise<SealingCertificate> {
  const der = pemToDer(pem);

  const certificate = readElement(der, 0);
  if (certificate.tag !== SEQUENCE) {
    throw new Error('Ongeldig certificaat');
  }
  const tbs = readChildren(der, certificate)[0];
  const fields = readChildren(der, tbs);
  // tbsCertificate: [version], serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
  const offset = fields[0]?.tag === EXPLICIT_VERSION ? 1 : 0;
  const validity = fields[offset + 3];
  const spki = fields[offset + 5];
  if (!validity || !spki) {
    throw new Error('Ongeldig certificaat: velden ontbreken');
  }
  const [notBefore, notAfter] = readChildren(der, validity).map((t) => readTime(der, t));

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      'spki',
      der.subarray(spki.start, spki.end),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt'],
    );
  } catch {
    throw new Error('Het certificaat bevat geen bruikbare RSA-sleutel');
  }

  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', der));
  const fingerprint = Array.from(digest, (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(
    ':',
  );

  return { key, notBefore, notAfter, fingerprint };
}
