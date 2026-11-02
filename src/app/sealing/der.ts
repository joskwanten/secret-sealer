/**
 * Minimal DER reader: just enough to pull the public key and validity period
 * out of an X.509 certificate, so we don't need a full ASN.1 library.
 */

export interface DerElement {
  tag: number;
  /** Offset of the tag byte. */
  start: number;
  /** Offset of the first content byte. */
  contentStart: number;
  /** Offset just past the last content byte. */
  end: number;
}

export function readElement(bytes: Uint8Array, offset: number): DerElement {
  if (offset + 2 > bytes.length) {
    throw new Error('Onverwacht einde van DER-data');
  }
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let contentStart = offset + 2;

  if (length & 0x80) {
    const lengthBytes = length & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 4) {
      throw new Error('Ongeldige DER-lengte');
    }
    length = 0;
    for (let i = 0; i < lengthBytes; i++) {
      length = length * 256 + bytes[contentStart + i];
    }
    contentStart += lengthBytes;
  }

  const end = contentStart + length;
  if (end > bytes.length) {
    throw new Error('DER-element loopt voorbij het einde van de data');
  }
  return { tag, start: offset, contentStart, end };
}

export function readChildren(bytes: Uint8Array, parent: DerElement): DerElement[] {
  const children: DerElement[] = [];
  let offset = parent.contentStart;
  while (offset < parent.end) {
    const child = readElement(bytes, offset);
    children.push(child);
    offset = child.end;
  }
  return children;
}

const UTC_TIME = 0x17;
const GENERALIZED_TIME = 0x18;

export function readTime(bytes: Uint8Array, element: DerElement): Date {
  const text = new TextDecoder().decode(bytes.subarray(element.contentStart, element.end));
  let match: RegExpMatchArray | null;
  let year: number;

  if (element.tag === UTC_TIME) {
    match = text.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!match) throw new Error(`Ongeldige UTCTime: ${text}`);
    // RFC 5280: YY >= 50 means 19YY, otherwise 20YY.
    const yy = Number(match[1]);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
  } else if (element.tag === GENERALIZED_TIME) {
    match = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
    if (!match) throw new Error(`Ongeldige GeneralizedTime: ${text}`);
    year = Number(match[1]);
  } else {
    throw new Error('Verwachtte een tijdstip in het certificaat');
  }

  const [, , month, day, hour, minute, second] = match.map(Number);
  return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
}
