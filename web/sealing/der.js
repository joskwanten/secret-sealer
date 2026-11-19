// @ts-check
/**
 * Minimal DER reader: just enough to pull the public key and validity period
 * out of an X.509 certificate, so we don't need a full ASN.1 library.
 */

/**
 * @typedef {object} DerElement
 * @property {number} tag
 * @property {number} start Offset of the tag byte.
 * @property {number} contentStart Offset of the first content byte.
 * @property {number} end Offset just past the last content byte.
 */

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @returns {DerElement}
 */
export function readElement(bytes, offset) {
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

/**
 * @param {Uint8Array} bytes
 * @param {DerElement} parent
 * @returns {DerElement[]}
 */
export function readChildren(bytes, parent) {
  const children = [];
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

/**
 * @param {Uint8Array} bytes
 * @param {DerElement} element
 * @returns {Date}
 */
export function readTime(bytes, element) {
  const text = new TextDecoder().decode(bytes.subarray(element.contentStart, element.end));
  let match;
  let year;

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
