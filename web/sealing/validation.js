// @ts-check
const DNS1123_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DNS1123_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const SECRET_KEY = /^[-._a-zA-Z0-9]+$/;

/** @param {string} value */
export function isValidNamespace(value) {
  return value.length <= 63 && DNS1123_LABEL.test(value);
}

/** @param {string} value */
export function isValidSecretName(value) {
  return value.length <= 253 && DNS1123_SUBDOMAIN.test(value);
}

/** @param {string} value */
export function isValidSecretKey(value) {
  return value.length <= 253 && SECRET_KEY.test(value);
}
