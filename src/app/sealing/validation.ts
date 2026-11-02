const DNS1123_LABEL = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const DNS1123_SUBDOMAIN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const SECRET_KEY = /^[-._a-zA-Z0-9]+$/;

export function isValidNamespace(value: string): boolean {
  return value.length <= 63 && DNS1123_LABEL.test(value);
}

export function isValidSecretName(value: string): boolean {
  return value.length <= 253 && DNS1123_SUBDOMAIN.test(value);
}

export function isValidSecretKey(value: string): boolean {
  return value.length <= 253 && SECRET_KEY.test(value);
}
