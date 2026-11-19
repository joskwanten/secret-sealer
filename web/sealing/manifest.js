// @ts-check

/** @typedef {import('./seal.js').SealScope} SealScope */

/**
 * @typedef {object} SealedSecretSpec
 * @property {string} name
 * @property {string} namespace
 * @property {SealScope} scope
 * @property {Record<string, string>} encryptedData Key → sealed (base64) value.
 */

/** @type {Record<SealScope, string | null>} */
const SCOPE_ANNOTATIONS = {
  strict: null,
  'namespace-wide': 'sealedsecrets.bitnami.com/namespace-wide',
  'cluster-wide': 'sealedsecrets.bitnami.com/cluster-wide',
};

/**
 * Renders a SealedSecret manifest in the same shape `kubeseal -o yaml` produces.
 * @param {SealedSecretSpec} spec
 * @returns {string}
 */
export function buildSealedSecretManifest(spec) {
  const annotation = SCOPE_ANNOTATIONS[spec.scope];
  const metadata = [
    `  name: ${spec.name}`,
    `  namespace: ${spec.namespace}`,
    ...(annotation ? ['  annotations:', `    ${annotation}: "true"`] : []),
  ];

  return [
    'apiVersion: bitnami.com/v1alpha1',
    'kind: SealedSecret',
    'metadata:',
    ...metadata,
    'spec:',
    '  encryptedData:',
    ...Object.entries(spec.encryptedData).map(([key, value]) => `    ${key}: ${value}`),
    '  template:',
    '    metadata:',
    ...metadata.map((line) => `    ${line}`),
    '    type: Opaque',
    '',
  ].join('\n');
}
