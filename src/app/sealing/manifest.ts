import { SealScope } from './seal';

export interface SealedSecretSpec {
  name: string;
  namespace: string;
  scope: SealScope;
  /** Key → sealed (base64) value. */
  encryptedData: Record<string, string>;
}

const SCOPE_ANNOTATIONS: Record<SealScope, string | null> = {
  strict: null,
  'namespace-wide': 'sealedsecrets.bitnami.com/namespace-wide',
  'cluster-wide': 'sealedsecrets.bitnami.com/cluster-wide',
};

/** Renders a SealedSecret manifest in the same shape `kubeseal -o yaml` produces. */
export function buildSealedSecretManifest(spec: SealedSecretSpec): string {
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
