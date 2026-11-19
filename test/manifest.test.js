import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { buildSealedSecretManifest } from '../web/sealing/manifest.js';

describe('buildSealedSecretManifest', () => {
  it('renders a strict SealedSecret without scope annotation', () => {
    const yaml = buildSealedSecretManifest({
      name: 'db',
      namespace: 'team-a',
      scope: 'strict',
      encryptedData: { USER: 'AgA1', PASSWORD: 'AgA2' },
    });

    assert.equal(
      yaml,
      [
        'apiVersion: bitnami.com/v1alpha1',
        'kind: SealedSecret',
        'metadata:',
        '  name: db',
        '  namespace: team-a',
        'spec:',
        '  encryptedData:',
        '    USER: AgA1',
        '    PASSWORD: AgA2',
        '  template:',
        '    metadata:',
        '      name: db',
        '      namespace: team-a',
        '    type: Opaque',
        '',
      ].join('\n'),
    );
  });

  it('adds the namespace-wide annotation to object and template', () => {
    const yaml = buildSealedSecretManifest({
      name: 'db',
      namespace: 'team-a',
      scope: 'namespace-wide',
      encryptedData: { KEY: 'AgA1' },
    });

    assert.ok(yaml.includes('  annotations:\n    sealedsecrets.bitnami.com/namespace-wide: "true"'));
    assert.ok(
      yaml.includes('      annotations:\n        sealedsecrets.bitnami.com/namespace-wide: "true"'),
    );
  });
});
