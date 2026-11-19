import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isValidNamespace, isValidSecretKey, isValidSecretName } from '../web/sealing/validation.js';

describe('validation', () => {
  it('accepts DNS-1123 namespaces and rejects the rest', () => {
    assert.ok(isValidNamespace('team-a-ont'));
    assert.ok(!isValidNamespace('Team-A'));
    assert.ok(!isValidNamespace('-team'));
    assert.ok(!isValidNamespace('a'.repeat(64)));
  });

  it('allows dots in secret names but not in namespaces', () => {
    assert.ok(isValidSecretName('db.credentials'));
    assert.ok(!isValidNamespace('team.a'));
  });

  it('accepts env-style and dotted keys', () => {
    assert.ok(isValidSecretKey('DB_PASSWORD'));
    assert.ok(isValidSecretKey('tls.crt'));
    assert.ok(!isValidSecretKey('met spatie'));
  });
});
