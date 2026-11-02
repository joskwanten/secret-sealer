import { Component, computed, effect, inject, linkedSignal, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CertificateState, ClusterConfigService } from './config/cluster-config.service';
import { loadCertificate } from './sealing/certificate';
import { buildSealedSecretManifest } from './sealing/manifest';
import { SCOPES, SealScope, encryptionLabel, sealValue } from './sealing/seal';
import { isValidNamespace, isValidSecretKey, isValidSecretName } from './sealing/validation';

type Mode = 'value' | 'manifest';

interface Entry {
  id: number;
  key: string;
  value: string;
}

const CUSTOM_CLUSTER = '__custom__';
const STORAGE_KEY = 'secret-sealer.preferences';

interface Preferences {
  clusterId?: string;
  namespace?: string;
  scope?: SealScope;
}

const SCOPE_INFO: Record<SealScope, { title: string; description: string }> = {
  'namespace-wide': {
    title: 'Namespace',
    description: 'Bruikbaar in elk Secret binnen deze namespace.',
  },
  strict: {
    title: 'Strikt',
    description: 'Alleen voor deze namespace én deze secret-naam.',
  },
  'cluster-wide': {
    title: 'Cluster-breed',
    description: 'Bruikbaar in elke namespace op het cluster.',
  },
};

const dateFormat = new Intl.DateTimeFormat('nl-NL', { dateStyle: 'medium' });

@Component({
  selector: 'app-root',
  imports: [FormsModule],
  templateUrl: './app.html',
  host: {
    '(keydown.control.enter)': 'seal()',
    '(keydown.meta.enter)': 'seal()',
  },
})
export class App {
  private readonly config = inject(ClusterConfigService);
  private readonly preferences = readPreferences();

  protected readonly CUSTOM_CLUSTER = CUSTOM_CLUSTER;
  protected readonly scopes = SCOPES.map((id) => ({ id, ...SCOPE_INFO[id] }));
  protected readonly clusters = this.config.clusters;
  protected readonly configLoading = this.config.loading;
  protected readonly configError = this.config.error;

  // --- Inputs -------------------------------------------------------------

  protected readonly clusterId = signal(this.preferences.clusterId ?? '');
  protected readonly customPem = signal('');
  protected readonly namespace = signal(this.preferences.namespace ?? '');
  protected readonly scope = linkedSignal<SealScope>(
    () => this.preferences.scope ?? this.config.defaultScope(),
  );
  protected readonly secretName = signal('');
  protected readonly mode = signal<Mode>('value');
  protected readonly value = signal('');
  protected readonly entries = signal<Entry[]>([{ id: 1, key: '', value: '' }]);
  private nextEntryId = 2;

  // --- Derived state ------------------------------------------------------

  /** Falls back to the first configured cluster when nothing (valid) is stored. */
  protected readonly selectedClusterId = computed(() => {
    const id = this.clusterId();
    if (id === CUSTOM_CLUSTER || this.clusters().some((c) => c.id === id)) {
      return id;
    }
    return this.clusters()[0]?.id ?? (this.configLoading() ? '' : CUSTOM_CLUSTER);
  });

  protected readonly selectedCluster = computed(() =>
    this.clusters().find((c) => c.id === this.selectedClusterId()),
  );

  private readonly customCertificate = signal<CertificateState | null>(null);

  protected readonly certificateState = computed<CertificateState | null>(() =>
    this.selectedClusterId() === CUSTOM_CLUSTER
      ? this.customCertificate()
      : (this.selectedCluster()?.certificate ?? null),
  );

  protected readonly certificateSummary = computed(() => {
    const state = this.certificateState();
    if (state?.status !== 'ready') return null;
    const { notAfter, fingerprint } = state.certificate;
    return {
      validUntil: dateFormat.format(notAfter),
      expired: notAfter.getTime() < Date.now(),
      shortFingerprint: fingerprint.split(':').slice(0, 6).join(':') + '…',
      fingerprint,
      server: state.server,
    };
  });

  protected readonly certificateError = computed(() => {
    const state = this.certificateState();
    return state?.status === 'error' ? state.message : null;
  });

  protected readonly namespaceSuggestions = computed(() => this.selectedCluster()?.namespaces ?? []);

  protected readonly needsName = computed(
    () => this.mode() === 'manifest' || this.scope() === 'strict',
  );

  protected readonly needsNamespace = computed(
    () => this.mode() === 'manifest' || this.scope() !== 'cluster-wide',
  );

  protected readonly valueHints = computed(() => {
    const value = this.value();
    if (!value) return null;
    return {
      length: value.length,
      lines: value.split('\n').length,
      trailingWhitespace: /\s$/.test(value),
    };
  });

  /** Everything that must be fixed before we can seal, in reading order. */
  protected readonly problems = computed(() => {
    const problems: string[] = [];
    if (this.certificateState()?.status !== 'ready') {
      problems.push('Kies een cluster met een geldig certificaat.');
    }
    const namespace = this.namespace().trim();
    if (this.needsNamespace()) {
      if (!namespace) problems.push('Vul een namespace in.');
      else if (!isValidNamespace(namespace))
        problems.push('Een namespace bevat alleen kleine letters, cijfers en "-".');
    }
    const name = this.secretName().trim();
    if (this.needsName()) {
      if (!name) problems.push('Vul de naam van het Secret in.');
      else if (!isValidSecretName(name))
        problems.push('De secret-naam bevat alleen kleine letters, cijfers, "-" en ".".');
    }
    if (this.mode() === 'value') {
      if (!this.value()) problems.push('Vul de waarde in die je wilt versleutelen.');
    } else {
      const keys = this.entries().map((e) => e.key.trim());
      if (keys.some((k) => !k)) problems.push('Geef elke regel een key.');
      else if (keys.some((k) => !isValidSecretKey(k)))
        problems.push('Een key bevat alleen letters, cijfers, "-", "_" en ".".');
      else if (new Set(keys).size !== keys.length) problems.push('Elke key mag maar één keer voorkomen.');
      if (this.entries().some((e) => !e.value)) problems.push('Vul bij elke key een waarde in.');
    }
    return problems;
  });

  /** Identifies the inputs a result was made from, so we never show a stale result. */
  private readonly inputSnapshot = computed(() => {
    const state = this.certificateState();
    return JSON.stringify([
      state?.status === 'ready' ? state.certificate.fingerprint : null,
      this.namespace().trim(),
      this.scope(),
      this.secretName().trim(),
      this.mode(),
      this.mode() === 'value' ? this.value() : this.entries(),
    ]);
  });

  private readonly sealed = signal<{ snapshot: string; output: string } | null>(null);

  protected readonly result = computed(() => {
    const sealed = this.sealed();
    return sealed && sealed.snapshot === this.inputSnapshot() ? sealed.output : null;
  });

  protected readonly busy = signal(false);
  protected readonly sealError = signal<string | null>(null);
  protected readonly copied = signal(false);

  constructor() {
    effect(() => {
      writePreferences({
        clusterId: this.clusterId() || undefined,
        namespace: this.namespace().trim() || undefined,
        scope: this.scope(),
      });
    });
  }

  // --- Actions ------------------------------------------------------------

  protected async onCustomPemChange(pem: string): Promise<void> {
    this.customPem.set(pem);
    if (!pem.trim()) {
      this.customCertificate.set(null);
      return;
    }
    try {
      const certificate = await loadCertificate(pem);
      if (this.customPem() === pem) {
        this.customCertificate.set({ status: 'ready', certificate, server: null });
      }
    } catch (e) {
      if (this.customPem() === pem) {
        this.customCertificate.set({
          status: 'error',
          message: e instanceof Error ? e.message : 'Ongeldig certificaat',
        });
      }
    }
  }

  protected reloadCertificate(): void {
    void this.config.reload(this.selectedClusterId());
  }

  protected addEntry(): void {
    this.entries.update((entries) => [...entries, { id: this.nextEntryId++, key: '', value: '' }]);
  }

  protected removeEntry(id: number): void {
    this.entries.update((entries) => entries.filter((e) => e.id !== id));
  }

  protected updateEntry(id: number, change: Partial<Omit<Entry, 'id'>>): void {
    this.entries.update((entries) => entries.map((e) => (e.id === id ? { ...e, ...change } : e)));
  }

  protected trimValue(): void {
    this.value.update((v) => v.replace(/\s+$/, ''));
  }

  protected clearInput(): void {
    this.value.set('');
    this.entries.set([{ id: this.nextEntryId++, key: '', value: '' }]);
    this.sealed.set(null);
  }

  protected async seal(): Promise<void> {
    const state = this.certificateState();
    if (this.busy() || this.problems().length > 0 || state?.status !== 'ready') {
      return;
    }

    const snapshot = this.inputSnapshot();
    const namespace = this.namespace().trim();
    const name = this.secretName().trim();
    const label = encryptionLabel(this.scope(), namespace, name);
    const key = state.certificate.key;

    this.busy.set(true);
    this.sealError.set(null);
    try {
      let output: string;
      if (this.mode() === 'value') {
        output = await sealValue(key, this.value(), label);
      } else {
        const encryptedData: Record<string, string> = {};
        for (const entry of this.entries()) {
          encryptedData[entry.key.trim()] = await sealValue(key, entry.value, label);
        }
        output = buildSealedSecretManifest({ name, namespace, scope: this.scope(), encryptedData });
      }
      this.sealed.set({ snapshot, output });
      this.copied.set(false);
    } catch (e) {
      this.sealError.set(`Versleutelen mislukt: ${e instanceof Error ? e.message : e}`);
    } finally {
      this.busy.set(false);
    }
  }

  protected async copyResult(): Promise<void> {
    const result = this.result();
    if (!result) return;
    await navigator.clipboard.writeText(result);
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 2000);
  }

  protected downloadResult(): void {
    const result = this.result();
    if (!result) return;
    const url = URL.createObjectURL(new Blob([result], { type: 'application/yaml' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${this.secretName().trim()}.sealedsecret.yaml`;
    link.click();
    URL.revokeObjectURL(url);
  }
}

function readPreferences(): Preferences {
  try {
    const preferences = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}') as Preferences;
    if (preferences.scope && !SCOPES.includes(preferences.scope)) {
      delete preferences.scope;
    }
    return preferences;
  } catch {
    return {};
  }
}

function writePreferences(preferences: Preferences): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
  } catch {
    // Private mode or blocked storage: preferences are a convenience only.
  }
}
