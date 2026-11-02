import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { SealingCertificate, loadCertificate } from '../sealing/certificate';
import { SCOPES, SealScope } from '../sealing/seal';

/** Shape of `config/clusters.json`; mounted from a ConfigMap in OpenShift. */
export interface SealerConfig {
  defaultScope?: SealScope;
  clusters: ClusterDefinition[];
}

export interface ClusterDefinition {
  id: string;
  name: string;
  /** Public sealing certificate, relative to the app or an absolute same-origin URL. */
  certificateUrl: string;
  /** Suggestions for the namespace field. */
  namespaces?: string[];
}

export type CertificateState =
  | { status: 'loading' }
  | { status: 'ready'; certificate: SealingCertificate }
  | { status: 'error'; message: string };

export interface Cluster extends ClusterDefinition {
  certificate: CertificateState;
}

const CONFIG_URL = 'config/clusters.json';

@Injectable({ providedIn: 'root' })
export class ClusterConfigService {
  private readonly http = inject(HttpClient);

  readonly clusters = signal<Cluster[]>([]);
  readonly defaultScope = signal<SealScope>('namespace-wide');
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  constructor() {
    void this.load();
  }

  private async load(): Promise<void> {
    let config: SealerConfig;
    try {
      config = await firstValueFrom(this.http.get<SealerConfig>(CONFIG_URL));
    } catch {
      this.error.set(`Kon ${CONFIG_URL} niet laden.`);
      this.loading.set(false);
      return;
    }

    if (config.defaultScope && SCOPES.includes(config.defaultScope)) {
      this.defaultScope.set(config.defaultScope);
    }
    this.clusters.set(
      (config.clusters ?? []).map((c) => ({ ...c, certificate: { status: 'loading' } })),
    );
    this.loading.set(false);

    await Promise.all(this.clusters().map((c) => this.loadClusterCertificate(c.id)));
  }

  private async loadClusterCertificate(id: string): Promise<void> {
    const cluster = this.clusters().find((c) => c.id === id)!;
    let state: CertificateState;
    try {
      const pem = await firstValueFrom(
        this.http.get(cluster.certificateUrl, { responseType: 'text' }),
      );
      state = { status: 'ready', certificate: await loadCertificate(pem) };
    } catch (e) {
      // HttpErrorResponse is not an Error; parse failures are.
      state = {
        status: 'error',
        message: e instanceof Error ? e.message : 'Certificaat niet bereikbaar',
      };
    }
    this.clusters.update((all) => all.map((c) => (c.id === id ? { ...c, certificate: state } : c)));
  }
}
