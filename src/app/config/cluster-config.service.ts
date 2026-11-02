import { HttpClient, HttpErrorResponse } from '@angular/common/http';
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
  | { status: 'ready'; certificate: SealingCertificate; server: string | null }
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

  /** Fetches a cluster's certificate again, e.g. after logging in to another cluster. */
  async reload(id: string): Promise<void> {
    const cluster = this.clusters().find((c) => c.id === id);
    if (!cluster) return;

    this.setCertificate(id, { status: 'loading' });
    let state: CertificateState;
    try {
      const response = await firstValueFrom(
        this.http.get(cluster.certificateUrl, { responseType: 'text', observe: 'response' }),
      );
      state = {
        status: 'ready',
        certificate: await loadCertificate(response.body ?? ''),
        // Set by the dev server proxy, which knows which cluster it fetched from.
        server: response.headers.get('X-Cluster-Server'),
      };
    } catch (e) {
      state = { status: 'error', message: errorMessage(e) };
    }
    this.setCertificate(id, state);
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

    await Promise.all(this.clusters().map((c) => this.reload(c.id)));
  }

  private setCertificate(id: string, state: CertificateState): void {
    this.clusters.update((all) => all.map((c) => (c.id === id ? { ...c, certificate: state } : c)));
  }
}

function errorMessage(e: unknown): string {
  if (e instanceof HttpErrorResponse) {
    // A short plain-text body (like the dev proxy's kubeseal error) says more than the status.
    return typeof e.error === 'string' && e.error.length < 500 && !e.error.includes('<')
      ? e.error
      : 'Certificaat niet bereikbaar';
  }
  return e instanceof Error ? e.message : 'Certificaat niet bereikbaar';
}
