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
  /** Fixed list of namespaces to choose from. */
  namespaces?: string[];
  /** URL returning a JSON array of namespace names; takes precedence over `namespaces`. */
  namespacesUrl?: string;
}

export type CertificateState =
  | { status: 'loading' }
  | { status: 'ready'; certificate: SealingCertificate; server: string | null }
  | { status: 'error'; message: string };

export type NamespaceListState =
  | { status: 'loading' }
  | { status: 'ready'; names: string[] }
  | { status: 'error'; message: string };

export interface Cluster extends ClusterDefinition {
  certificate: CertificateState;
  /** Only set for clusters with a `namespacesUrl`. */
  namespaceList?: NamespaceListState;
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

  /** Fetches a cluster's live data again, e.g. after logging in to another cluster. */
  async reload(id: string): Promise<void> {
    const cluster = this.clusters().find((c) => c.id === id);
    if (!cluster) return;
    await Promise.all([
      this.loadCertificate(cluster),
      cluster.namespacesUrl ? this.loadNamespaces(id, cluster.namespacesUrl) : undefined,
    ]);
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

  private async loadCertificate(cluster: Cluster): Promise<void> {
    this.patch(cluster.id, { certificate: { status: 'loading' } });
    let certificate: CertificateState;
    try {
      const response = await firstValueFrom(
        this.http.get(cluster.certificateUrl, { responseType: 'text', observe: 'response' }),
      );
      certificate = {
        status: 'ready',
        certificate: await loadCertificate(response.body ?? ''),
        // Set by the dev server proxy, which knows which cluster it fetched from.
        server: response.headers.get('X-Cluster-Server'),
      };
    } catch (e) {
      certificate = { status: 'error', message: errorMessage(e, 'Certificaat niet bereikbaar') };
    }
    this.patch(cluster.id, { certificate });
  }

  private async loadNamespaces(id: string, url: string): Promise<void> {
    this.patch(id, { namespaceList: { status: 'loading' } });
    let namespaceList: NamespaceListState;
    try {
      const names = await firstValueFrom(this.http.get<unknown>(url));
      if (!Array.isArray(names) || names.some((n) => typeof n !== 'string')) {
        throw new Error('Onverwacht antwoord bij het ophalen van namespaces');
      }
      namespaceList = { status: 'ready', names };
    } catch (e) {
      namespaceList = { status: 'error', message: errorMessage(e, 'Namespaces niet bereikbaar') };
    }
    this.patch(id, { namespaceList });
  }

  private patch(id: string, change: Partial<Cluster>): void {
    this.clusters.update((all) => all.map((c) => (c.id === id ? { ...c, ...change } : c)));
  }
}

function errorMessage(e: unknown, fallback: string): string {
  if (e instanceof HttpErrorResponse) {
    // A short plain-text body (like the dev proxy's kubeseal error) says more than the status.
    return typeof e.error === 'string' && e.error.length < 500 && !e.error.includes('<')
      ? e.error
      : fallback;
  }
  return e instanceof Error ? e.message : fallback;
}
