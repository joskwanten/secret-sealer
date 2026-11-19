// @ts-check
import { loadCertificate } from './sealing/certificate.js';
import { SCOPES } from './sealing/seal.js';

/** @typedef {import('./sealing/seal.js').SealScope} SealScope */
/** @typedef {import('./sealing/certificate.js').SealingCertificate} SealingCertificate */

/**
 * Shape of `config/clusters.json`; mounted from a ConfigMap in OpenShift.
 * @typedef {object} SealerConfig
 * @property {SealScope} [defaultScope]
 * @property {ClusterDefinition[]} clusters
 */

/**
 * @typedef {object} ClusterDefinition
 * @property {string} id
 * @property {string} name
 * @property {string} certificateUrl Public sealing certificate, relative to the app or same-origin.
 * @property {string[]} [namespaces] Fixed list of namespaces to choose from.
 * @property {string} [namespacesUrl] URL returning a JSON array of names; wins over `namespaces`.
 */

/**
 * @typedef {{ status: 'loading' }
 *   | { status: 'ready', certificate: SealingCertificate, server: string | null }
 *   | { status: 'error', message: string }} CertificateState
 */

/**
 * @typedef {{ status: 'loading' }
 *   | { status: 'ready', names: string[] }
 *   | { status: 'error', message: string }} NamespaceListState
 */

/**
 * @typedef {ClusterDefinition & {
 *   certificate: CertificateState,
 *   namespaceList?: NamespaceListState,
 * }} Cluster
 */

const CONFIG_URL = 'config/clusters.json';

/**
 * Loads the cluster list, then each cluster's certificate (and live namespaces).
 * Calls `onChange` whenever something arrives, so the page can re-render.
 */
export class ClusterConfig {
  /** @type {Cluster[]} */
  clusters = [];
  /** @type {SealScope} */
  defaultScope = 'namespace-wide';
  loading = true;
  /** @type {string | null} */
  error = null;

  /** @param {() => void} onChange */
  constructor(onChange) {
    this.onChange = onChange;
  }

  async load() {
    /** @type {SealerConfig} */
    let config;
    try {
      const response = await fetch(CONFIG_URL, { cache: 'no-store' });
      if (!response.ok) throw new Error();
      config = await response.json();
    } catch {
      this.error = `Kon ${CONFIG_URL} niet laden.`;
      this.loading = false;
      this.onChange();
      return;
    }

    if (config.defaultScope && SCOPES.includes(config.defaultScope)) {
      this.defaultScope = config.defaultScope;
    }
    this.clusters = (config.clusters ?? []).map((c) => ({ ...c, certificate: { status: 'loading' } }));
    this.loading = false;
    this.onChange();

    await Promise.all(this.clusters.map((c) => this.reload(c.id)));
  }

  /**
   * Fetches a cluster's live data again, e.g. after logging in to another cluster.
   * @param {string} id
   */
  async reload(id) {
    const cluster = this.clusters.find((c) => c.id === id);
    if (!cluster) return;
    await Promise.all([
      this.#loadCertificate(cluster),
      cluster.namespacesUrl ? this.#loadNamespaces(cluster, cluster.namespacesUrl) : undefined,
    ]);
  }

  /** @param {Cluster} cluster */
  async #loadCertificate(cluster) {
    cluster.certificate = { status: 'loading' };
    this.onChange();
    try {
      const response = await get(cluster.certificateUrl, 'Certificaat niet bereikbaar');
      cluster.certificate = {
        status: 'ready',
        certificate: await loadCertificate(await response.text()),
        // Set by the local Go server, which knows which cluster it fetched from.
        server: response.headers.get('X-Cluster-Server'),
      };
    } catch (e) {
      cluster.certificate = { status: 'error', message: errorMessage(e, 'Certificaat niet bereikbaar') };
    }
    this.onChange();
  }

  /**
   * @param {Cluster} cluster
   * @param {string} url
   */
  async #loadNamespaces(cluster, url) {
    cluster.namespaceList = { status: 'loading' };
    this.onChange();
    try {
      const names = await (await get(url, 'Namespaces niet bereikbaar')).json();
      if (!Array.isArray(names) || names.some((n) => typeof n !== 'string')) {
        throw new Error('Onverwacht antwoord bij het ophalen van namespaces');
      }
      cluster.namespaceList = { status: 'ready', names };
    } catch (e) {
      cluster.namespaceList = { status: 'error', message: errorMessage(e, 'Namespaces niet bereikbaar') };
    }
    this.onChange();
  }
}

/**
 * GET that turns an error response into an Error with a useful message. A short plain-text body
 * (like the Go server's kubeseal error) says more than the status code.
 * @param {string} url
 * @param {string} fallback
 */
async function get(url, fallback) {
  const response = await fetch(url, { cache: 'no-store' });
  if (response.ok) return response;
  const body = await response.text().catch(() => '');
  throw new Error(body && body.length < 500 && !body.includes('<') ? body.trim() : fallback);
}

/**
 * @param {unknown} e
 * @param {string} fallback
 */
function errorMessage(e, fallback) {
  // TypeError = network failure, SyntaxError = not JSON: the browser's wording doesn't help anyone.
  if (e instanceof TypeError || e instanceof SyntaxError) return fallback;
  return e instanceof Error && e.message ? e.message : fallback;
}
