// Dev server only (`npm start`): answers live cluster lookups with your own oc/kubectl login,
// so no cert files or namespace lists need to be maintained for local use.
//
//   GET /live-certs/current                 → sealing cert of the cluster you're logged in to
//   GET /live-namespaces/current            → JSON list of projects/namespaces you can see
//   GET /live-<…>/<url-encoded context>     → same, via a specific kubeconfig context
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

const CONTROLLER_NAMESPACE = process.env.SEALED_SECRETS_NAMESPACE ?? 'cd-sealed-secrets';
const CONTROLLER_NAME = process.env.SEALED_SECRETS_NAME ?? 'sealed-secrets';

const contextArgs = (context) => (context === 'current' ? [] : [`--context=${context}`]);

async function fetchCertificate(context) {
  const { stdout } = await run(
    'kubeseal',
    [
      `--controller-namespace=${CONTROLLER_NAMESPACE}`,
      `--controller-name=${CONTROLLER_NAME}`,
      ...contextArgs(context),
      '--fetch-cert',
    ],
    { timeout: 20_000, windowsHide: true },
  );
  return stdout;
}

/** Best effort: which API server we talked to, so you can see you have the right cluster. */
async function apiServer(context) {
  const attempts = [
    ['oc', ['whoami', '--show-server', ...contextArgs(context)]],
    ['kubectl', ['config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}', ...contextArgs(context)]],
  ];
  for (const [cli, args] of attempts) {
    try {
      const { stdout } = await run(cli, args, { timeout: 5_000, windowsHide: true });
      if (stdout.trim()) return stdout.trim();
    } catch {
      // Try the next CLI.
    }
  }
  return null;
}

/**
 * OpenShift projects only include what you have access to, so they work without
 * cluster-wide rights; plain namespaces are the fallback for non-OpenShift clusters.
 */
async function listNamespaces(context) {
  const jsonpath = ['-o', 'jsonpath={.items[*].metadata.name}'];
  const errors = [];
  for (const [cli, args] of [
    ['oc', ['get', 'projects', ...jsonpath, ...contextArgs(context)]],
    ['kubectl', ['get', 'namespaces', ...jsonpath, ...contextArgs(context)]],
  ]) {
    try {
      const { stdout } = await run(cli, args, { timeout: 20_000, windowsHide: true });
      return stdout.split(/\s+/).filter(Boolean).sort();
    } catch (e) {
      errors.push(e);
    }
  }
  // A real error from oc (e.g. Unauthorized) says more than "kubectl not installed".
  throw errors.find((e) => e.code !== 'ENOENT') ?? errors[0];
}

/** Proxy entry that never proxies: `bypass` answers every request under `prefix` itself. */
function liveEndpoint(prefix, handler) {
  return {
    [prefix]: {
      target: 'http://127.0.0.1:9',
      bypass: async (req, res) => {
        const context = decodeURIComponent(
          new URL(req.url, 'http://localhost').pathname.slice(prefix.length),
        );
        res.setHeader('Cache-Control', 'no-store');

        if (!context || context.startsWith('-')) {
          res.statusCode = 400;
          res.end('Ongeldige context');
          return req.url;
        }

        try {
          await handler(context, res);
        } catch (e) {
          const detail = e.stderr?.toString().trim().split('\n').pop() || e.message;
          res.statusCode = 502;
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
          res.end(
            e.code === 'ENOENT'
              ? `${e.path} is niet gevonden. Staat het in je PATH?`
              : `Fout bij ${e.cmd?.split(' ')[0] ?? 'ophalen'}: ${detail.replace(/\.$/, '')}. Ben je ingelogd met oc login?`,
          );
        }
        return req.url;
      },
    },
  };
}

export default {
  ...liveEndpoint('/live-certs/', async (context, res) => {
    const [pem, server] = await Promise.all([fetchCertificate(context), apiServer(context)]);
    res.setHeader('Content-Type', 'application/x-pem-file');
    if (server) res.setHeader('X-Cluster-Server', server);
    res.end(pem);
  }),
  ...liveEndpoint('/live-namespaces/', async (context, res) => {
    const namespaces = await listNamespaces(context);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(namespaces));
  }),
};
