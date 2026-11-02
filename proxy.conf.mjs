// Dev server only (`npm start`): serves live sealing certificates by running
// `kubeseal --fetch-cert` with your own oc/kubectl login, so no cert files are needed.
//
//   GET /live-certs/current            → cert of the cluster you're currently logged in to
//   GET /live-certs/<url-encoded ctx>  → cert via a specific kubeconfig context
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

const CONTROLLER_NAMESPACE = process.env.SEALED_SECRETS_NAMESPACE ?? 'cd-sealed-secrets';
const CONTROLLER_NAME = process.env.SEALED_SECRETS_NAME ?? 'sealed-secrets';
const PREFIX = '/live-certs/';

async function fetchCertificate(context) {
  const contextArgs = context === 'current' ? [] : [`--context=${context}`];
  const { stdout } = await run(
    'kubeseal',
    [
      `--controller-namespace=${CONTROLLER_NAMESPACE}`,
      `--controller-name=${CONTROLLER_NAME}`,
      ...contextArgs,
      '--fetch-cert',
    ],
    { timeout: 20_000, windowsHide: true },
  );
  return stdout;
}

/** Best effort: which API server the cert came from, so you can see you have the right cluster. */
async function apiServer(context) {
  const contextArgs = context === 'current' ? [] : [`--context=${context}`];
  for (const cli of ['oc', 'kubectl']) {
    try {
      const args =
        cli === 'oc'
          ? ['whoami', '--show-server', ...contextArgs]
          : ['config', 'view', '--minify', '-o', 'jsonpath={.clusters[0].cluster.server}', ...contextArgs];
      const { stdout } = await run(cli, args, { timeout: 5_000, windowsHide: true });
      if (stdout.trim()) return stdout.trim();
    } catch {
      // Try the next CLI.
    }
  }
  return null;
}

export default {
  [PREFIX]: {
    // Never contacted: the bypass below always answers the request itself.
    target: 'http://127.0.0.1:9',
    bypass: async (req, res) => {
      const context = decodeURIComponent(new URL(req.url, 'http://localhost').pathname.slice(PREFIX.length));
      res.setHeader('Cache-Control', 'no-store');

      if (!context || context.startsWith('-')) {
        res.statusCode = 400;
        res.end('Ongeldige context');
        return req.url;
      }

      try {
        const [pem, server] = await Promise.all([fetchCertificate(context), apiServer(context)]);
        res.setHeader('Content-Type', 'application/x-pem-file');
        if (server) res.setHeader('X-Cluster-Server', server);
        res.end(pem);
      } catch (e) {
        const detail = e.stderr?.toString().trim().split('\n').pop() || e.message;
        res.statusCode = 502;
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.end(
          e.code === 'ENOENT'
            ? 'kubeseal is niet gevonden. Installeer het, bijv. met: scoop install kubeseal'
            : `Ophalen via kubeseal mislukt (${detail}). Ben je ingelogd met oc login?`,
        );
      }
      return req.url;
    },
  },
};
