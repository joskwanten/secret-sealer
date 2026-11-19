// @ts-check
import { Combobox } from './combobox.js';
import { ClusterConfig } from './config.js';
import { loadCertificate } from './sealing/certificate.js';
import { buildSealedSecretManifest } from './sealing/manifest.js';
import { SCOPES, encryptionLabel, sealValue } from './sealing/seal.js';
import { isValidNamespace, isValidSecretKey, isValidSecretName } from './sealing/validation.js';

/** @typedef {import('./sealing/seal.js').SealScope} SealScope */
/** @typedef {import('./config.js').CertificateState} CertificateState */
/** @typedef {'value' | 'manifest'} Mode */
/** @typedef {{ id: number, key: string, value: string }} Entry */

const CUSTOM_CLUSTER = '__custom__';
const STORAGE_KEY = 'secret-sealer.preferences';

/** @type {Record<SealScope, { title: string, description: string }>} */
const SCOPE_INFO = {
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

// --- State ------------------------------------------------------------------
// Everything the page shows is derived from `state` and `config` by render().

const preferences = readPreferences();
const config = new ClusterConfig(render);

const state = {
  clusterId: preferences.clusterId ?? '',
  customPem: '',
  /** @type {CertificateState | null} */
  customCertificate: null,
  namespace: preferences.namespace ?? '',
  /** Null until chosen (here or earlier); then the config's default applies. */
  /** @type {SealScope | null} */
  scope: preferences.scope ?? null,
  secretName: '',
  /** @type {Mode} */
  mode: 'value',
  value: '',
  /** @type {Entry[]} */
  entries: [{ id: 1, key: '', value: '' }],
  nextEntryId: 2,
  /** @type {{ snapshot: string, output: string } | null} */
  sealed: null,
  busy: false,
  /** @type {string | null} */
  sealError: null,
  copied: false,
};

// --- Derived state ----------------------------------------------------------

/** @returns {SealScope} */
const scope = () => state.scope ?? config.defaultScope;

/** Falls back to the first configured cluster when nothing (valid) is stored. */
function selectedClusterId() {
  const id = state.clusterId;
  if (id === CUSTOM_CLUSTER || config.clusters.some((c) => c.id === id)) return id;
  return config.clusters[0]?.id ?? (config.loading ? '' : CUSTOM_CLUSTER);
}

const selectedCluster = () => config.clusters.find((c) => c.id === selectedClusterId());

/** @returns {CertificateState | null} */
function certificateState() {
  return selectedClusterId() === CUSTOM_CLUSTER
    ? state.customCertificate
    : (selectedCluster()?.certificate ?? null);
}

/** Live list from the cluster when configured, otherwise the fixed list from the config. */
function namespaceList() {
  const cluster = selectedCluster();
  if (cluster?.namespaceList) return cluster.namespaceList;
  return cluster?.namespaces?.length
    ? /** @type {const} */ ({ status: 'ready', names: cluster.namespaces })
    : null;
}

function namespaceOptions() {
  const list = namespaceList();
  return list?.status === 'ready' && list.names.length > 0 ? list.names : null;
}

const needsName = () => state.mode === 'manifest' || scope() === 'strict';
const needsNamespace = () => state.mode === 'manifest' || scope() !== 'cluster-wide';

/** Everything that must be fixed before we can seal, in reading order. */
function problems() {
  const problems = [];
  if (certificateState()?.status !== 'ready') {
    problems.push('Kies een cluster met een geldig certificaat.');
  }
  const namespace = state.namespace.trim();
  if (needsNamespace()) {
    if (!namespace) problems.push('Vul een namespace in.');
    else if (!isValidNamespace(namespace))
      problems.push('Een namespace bevat alleen kleine letters, cijfers en "-".');
  }
  const name = state.secretName.trim();
  if (needsName()) {
    if (!name) problems.push('Vul de naam van het Secret in.');
    else if (!isValidSecretName(name))
      problems.push('De secret-naam bevat alleen kleine letters, cijfers, "-" en ".".');
  }
  if (state.mode === 'value') {
    if (!state.value) problems.push('Vul de waarde in die je wilt versleutelen.');
  } else {
    const keys = state.entries.map((e) => e.key.trim());
    if (keys.some((k) => !k)) problems.push('Geef elke regel een key.');
    else if (keys.some((k) => !isValidSecretKey(k)))
      problems.push('Een key bevat alleen letters, cijfers, "-", "_" en ".".');
    else if (new Set(keys).size !== keys.length) problems.push('Elke key mag maar één keer voorkomen.');
    if (state.entries.some((e) => !e.value)) problems.push('Vul bij elke key een waarde in.');
  }
  return problems;
}

/** Identifies the inputs a result was made from, so we never show a stale result. */
function inputSnapshot() {
  const cert = certificateState();
  return JSON.stringify([
    cert?.status === 'ready' ? cert.certificate.fingerprint : null,
    state.namespace.trim(),
    scope(),
    state.secretName.trim(),
    state.mode,
    state.mode === 'value' ? state.value : state.entries,
  ]);
}

function result() {
  return state.sealed && state.sealed.snapshot === inputSnapshot() ? state.sealed.output : null;
}

// --- Elements ---------------------------------------------------------------

/** @param {string} id */
const $ = (id) => /** @type {HTMLElement} */ (document.getElementById(id));
const field = (/** @type {string} */ id) => /** @type {HTMLInputElement} */ ($(id));
/**
 * @param {Element} parent
 * @param {string} selector
 */
const child = (parent, selector) => /** @type {HTMLElement} */ (parent.querySelector(selector));

const el = {
  configError: $('config-error'),
  clusters: $('clusters'),
  clustersLoading: $('clusters-loading'),
  customChoice: $('custom-choice'),
  customPemField: $('custom-pem-field'),
  customPem: field('custom-pem'),
  certServer: $('cert-server'),
  certInfo: $('cert-info'),
  certError: $('cert-error'),
  namespaceOptional: $('namespace-optional'),
  namespaceError: $('namespace-error'),
  secretNameField: $('secret-name-field'),
  secretName: field('secret-name'),
  scopes: $('scopes'),
  tabs: /** @type {HTMLButtonElement[]} */ ([...document.querySelectorAll('[data-mode]')]),
  valueMode: $('value-mode'),
  value: field('value'),
  valueHints: $('value-hints'),
  manifestMode: $('manifest-mode'),
  entries: $('entries'),
  seal: /** @type {HTMLButtonElement} */ ($('seal')),
  problems: $('problems'),
  sealError: $('seal-error'),
  result: $('result'),
  output: /** @type {HTMLTextAreaElement} */ ($('output')),
  download: $('download'),
  copy: $('copy'),
  resultHelpValue: $('result-help-value'),
  resultHelpManifest: $('result-help-manifest'),
};

const namespaceBox = new Combobox($('namespace-combobox'), {
  inputId: 'namespace-input',
  onChange: (value) => update({ namespace: value }),
});
namespaceBox.value = state.namespace;

/** @type {Map<string, HTMLLabelElement>} */
const clusterCards = new Map([[CUSTOM_CLUSTER, /** @type {HTMLLabelElement} */ (el.customChoice)]]);
/** @type {Map<SealScope, HTMLLabelElement>} */
const scopeCards = new Map();
/** @type {Map<number, HTMLElement>} */
const entryRows = new Map();

// --- Rendering --------------------------------------------------------------

/** @param {Partial<typeof state>} change */
function update(change) {
  Object.assign(state, change);
  render();
}

let lastPreferences = '';

function render() {
  const clusterId = selectedClusterId();
  const cert = certificateState();

  // Cluster
  el.configError.hidden = !config.error;
  el.configError.textContent = config.error
    ? `${config.error} Je kunt hieronder wel een eigen certificaat plakken.`
    : '';
  el.clustersLoading.hidden = !config.loading;
  renderClusterCards(clusterId);
  el.customPemField.hidden = clusterId !== CUSTOM_CLUSTER;

  const ready = cert?.status === 'ready' ? cert : null;
  el.certServer.hidden = !ready?.server;
  child(el.certServer, 'strong').textContent = ready?.server ?? '';
  el.certInfo.hidden = !ready;
  if (ready) {
    const { notAfter, fingerprint } = ready.certificate;
    const validUntil = dateFormat.format(notAfter);
    const expired = notAfter.getTime() < Date.now();
    el.certInfo.classList.toggle('warn', expired);
    child(el.certInfo, '.cert-validity').textContent = expired
      ? `Dit certificaat is verlopen op ${validUntil}. Controleer of het nog actueel is.`
      : `Certificaat geldig tot ${validUntil}`;
    const fp = /** @type {HTMLElement} */ (el.certInfo.querySelector('.cert-fingerprint'));
    fp.textContent = `SHA-256 ${fingerprint.split(':').slice(0, 6).join(':')}…`;
    fp.title = fingerprint;
    /** @type {HTMLElement} */ (el.certInfo.querySelector('.cert-reload')).hidden =
      clusterId === CUSTOM_CLUSTER;
  }
  el.certError.hidden = cert?.status !== 'error';
  child(el.certError, 'span').textContent = cert?.status === 'error' ? cert.message : '';

  // Namespace, name, scope
  const options = namespaceOptions();
  const list = namespaceList();
  el.namespaceOptional.hidden = needsNamespace();
  namespaceBox.update({
    options: options ?? [],
    loading: list?.status === 'loading',
    disabled: !needsNamespace(),
    placeholder: options ? 'Kies of typ een namespace' : 'bijv. team-a-ont',
  });
  el.namespaceError.hidden = list?.status !== 'error';
  el.namespaceError.textContent =
    list?.status === 'error' ? `Namespaces niet opgehaald. ${list.message} Typ de namespace zelf in.` : '';

  el.secretNameField.hidden = !needsName();
  setValue(el.secretName, state.secretName);

  for (const [id, card] of scopeCards) {
    const selected = scope() === id;
    card.classList.toggle('selected', selected);
    /** @type {HTMLInputElement} */ (card.querySelector('input')).checked = selected;
  }

  // Input
  for (const tab of el.tabs) {
    tab.setAttribute('aria-selected', String(tab.dataset.mode === state.mode));
  }
  el.valueMode.hidden = state.mode !== 'value';
  el.manifestMode.hidden = state.mode !== 'manifest';
  setValue(el.value, state.value);
  renderValueHints();
  renderEntries();

  const currentProblems = problems();
  el.seal.disabled = currentProblems.length > 0 || state.busy;
  el.seal.textContent = state.busy ? 'Versleutelen…' : 'Versleutelen';
  el.problems.hidden = currentProblems.length === 0;
  el.problems.replaceChildren(
    ...currentProblems.map((p) => Object.assign(document.createElement('li'), { textContent: p })),
  );
  el.sealError.hidden = !state.sealError;
  el.sealError.textContent = state.sealError ?? '';

  // Result
  const output = result();
  el.result.hidden = output === null;
  if (output !== null) {
    setValue(el.output, output);
    el.output.rows = state.mode === 'manifest' ? 16 : 6;
    el.download.hidden = state.mode !== 'manifest';
    el.copy.textContent = state.copied ? 'Gekopieerd ✓' : 'Kopiëren';
    el.resultHelpValue.hidden = state.mode !== 'value';
    el.resultHelpManifest.hidden = state.mode !== 'manifest';
  }

  savePreferences();
}

/** @param {string} clusterId */
function renderClusterCards(clusterId) {
  for (const cluster of config.clusters) {
    let card = clusterCards.get(cluster.id);
    if (!card) {
      card = choiceCard('cluster', cluster.id, cluster.name, '');
      card.querySelector('input')?.addEventListener('change', () => update({ clusterId: cluster.id }));
      el.clusters.insertBefore(card, el.clustersLoading);
      clusterCards.set(cluster.id, card);
    }
    const meta = /** @type {HTMLElement} */ (card.querySelector('.choice-meta'));
    const status = cluster.certificate.status;
    if (meta.dataset.status !== status) {
      meta.dataset.status = status;
      meta.innerHTML = {
        loading: 'Certificaat laden…',
        ready: '<span class="dot ok"></span> Klaar voor gebruik',
        error: '<span class="dot error"></span> Certificaat niet beschikbaar',
      }[status];
    }
  }
  for (const [id, card] of clusterCards) {
    card.classList.toggle('selected', id === clusterId);
    /** @type {HTMLInputElement} */ (card.querySelector('input')).checked = id === clusterId;
  }
}

function renderValueHints() {
  const value = state.value;
  el.valueHints.hidden = !value;
  if (!value) return;
  const lines = value.split('\n').length;
  child(el.valueHints, '.hint-counts').textContent =
    `${value.length} tekens · ${lines} ${lines === 1 ? 'regel' : 'regels'}`;
  /** @type {HTMLElement} */ (el.valueHints.querySelector('.hint-trailing')).hidden = !/\s$/.test(value);
}

/** Rows are created once per entry and reused, so typing never loses focus. */
function renderEntries() {
  const rows = state.entries.map((entry, i) => {
    let row = entryRows.get(entry.id);
    if (!row) {
      row = entryRow(entry);
      entryRows.set(entry.id, row);
    }
    setValue(/** @type {HTMLInputElement} */ (row.querySelector('input')), entry.key);
    setValue(/** @type {HTMLTextAreaElement} */ (row.querySelector('textarea')), entry.value);
    const remove = /** @type {HTMLButtonElement} */ (row.querySelector('.icon-button'));
    remove.disabled = state.entries.length === 1;
    remove.setAttribute('aria-label', `Verwijder regel ${i + 1}`);
    return row;
  });
  for (const id of entryRows.keys()) {
    if (!state.entries.some((e) => e.id === id)) entryRows.delete(id);
  }
  const current = [...el.entries.children];
  if (current.length !== rows.length || current.some((c, i) => c !== rows[i])) {
    el.entries.replaceChildren(...rows);
  }
}

/** @param {Entry} entry */
function entryRow(entry) {
  const row = document.createElement('div');
  row.className = 'entry';
  row.innerHTML = `
    <label class="field entry-key">
      <span class="label">Key</span>
      <input type="text" autocomplete="off" spellcheck="false" placeholder="bijv. PASSWORD" />
    </label>
    <label class="field entry-value">
      <span class="label">Waarde</span>
      <textarea class="mono secret-input" rows="2" spellcheck="false" autocomplete="off"></textarea>
    </label>
    <button type="button" class="icon-button" title="Verwijder">×</button>`;
  /** @param {Partial<Entry>} change */
  const updateEntry = (change) =>
    update({ entries: state.entries.map((e) => (e.id === entry.id ? { ...e, ...change } : e)) });
  const key = /** @type {HTMLInputElement} */ (row.querySelector('input'));
  const value = /** @type {HTMLTextAreaElement} */ (row.querySelector('textarea'));
  key.addEventListener('input', () => updateEntry({ key: key.value }));
  value.addEventListener('input', () => updateEntry({ value: value.value }));
  row.querySelector('button')?.addEventListener('click', () =>
    update({ entries: state.entries.filter((e) => e.id !== entry.id) }),
  );
  return row;
}

/**
 * @param {string} name
 * @param {string} value
 * @param {string} title
 * @param {string} meta
 */
function choiceCard(name, value, title, meta) {
  const card = document.createElement('label');
  card.className = 'choice';
  const input = Object.assign(document.createElement('input'), { type: 'radio', name, value });
  const titleEl = Object.assign(document.createElement('span'), { className: 'choice-title', textContent: title });
  const metaEl = Object.assign(document.createElement('span'), { className: 'choice-meta', textContent: meta });
  card.append(input, titleEl, metaEl);
  return card;
}

/**
 * Only touches the field when it differs, so the caret stays put while typing.
 * @param {HTMLInputElement | HTMLTextAreaElement} input
 * @param {string} value
 */
function setValue(input, value) {
  if (input.value !== value) input.value = value;
}

// --- Actions ----------------------------------------------------------------

/** @param {string} pem */
async function onCustomPemChange(pem) {
  update({ customPem: pem });
  if (!pem.trim()) {
    update({ customCertificate: null });
    return;
  }
  try {
    const certificate = await loadCertificate(pem);
    if (state.customPem === pem) {
      update({ customCertificate: { status: 'ready', certificate, server: null } });
    }
  } catch (e) {
    if (state.customPem === pem) {
      update({
        customCertificate: {
          status: 'error',
          message: e instanceof Error ? e.message : 'Ongeldig certificaat',
        },
      });
    }
  }
}

async function seal() {
  const cert = certificateState();
  if (state.busy || problems().length > 0 || cert?.status !== 'ready') return;

  const snapshot = inputSnapshot();
  const namespace = state.namespace.trim();
  const name = state.secretName.trim();
  const currentScope = scope();
  const label = encryptionLabel(currentScope, namespace, name);
  const key = cert.certificate.key;

  update({ busy: true, sealError: null });
  try {
    let output;
    if (state.mode === 'value') {
      output = await sealValue(key, state.value, label);
    } else {
      /** @type {Record<string, string>} */
      const encryptedData = {};
      for (const entry of state.entries) {
        encryptedData[entry.key.trim()] = await sealValue(key, entry.value, label);
      }
      output = buildSealedSecretManifest({ name, namespace, scope: currentScope, encryptedData });
    }
    update({ sealed: { snapshot, output }, copied: false });
  } catch (e) {
    update({ sealError: `Versleutelen mislukt: ${e instanceof Error ? e.message : e}` });
  } finally {
    update({ busy: false });
  }
}

async function copyResult() {
  const output = result();
  if (output === null) return;
  await navigator.clipboard.writeText(output);
  update({ copied: true });
  setTimeout(() => update({ copied: false }), 2000);
}

function downloadResult() {
  const output = result();
  if (output === null) return;
  const url = URL.createObjectURL(new Blob([output], { type: 'application/yaml' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = `${state.secretName.trim()}.sealedsecret.yaml`;
  link.click();
  URL.revokeObjectURL(url);
}

// --- Wiring -----------------------------------------------------------------

for (const id of SCOPES) {
  const card = choiceCard('scope', id, SCOPE_INFO[id].title, SCOPE_INFO[id].description);
  card.querySelector('input')?.addEventListener('change', () => update({ scope: id }));
  el.scopes.append(card);
  scopeCards.set(id, card);
}

el.customChoice.querySelector('input')?.addEventListener('change', () => update({ clusterId: CUSTOM_CLUSTER }));
el.customPem.addEventListener('input', () => onCustomPemChange(el.customPem.value));
for (const button of el.certInfo.querySelectorAll('button'))
  button.addEventListener('click', () => config.reload(selectedClusterId()));
for (const button of el.certError.querySelectorAll('button'))
  button.addEventListener('click', () => config.reload(selectedClusterId()));

el.secretName.addEventListener('input', () => update({ secretName: el.secretName.value }));
for (const tab of el.tabs) {
  tab.addEventListener('click', () => update({ mode: /** @type {Mode} */ (tab.dataset.mode) }));
}
el.value.addEventListener('input', () => update({ value: el.value.value }));
el.valueHints
  .querySelector('button')
  ?.addEventListener('click', () => update({ value: state.value.replace(/\s+$/, '') }));
$('add-entry').addEventListener('click', () =>
  update({
    entries: [...state.entries, { id: state.nextEntryId, key: '', value: '' }],
    nextEntryId: state.nextEntryId + 1,
  }),
);
$('clear').addEventListener('click', () =>
  update({
    value: '',
    entries: [{ id: state.nextEntryId, key: '', value: '' }],
    nextEntryId: state.nextEntryId + 1,
    sealed: null,
  }),
);
el.seal.addEventListener('click', seal);
el.copy.addEventListener('click', copyResult);
el.download.addEventListener('click', downloadResult);
el.output.addEventListener('focus', () => el.output.select());
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) seal();
});

render();
config.load();

// --- Preferences ------------------------------------------------------------

/** @returns {{ clusterId?: string, namespace?: string, scope?: SealScope }} */
function readPreferences() {
  try {
    const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}');
    if (stored.scope && !SCOPES.includes(stored.scope)) delete stored.scope;
    return stored;
  } catch {
    return {};
  }
}

/** Cluster, namespace and a chosen scope are remembered; values never are. */
function savePreferences() {
  const json = JSON.stringify({
    clusterId: state.clusterId || undefined,
    namespace: state.namespace.trim() || undefined,
    scope: state.scope ?? undefined,
  });
  if (json === lastPreferences) return;
  lastPreferences = json;
  try {
    localStorage.setItem(STORAGE_KEY, json);
  } catch {
    // Private mode or blocked storage: preferences are a convenience only.
  }
}
