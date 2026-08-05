'use strict';

const $ = (id) => document.getElementById(id);
let pending = null;
let generation = 0;
const token = () => sessionStorage.getItem('blackglass-admin-token');
const label = (key) => key.replace(/[A-Z]/g, (match) => ` ${match.toLowerCase()}`);
const bytes = (value) => {
  if (value == null) return 'Unavailable';
  let number = Number(value);
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let index = 0;
  while (Math.abs(number) >= 1024 && index < units.length - 1) { number /= 1024; index += 1; }
  return `${number.toFixed(index ? 1 : 0)} ${units[index]}`;
};
const time = (value) => value == null ? 'Unavailable' : new Date(value).toLocaleString();
const duration = (value) => value == null ? 'Unavailable'
  : value < 60 ? `${value} s`
  : value < 3600 ? `${Math.round(value / 60)} min`
  : value < 86400 ? `${Math.round(value / 3600)} h`
  : `${Math.round(value / 86400)} d`;
const display = (key, value) => key.match(/bytes|size/i) ? bytes(value)
  : key.match(/at$|timestamp|created|expires|revoked/i) && typeof value === 'number' ? time(value)
  : key.match(/seconds/i) ? duration(value)
  : typeof value === 'boolean' ? (value ? 'Yes' : 'No')
  : (value ?? 'Unavailable');

function definitionList(id, object) {
  const element = $(id);
  element.replaceChildren();
  for (const [key, value] of Object.entries(object)) {
    const term = document.createElement('dt');
    const detail = document.createElement('dd');
    term.textContent = label(key);
    detail.textContent = display(key, value);
    element.append(term, detail);
  }
}

function rows(id, items, empty) {
  const element = $(id);
  element.replaceChildren();
  if (!items.length) {
    const message = document.createElement('p');
    message.textContent = empty;
    element.append(message);
    return;
  }
  for (const item of items) {
    const article = document.createElement('article');
    const title = document.createElement('strong');
    const fields = document.createElement('div');
    fields.className = 'fields';
    title.textContent = String(item.name || item.device || item.eventType || 'Session');
    for (const [key, value] of Object.entries(item)) {
      if (['name', 'device', 'eventType'].includes(key)) continue;
      const field = document.createElement('span');
      const fieldLabel = document.createElement('span');
      const fieldValue = document.createElement('span');
      field.className = 'field';
      fieldLabel.className = 'label';
      fieldValue.className = 'value';
      fieldLabel.textContent = label(key);
      fieldValue.textContent = display(key, value);
      field.append(fieldLabel, fieldValue);
      fields.append(field);
    }
    article.append(title, fields);
    element.append(article);
  }
}

function busy(active) {
  $('connect').disabled = active;
  $('refresh').disabled = active;
  $('refresh').textContent = active ? 'Refreshing…' : 'Refresh';
  $('dashboard').setAttribute('aria-busy', String(active));
  if (active) $('refreshed').textContent = 'Refreshing dashboard…';
}

function forget(message = '') {
  generation += 1;
  if (pending) pending.controller.abort();
  pending = null;
  busy(false);
  sessionStorage.removeItem('blackglass-admin-token');
  $('dashboard').hidden = true;
  $('login').hidden = false;
  $('token').value = '';
  $('refreshed').textContent = 'Not connected';
  $('login-error').textContent = message;
  $('token').focus();
}

async function load(manual = false) {
  if (pending) return pending.promise;
  const requestGeneration = ++generation;
  const controller = new AbortController();
  const wasHidden = $('dashboard').hidden;
  const promise = (async () => {
    busy(true);
    $('login-error').textContent = '';
    try {
      const response = await fetch('/admin/api/snapshot', {
        headers: { Authorization: `Bearer ${token() || ''}` },
        cache: 'no-store',
        signal: controller.signal,
      });
      if (requestGeneration !== generation) return;
      if (response.status === 401) { forget('Invalid admin token.'); return; }
      if (!response.ok) throw Error(response.status === 429
        ? 'Request rate limited; retry shortly.'
        : 'Snapshot unavailable.');
      const snapshot = await response.json();
      if (requestGeneration !== generation || !token()) return;
      $('login').hidden = true;
      $('dashboard').hidden = false;
      $('health').textContent = snapshot.overview.healthy ? 'Healthy' : 'Degraded';
      $('health').className = snapshot.overview.healthy ? 'good' : 'bad';
      $('version').textContent = `Version ${snapshot.overview.version}`;
      $('refreshed').textContent = `Refreshed ${time(snapshot.generatedAt)}`;
      definitionList('overview', {
        ...snapshot.overview,
        perFileLimitBytes: snapshot.limits.perFileBytes,
        retainedStorageLimitBytes: snapshot.limits.retainedStorageBytes,
        ownerStorageLimitBytes: snapshot.limits.retainedStorageBytesPerOwner,
        sessionLimit: snapshot.limits.maxSessions,
        connectionLimit: snapshot.limits.maxConnections,
        connectionLimitPerUser: snapshot.limits.maxConnectionsPerUser,
        uploadLimit: snapshot.limits.maxUploads,
        uploadLimitPerUser: snapshot.limits.maxUploadsPerUser,
      });
      $('user-title').textContent = `Users — ${snapshot.counts.usersActive} active / ${snapshot.counts.usersDisabled} disabled (${snapshot.counts.usersVisible} visible)`;
      $('vault-title').textContent = `Vaults — ${snapshot.counts.vaultsVisible} visible / ${snapshot.counts.vaultsTotal} total`;
      $('connection-title').textContent = `Live connections — ${snapshot.liveConnections.length} active`;
      $('activity-title').textContent = `Recent activity — ${snapshot.counts.activityVisible} visible / ${snapshot.counts.activityTotal} total`;
      $('session-title').textContent = `Sessions — ${snapshot.sessions.active} active / ${snapshot.sessions.total} total (${snapshot.counts.sessionsVisible} visible)`;
      rows('users', snapshot.users, 'No users have been provisioned.');
      rows('vaults', snapshot.vaults, 'No vaults have been created.');
      rows('connections', snapshot.liveConnections, 'No active Sync connections.');
      rows('activity', snapshot.recentActivity, 'No revision activity recorded.');
      rows('sessions', snapshot.sessions.items, 'No sessions recorded.');
      definitionList('storage', snapshot.storage);
      definitionList('diagnostics', snapshot.diagnostics);
      if (wasHidden) $('dashboard-title').focus();
    } catch (error) {
      if (error.name === 'AbortError' || requestGeneration !== generation) return;
      const message = error instanceof Error ? error.message : 'Snapshot unavailable.';
      if ($('dashboard').hidden) $('login-error').textContent = message;
      else $('refreshed').textContent = message;
      if (manual && !$('dashboard').hidden) $('refresh').focus();
    } finally {
      if (requestGeneration === generation) { busy(false); pending = null; }
    }
  })();
  pending = { promise, controller };
  return promise;
}

$('login-form').addEventListener('submit', (event) => {
  event.preventDefault();
  sessionStorage.setItem('blackglass-admin-token', $('token').value);
  load(true);
});
$('refresh').onclick = () => load(true);
$('signout').onclick = () => forget();
if (token()) load();
setInterval(() => { if (token()) load(); }, 30000);
