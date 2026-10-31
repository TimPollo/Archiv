/* PairVault v3: ohne Entsperr- oder Backup-Passwort. Geräteschlüssel bleibt automatisch im Browser. */
'use strict';

const LEGACY_STORAGE_KEY = 'pairvault.v1.encrypted';
const STORAGE_KEY = 'pairvault.v2.device-encrypted';
const DB_NAME = 'pairvault-device-key-v2';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (id) => document.getElementById(id);
const el = {
  appNotice: $('appNotice'), mainView: $('mainView'),
  tabEntry: $('tabEntry'), tabArchive: $('tabArchive'), archiveTabCount: $('archiveTabCount'),
  entryView: $('entryView'), archiveView: $('archiveView'), entryTitle: $('entryTitle'),
  entryForm: $('entryForm'), nameInput: $('nameInput'), passwordInput: $('passwordInput'),
  showEntryPassword: $('showEntryPassword'), saveButton: $('saveButton'),
  cancelEdit: $('cancelEdit'), entryMessage: $('entryMessage'),
  archiveCount: $('archiveCount'), archiveList: $('archiveList'), searchInput: $('searchInput'), searchSuggestions: $('searchSuggestions'),
  exportButton: $('exportButton'), importArchive: $('importArchive'), backupInput: $('backupInput'), toast: $('toast')
};

let vault = { items: [] };
let vaultKey = null;
let expandedId = null;
let activeSuggestion = -1;
let editingId = null;
let isSaving = false;
let toastTimer = null;
const visiblePasswords = new Set();

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}
function base64ToBytes(base64) {
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
function randomBytes(count) {
  return crypto.getRandomValues(new Uint8Array(count));
}
function isValidVault(data) {
  return data && Array.isArray(data.items) && data.items.length <= 50000 && data.items.every((item) =>
    item && typeof item.id === 'string' && item.id.length <= 100 &&
    typeof item.name === 'string' && item.name.length <= 29 &&
    typeof item.password === 'string' && item.password.length <= 10000
  );
}
// Geräteschlüssel: nicht exportierbar und persistent in IndexedDB. Keine Anmeldung beim ersten Start.
function openKeyDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('Schlüsseldatenbank blockiert'));
  });
}
async function loadDeviceKey() {
  const db = await openKeyDatabase();
  try {
    const existing = await new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readonly');
      const req = tx.objectStore('keys').get('primary');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    if (existing) return existing;
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    await new Promise((resolve, reject) => {
      const tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').put(key, 'primary');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('Schlüssel konnte nicht gespeichert werden'));
    });
    return key;
  } finally { db.close(); }
}
async function encryptAndStore(data) {
  if (!vaultKey) throw new Error('Geräteschlüssel nicht verfügbar');
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, encoder.encode(JSON.stringify(data)));
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    format: 'pairvault-device-aes-gcm-v2', version: 2,
    iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  }));
}
async function decryptDeviceArchive(raw) {
  const payload = JSON.parse(raw);
  if (payload?.format !== 'pairvault-device-aes-gcm-v2' || payload.version !== 2 ||
      typeof payload.iv !== 'string' || typeof payload.ciphertext !== 'string' ||
      payload.ciphertext.length > 12000000 || base64ToBytes(payload.iv).length !== 12) {
    throw new Error('Ungültiges Gerätearchiv');
  }
  const bytes = await crypto.subtle.decrypt({ name:'AES-GCM', iv:base64ToBytes(payload.iv) }, vaultKey, base64ToBytes(payload.ciphertext));
  const result = JSON.parse(decoder.decode(bytes));
  if (!isValidVault(result)) throw new Error('Archivdaten beschädigt');
  return result;
}
function setMessage(node, text, isError = false) {
  node.textContent = text;
  node.classList.toggle('error', !!isError);
}
function toast(text) {
  clearTimeout(toastTimer);
  el.toast.textContent = text;
  el.toast.hidden = false;
  toastTimer = setTimeout(() => { el.toast.hidden = true; }, 2200);
}
function setBusy(busy) {
  isSaving = busy;
  el.saveButton.disabled = busy;
}
function resetEntry() {
  editingId = null;
  el.entryForm.reset();
  el.passwordInput.type = 'password';
  el.entryTitle.textContent = 'Zugangsdaten speichern';
  el.saveButton.textContent = 'Im Archiv speichern';
  el.cancelEdit.hidden = true;
  setMessage(el.entryMessage, '');
}
function showNotice(message, danger = false) {
  el.appNotice.hidden = !message;
  el.appNotice.textContent = message;
  el.appNotice.classList.toggle('danger', danger);
}
async function startApp() {
  el.saveButton.disabled = true;
  try {
    if (!globalThis.crypto?.subtle || !globalThis.indexedDB)
      throw new Error('Browser-Speicherung nicht verfügbar. Bitte die HTTPS-Adresse über GitHub Pages verwenden.');
    vaultKey = await loadDeviceKey();
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      vault = await decryptDeviceArchive(stored);
    } else {
      vault = {items: []};
      await encryptAndStore(vault);
    }
    el.saveButton.disabled = false;
    showMain();
    if (localStorage.getItem(LEGACY_STORAGE_KEY) && vault.items.length === 0) {
      showNotice('Hinweis: Ein altes, mit Passwort geschütztes Archiv ist noch im Browser gespeichert. Es bleibt unverändert, kann aber ohne das damalige Passwort nicht automatisch übernommen werden. Neue Einträge werden hier separat gespeichert.');
    }
  } catch (error) {
    console.error('Archiv konnte nicht geladen werden:', error);
    showNotice('Das gespeicherte Archiv kann auf diesem Gerät nicht gelesen werden. Die bestehenden Daten wurden nicht gelöscht. ' + (error?.message || ''), true);
    el.saveButton.disabled = true; // Auf keinen Fall die verschlüsselten alten Daten überschreiben.
  }
}
function showMain() {
  el.mainView.hidden = false;
  el.searchInput.value = '';
  expandedId = null;
  resetEntry();
  updateCounts();
  switchTab('entry');
}
function updateCounts() {
  const count = vault.items.length;
  el.archiveTabCount.textContent = String(count);
  el.archiveCount.textContent = `${count} ${count === 1 ? 'Name' : 'Namen'}`;
}
function switchTab(name) {
  const archive = name === 'archive';
  el.tabEntry.classList.toggle('active', !archive);
  el.tabArchive.classList.toggle('active', archive);
  el.tabEntry.setAttribute('aria-selected', String(!archive));
  el.tabArchive.setAttribute('aria-selected', String(archive));
  el.entryView.hidden = archive;
  el.archiveView.hidden = !archive;
  if (archive) {
    el.searchInput.value = '';
    el.archiveList.scrollTop = 0;
    expandedId = null;
    visiblePasswords.clear();
    closeSuggestions();
    renderArchive();
  } else {
    visiblePasswords.clear();
  }
}
function textElement(tag, className, value) {
  const node = document.createElement(tag);
  node.className = className;
  node.textContent = value;
  return node;
}
function iconSvg(kind) {
  if (kind === 'folder') {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H10l2.2 2H19a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5.5A2.5 2.5 0 0 1 3 17.5z"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
}
function closeSuggestions() {
  el.searchSuggestions.hidden = true;
  el.searchSuggestions.replaceChildren();
  activeSuggestion = -1;
  el.searchInput.removeAttribute('aria-activedescendant');
}
function showSuggestions() {
  const term = el.searchInput.value.trim().toLocaleLowerCase('de');
  closeSuggestions();
  if (!term || el.archiveView.hidden) return;
  const matching = vault.items.filter((item) => item.name.toLocaleLowerCase('de').includes(term)).slice(0, 6);
  if (!matching.length) return;
  matching.forEach((item, index) => {
    const button = textElement('button', 'search-option', item.name);
    button.id = `suggestion-${index}`;
    button.type = 'button';
    button.setAttribute('role', 'option');
    button.setAttribute('aria-selected', 'false');
    button.addEventListener('click', () => chooseSuggestion(item));
    el.searchSuggestions.appendChild(button);
  });
  el.searchSuggestions.hidden = false;
}
function chooseSuggestion(item) {
  el.searchInput.value = item.name;
  el.searchInput.blur();
  expandedId = item.id;
  closeSuggestions();
  renderArchive();
  el.archiveList.scrollTop = 0;
}
function renderArchive() {
  const term = el.searchInput.value.trim().toLocaleLowerCase('de');
  const entries = vault.items.filter((item) => item.name.toLocaleLowerCase('de').includes(term));
  el.archiveList.replaceChildren();
  if (!entries.length) {
    const empty = textElement('div', 'empty-archive', vault.items.length ? 'Kein passender Name gefunden.' : 'Noch keine Einträge gespeichert.');
    if (!vault.items.length) empty.innerHTML = `${iconSvg('folder')}<span>Noch keine Einträge gespeichert.</span>`;
    el.archiveList.appendChild(empty);
    return;
  }
  entries.forEach((item) => {
    const open = item.id === expandedId;
    const folder = document.createElement('article');
    folder.className = `folder${open ? ' open' : ''}`;
    const head = document.createElement('button');
    head.type = 'button';
    head.className = 'folder-head';
    head.setAttribute('aria-expanded', String(open));
    const icon = document.createElement('span');
    icon.className = 'folder-icon';
    icon.innerHTML = iconSvg('folder');
    const name = textElement('span', 'folder-name', item.name);
    name.title = item.name;
    const chevron = document.createElement('span');
    chevron.className = 'folder-chevron';
    chevron.innerHTML = iconSvg('chevron');
    head.append(icon, name, chevron);
    head.addEventListener('click', () => { expandedId = open ? null : item.id; renderArchive(); });
    folder.appendChild(head);
    if (open) {
      const details = document.createElement('div');
      details.className = 'folder-details';
      details.appendChild(textElement('div', 'detail-label', 'BENUTZERNAME'));
      details.appendChild(createCredentialRow(item.name, false, item.id));
      details.appendChild(textElement('div', 'detail-label', 'PASSWORT'));
      details.appendChild(createCredentialRow(item.password, true, item.id));
      const actions = document.createElement('div');
      actions.className = 'detail-actions';
      const revealButton = textElement('button', 'small-link', visiblePasswords.has(item.id) ? 'Verbergen' : 'Passwort anzeigen');
      revealButton.type = 'button';
      revealButton.addEventListener('click', () => {
        if (visiblePasswords.has(item.id)) visiblePasswords.delete(item.id);
        else visiblePasswords.add(item.id);
        renderArchive();
      });
      const editButton = textElement('button', 'small-link', 'Bearbeiten');
      editButton.type = 'button';
      editButton.addEventListener('click', () => {
        editingId = item.id;
        el.nameInput.value = item.name;
        el.passwordInput.value = item.password;
        el.showEntryPassword.checked = false;
        el.passwordInput.type = 'password';
        el.entryTitle.textContent = 'Eintrag bearbeiten';
        el.saveButton.textContent = 'Änderungen speichern';
        el.cancelEdit.hidden = false;
        switchTab('entry');
      });
      const deleteButton = textElement('button', 'small-link danger', 'Löschen');
      deleteButton.type = 'button';
      deleteButton.addEventListener('click', async () => {
        if (!confirm(`„${item.name}“ mitsamt Passwort dauerhaft löschen?`)) return;
        const oldItems = vault.items;
        vault.items = vault.items.filter((record) => record.id !== item.id);
        try { await encryptAndStore(vault); }
        catch { vault.items = oldItems; toast('Löschen fehlgeschlagen'); return; }
        expandedId = null;
        updateCounts(); renderArchive(); toast('Eintrag gelöscht');
      });
      actions.append(revealButton, editButton, deleteButton);
      details.appendChild(actions);
      folder.appendChild(details);
    }
    el.archiveList.appendChild(folder);
  });
}
function createCredentialRow(value, isPassword, id) {
  const row = document.createElement('div');
  row.className = 'credential-row';
  const show = !isPassword || visiblePasswords.has(id);
  const displayValue = textElement('div', 'credential-value' + (!show ? ' masked' : ''), show ? value : '••••••••••');
  displayValue.title = show ? value : 'Passwort verborgen';
  const copyButton = textElement('button', 'copy-button', 'Kopieren');
  copyButton.type = 'button';
  copyButton.setAttribute('aria-label', isPassword ? 'Passwort kopieren' : 'Benutzername kopieren');
  copyButton.addEventListener('click', async () => {
    try {
      await copyText(value);
      toast(isPassword ? 'Passwort kopiert' : 'Benutzername kopiert');
      copyButton.textContent = 'Kopiert ✓';
      setTimeout(() => { if (copyButton.isConnected) copyButton.textContent = 'Kopieren'; }, 1400);
    } catch { toast('Kopieren nicht möglich'); }
  });
  row.append(displayValue, copyButton);
  return row;
}
async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(text); return; }
    catch { /* older Safari fallback */ }
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.cssText = 'position:fixed;left:-9999px;top:0';
  document.body.append(textarea);
  textarea.focus(); textarea.select();
  const succeeded = document.execCommand('copy');
  textarea.remove();
  if (!succeeded) throw Error('Zugriff auf Zwischenablage verweigert');
}
async function pasteInto(input) {
  if (navigator.clipboard?.readText) {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        input.value = input === el.passwordInput ? text : text.trim();
        toast(input === el.nameInput ? 'Name eingesetzt' : 'Passwort eingesetzt');
        return;
      }
    } catch { /* Safari kann manuelles Einsetzen verlangen */ }
  }
  input.focus();
  setMessage(el.entryMessage, 'Im Eingabefeld lange drücken und „Einsetzen“ auswählen.');
  toast('Lange drücken → Einsetzen');
}
function normalizeName(name) { return name.trim().replace(/\s+/g, ' ').toLocaleLowerCase('de'); }

el.entryForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (isSaving || !vaultKey) return;
  const name = el.nameInput.value.trim();
  const password = el.passwordInput.value;
  if (!name || !password) { setMessage(el.entryMessage, 'Bitte beide Felder ausfüllen.', true); return; }
  if (name.length > 29 || password.length > 10000) { setMessage(el.entryMessage, 'Eintrag ist zu lang.', true); return; }
  const duplicate = vault.items.find((item) => item.id !== editingId && normalizeName(item.name) === normalizeName(name));
  if (duplicate) { setMessage(el.entryMessage, 'Dieser Name existiert bereits. Öffne ihn im Archiv zum Bearbeiten.', true); return; }
  const oldItems = vault.items;
  const stamp = new Date().toISOString();
  const next = [...oldItems];
  if (editingId) {
    const index = next.findIndex((item) => item.id === editingId);
    if (index === -1) { setMessage(el.entryMessage, 'Dieser Eintrag wurde nicht mehr gefunden.', true); return; }
    next[index] = { ...next[index], name, password, updatedAt: stamp };
  } else {
    next.unshift({ id: crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`, name, password, createdAt: stamp, updatedAt: stamp });
  }
  setBusy(true);
  try {
    await encryptAndStore({ items: next });
    vault.items = next;
    expandedId = null;
    const wasEditing = !!editingId;
    resetEntry();
    updateCounts();
    setMessage(el.entryMessage, wasEditing ? 'Änderungen gespeichert. Felder sind wieder leer.' : 'Gespeichert! Bereit für das nächste Paar.');
    toast(wasEditing ? 'Eintrag aktualisiert' : 'Im Archiv gespeichert');
  } catch (error) {
    console.error('Saving encrypted vault failed:', error.name);
    setMessage(el.entryMessage, 'Speichern fehlgeschlagen. Daten wurden nicht übernommen.', true);
  } finally { setBusy(false); }
});

el.tabEntry.addEventListener('click', () => switchTab('entry'));
el.tabArchive.addEventListener('click', () => switchTab('archive'));
el.cancelEdit.addEventListener('click', resetEntry);
el.searchInput.addEventListener('input', () => { expandedId = null; renderArchive(); showSuggestions(); });
el.searchInput.addEventListener('focus', showSuggestions);
el.searchInput.addEventListener('keydown', (event) => {
  const buttons = Array.from(el.searchSuggestions.querySelectorAll('.search-option'));
  if (event.key === 'Escape') { closeSuggestions(); return; }
  if (!buttons.length) return;
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    activeSuggestion = (activeSuggestion + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
    buttons.forEach((button, i) => button.setAttribute('aria-selected', String(i === activeSuggestion)));
    el.searchInput.setAttribute('aria-activedescendant', buttons[activeSuggestion].id);
  }
  if (event.key === 'Enter') {
    event.preventDefault();
    const index = Math.max(activeSuggestion, 0);
    const item = vault.items.find((v) => v.name === buttons[index]?.textContent);
    if (item) chooseSuggestion(item);
  }
});
document.addEventListener('pointerdown', (event) => {
  if (!event.target.closest('.search-wrap')) closeSuggestions();
});
// Verhindert iOS-Gestenzoom zusätzlich zur festen Viewport-Konfiguration.
document.addEventListener('gesturestart', (event) => event.preventDefault(), { passive: false });
document.addEventListener('gesturechange', (event) => event.preventDefault(), { passive: false });
el.showEntryPassword.addEventListener('change', () => { el.passwordInput.type = el.showEntryPassword.checked ? 'text' : 'password'; });
document.querySelectorAll('.paste-button').forEach((button) => {
  button.addEventListener('click', () => pasteInto($(button.dataset.target)));
});

// Portable Sicherung ohne Passwort: lesbares JSON. Vertraulich aufbewahren!
function makePortableBackup() {
  return {
    format: 'pairvault-plain-json-v3',
    version: 3,
    exportedAt: new Date().toISOString(),
    items: vault.items.map((item) => ({...item}))
  };
}
function downloadJson(object, filename) {
  const blob = new Blob([JSON.stringify(object, null, 2)], {type: 'application/json'});
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
el.exportButton.addEventListener('click', () => {
  if (!vaultKey) return;
  if (!confirm('Diese Backup-Datei enthält Namen und Passwörter UNVERSCHLÜSSELT. Nur an einem privaten, geschützten Ort speichern. Jetzt herunterladen?')) return;
  downloadJson(makePortableBackup(), `pairvault-backup-${new Date().toISOString().slice(0,10)}.json`);
  toast('Backup ohne Passwort erstellt');
});
el.importArchive.addEventListener('click', () => el.backupInput.click());
el.backupInput.addEventListener('change', async () => {
  const file = el.backupInput.files?.[0];
  el.backupInput.value = '';
  if (!file) return;
  if (file.size > 12000000) { toast('Backup-Datei ist zu groß'); return; }
  let data;
  try {
    data = JSON.parse(await file.text());
  } catch {
    toast('Backup-Datei nicht lesbar'); return;
  }
  if (data?.format !== 'pairvault-plain-json-v3' || data?.version !== 3 || !isValidVault(data)) {
    toast('Kein gültiges PairVault-3-Backup');
    return;
  }
  if (!vaultKey) { toast('Archiv aktuell nicht verfügbar'); return; }
  if (vault.items.length && !confirm('Aktuelles Archiv durch die Sicherung ERSETZEN? Nicht gesicherte Einträge können verloren gehen.')) return;
  const imported = {items: data.items.map((item) => ({...item}))};
  try {
    await encryptAndStore(imported);
    vault = imported;
    showMain();
    toast('Backup importiert');
  } catch {
    toast('Backup konnte nicht gespeichert werden');
  }
});
window.addEventListener('storage', (event) => {
  if (event.key === STORAGE_KEY && vaultKey) startApp();
});

startApp();
