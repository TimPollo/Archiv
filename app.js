/* PairVault · Statische App, ohne Server. Es werden nur verschlüsselte Inhalte gespeichert. */
'use strict';

const STORAGE_KEY = 'pairvault.v1.encrypted';
const ITERATIONS = 250000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const $ = (id) => document.getElementById(id);
const el = {
  welcomeView: $('welcomeView'), welcomeTitle: $('welcomeTitle'), welcomeDescription: $('welcomeDescription'),
  unlockForm: $('unlockForm'), masterPassword: $('masterPassword'), masterConfirm: $('masterConfirm'),
  confirmGroup: $('confirmGroup'), unlockSubmit: $('unlockSubmit'), welcomeMessage: $('welcomeMessage'),
  mainView: $('mainView'), lockButton: $('lockButton'),
  tabEntry: $('tabEntry'), tabArchive: $('tabArchive'), archiveTabCount: $('archiveTabCount'),
  entryView: $('entryView'), archiveView: $('archiveView'), entryTitle: $('entryTitle'),
  entryForm: $('entryForm'), nameInput: $('nameInput'), passwordInput: $('passwordInput'),
  showEntryPassword: $('showEntryPassword'), saveButton: $('saveButton'),
  cancelEdit: $('cancelEdit'), entryMessage: $('entryMessage'),
  archiveCount: $('archiveCount'), archiveList: $('archiveList'), searchInput: $('searchInput'),
  exportButton: $('exportButton'), importWelcome: $('importWelcome'), importArchive: $('importArchive'),
  backupInput: $('backupInput'), toast: $('toast')
};

let vault = { items: [] };
let vaultKey = null;
let saltBytes = null;
let vaultIterations = ITERATIONS;
let expandedId = null;
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
async function deriveKey(passphrase, salt, iterations = ITERATIONS) {
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
function readEncrypted() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); }
  catch { return { invalid: true }; }
}
function isValidArchive(payload) {
  if (!payload || payload.format !== 'pairvault-aes-gcm-v1' || payload.version !== 1 ||
    !Number.isInteger(payload.iterations) || payload.iterations < 200000 || payload.iterations > 600000 ||
    typeof payload.salt !== 'string' || typeof payload.iv !== 'string' || typeof payload.ciphertext !== 'string' ||
    payload.ciphertext.length > 12000000) return false;
  try {
    return base64ToBytes(payload.salt).length === 16 && base64ToBytes(payload.iv).length === 12 && base64ToBytes(payload.ciphertext).length >= 16;
  } catch { return false; }
}
function isValidVault(data) {
  return data && Array.isArray(data.items) && data.items.length <= 50000 && data.items.every((item) =>
    item && typeof item.id === 'string' && item.id.length <= 100 &&
    typeof item.name === 'string' && item.name.length <= 29 &&
    typeof item.password === 'string' && item.password.length <= 10000
  );
}
async function encryptAndStore(data) {
  if (!vaultKey || !saltBytes) throw new Error('Archiv ist gesperrt');
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vaultKey, encoder.encode(JSON.stringify(data)));
  const stored = {
    format: 'pairvault-aes-gcm-v1',
    version: 1,
    iterations: vaultIterations,
    salt: bytesToBase64(saltBytes),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(stored));
}
async function decryptArchive(payload, password) {
  if (!isValidArchive(payload)) throw new Error('Ungültige Archivdaten');
  const salt = base64ToBytes(payload.salt);
  const key = await deriveKey(password, salt, payload.iterations);
  const bytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(payload.iv) },
    key,
    base64ToBytes(payload.ciphertext)
  );
  const data = JSON.parse(decoder.decode(bytes));
  if (!isValidVault(data)) throw new Error('Archivinhalt ist ungültig');
  return { key, salt, data };
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
  el.unlockSubmit.disabled = busy;
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
function showLockScreen() {
  vaultKey = null;
  saltBytes = null;
  vaultIterations = ITERATIONS;
  vault = { items: [] };
  expandedId = null;
  editingId = null;
  visiblePasswords.clear();
  resetEntry();
  el.archiveList.replaceChildren();
  el.mainView.hidden = true;
  el.lockButton.hidden = true;
  el.welcomeView.hidden = false;
  el.unlockForm.reset();
  const exists = !!localStorage.getItem(STORAGE_KEY);
  el.welcomeTitle.textContent = exists ? 'Archiv entsperren' : 'Dein geschütztes Archiv';
  el.welcomeDescription.textContent = exists
    ? 'Gib dein Master-Passwort ein, um deine gespeicherten Einträge zu öffnen.'
    : 'Erstelle ein Master-Passwort. Deine Namen und Passwörter werden damit verschlüsselt.';
  el.confirmGroup.hidden = exists;
  el.masterConfirm.required = !exists;
  el.masterPassword.placeholder = exists ? 'Dein Master-Passwort' : 'Mindestens 10 Zeichen';
  el.unlockSubmit.textContent = exists ? 'Archiv entsperren' : 'Archiv erstellen';
  setMessage(el.welcomeMessage, '');
}
function showMain() {
  el.welcomeView.hidden = true;
  el.mainView.hidden = false;
  el.lockButton.hidden = false;
  el.searchInput.value = '';
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
    if (!expandedId && vault.items.length) expandedId = vault.items[0].id;
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

el.unlockForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (isSaving) return;
  if (!globalThis.crypto?.subtle) {
    setMessage(el.welcomeMessage, 'Verschlüsselung nicht verfügbar. Öffne die Website über HTTPS.', true);
    return;
  }
  const password = el.masterPassword.value;
  const payload = readEncrypted();
  if (!payload) {
    if (password.length < 10) { setMessage(el.welcomeMessage, 'Bitte mindestens 10 Zeichen verwenden.', true); return; }
    if (password !== el.masterConfirm.value) { setMessage(el.welcomeMessage, 'Die Passwörter stimmen nicht überein.', true); return; }
  }
  setBusy(true);
  try {
    if (payload) {
      const decrypted = await decryptArchive(payload, password);
      vaultKey = decrypted.key;
      saltBytes = decrypted.salt;
      vaultIterations = payload.iterations;
      vault = decrypted.data;
    } else {
      saltBytes = randomBytes(16);
      vaultKey = await deriveKey(password, saltBytes);
      vault = { items: [] };
      await encryptAndStore(vault);
    }
    showMain();
  } catch (error) {
    console.error('Unable to unlock or create vault:', error.name);
    vaultKey = null; saltBytes = null;
    setMessage(el.welcomeMessage, payload ? 'Master-Passwort falsch oder Archiv beschädigt.' : 'Archiv konnte nicht angelegt werden. Prüfe den Browserspeicher.', true);
  } finally { setBusy(false); el.masterPassword.value = ''; el.masterConfirm.value = ''; }
});

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
    expandedId = next[0]?.id || null;
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
el.lockButton.addEventListener('click', showLockScreen);
el.cancelEdit.addEventListener('click', resetEntry);
el.searchInput.addEventListener('input', renderArchive);
el.showEntryPassword.addEventListener('change', () => { el.passwordInput.type = el.showEntryPassword.checked ? 'text' : 'password'; });
document.querySelectorAll('.paste-button').forEach((button) => {
  button.addEventListener('click', () => pasteInto($(button.dataset.target)));
});

el.exportButton.addEventListener('click', () => {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw || !isValidArchive(readEncrypted())) { toast('Kein gültiges Archiv zum Exportieren'); return; }
  const blob = new Blob([raw], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `pairvault-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('Verschlüsseltes Backup gespeichert');
});
el.importWelcome.addEventListener('click', () => el.backupInput.click());
el.importArchive.addEventListener('click', () => el.backupInput.click());
el.backupInput.addEventListener('change', async () => {
  const file = el.backupInput.files?.[0];
  el.backupInput.value = '';
  if (!file) return;
  if (file.size > 12000000) { toast('Backup-Datei ist zu groß'); return; }
  try {
    const payload = JSON.parse(await file.text());
    if (!isValidArchive(payload)) throw new Error('Invalid backup');
    if (localStorage.getItem(STORAGE_KEY) && !confirm('Aktuelles Archiv durch dieses Backup ersetzen? Nicht gesicherte Einträge gehen verloren.')) return;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    showLockScreen();
    setMessage(el.welcomeMessage, 'Backup importiert. Bitte mit dem zugehörigen Master-Passwort entsperren.');
  } catch { toast('Ungültige oder nicht lesbare Backup-Datei'); }
});

window.addEventListener('storage', (event) => {
  if (event.key === STORAGE_KEY && vaultKey) {
    showLockScreen();
    setMessage(el.welcomeMessage, 'Archiv wurde in einem anderen Tab geändert. Bitte erneut entsperren.');
  }
});

showLockScreen();
