const { Kdbx, Credentials, ProtectedValue, CryptoEngine } = window.kdbxweb || {};

const form = document.getElementById('unlock-form');
const kdbxInput = document.getElementById('kdbx-input');
const passwordInput = document.getElementById('password-input');
const keyFileInput = document.getElementById('keyfile-input');
const unlockButton = document.getElementById('unlock-button');
const statusEl = document.getElementById('status');
const metaEl = document.getElementById('meta');
const entriesBody = document.getElementById('entries-body');
const entriesFootnote = document.getElementById('entries-footnote');

const MAX_PREVIEW_ROWS = 25;

const ensureArgon2 = (() => {
  let configured = false;
  return function ensure() {
    if (configured) {
      return;
    }
    if (!window.argon2) {
      throw new Error('Argon2 backend is not loaded.');
    }
    CryptoEngine.setArgon2Impl(
      (password, salt, memory, iterations, length, parallelism, type, version) => {
        const passBytes = new Uint8Array(password);
        const saltBytes = new Uint8Array(salt);
        const normalizedMem = Math.max(1, Math.floor(memory));
        const normalizedParallelism = Math.max(1, Math.floor(parallelism));
        const argonType =
          type === CryptoEngine.Argon2TypeArgon2d
            ? window.argon2.ArgonType.Argon2d
            : window.argon2.ArgonType.Argon2id;
        return window.argon2
          .hash({
            pass: passBytes,
            salt: saltBytes,
            time: iterations,
            mem: normalizedMem,
            hashLen: length,
            parallelism: normalizedParallelism,
            type: argonType,
            version,
          })
          .then((result) => result.hash.buffer);
      }
    );
    configured = true;
  };
})();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  resetDisplay();
  setStatus('Unlocking database…', 'info');
  unlockButton.disabled = true;
  try {
    ensureArgon2();
    const dbFile = kdbxInput.files[0];
    if (!dbFile) {
      throw new Error('Select a KeePass database file.');
    }

    const password = passwordInput.value.trim();
    const keyFile = keyFileInput.files[0];

    if (!password && !keyFile) {
      throw new Error('Provide a password, a key file, or both.');
    }

    const [dbBytes, keyBytes] = await Promise.all([
      readFileAsArrayBuffer(dbFile),
      keyFile ? readFileAsArrayBuffer(keyFile) : Promise.resolve(null),
    ]);

    const protectedPassword = password ? ProtectedValue.fromString(password) : null;
    const credentials = new Credentials(protectedPassword, keyBytes);
    await credentials.ready;

    const db = await Kdbx.load(dbBytes, credentials);
    const defaultGroup = db.getDefaultGroup();
    const entries = defaultGroup ? Array.from(defaultGroup.allEntries()) : [];
    renderMeta(db, entries.length);
    renderEntries(entries);
    setStatus('Database unlocked successfully.', 'ok');
  } catch (error) {
    console.error(error);
    setStatus(error.message || 'Failed to unlock database.', 'error');
  } finally {
    unlockButton.disabled = false;
  }
});

function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error || new Error('Failed to read file.'));
    reader.onload = () => resolve(reader.result);
    reader.readAsArrayBuffer(file);
  });
}

function resetDisplay() {
  metaEl.innerHTML = '';
  entriesBody.innerHTML = '';
  entriesFootnote.textContent = '';
  statusEl.classList.remove('error', 'ok');
}

function setStatus(message, kind) {
  statusEl.textContent = message;
  statusEl.classList.remove('error', 'ok');
  if (kind === 'error') {
    statusEl.classList.add('error');
  } else if (kind === 'ok') {
    statusEl.classList.add('ok');
  }
}

function renderMeta(db, entryCount) {
  const header = db.header;
  const meta = db.meta;
  const items = [
    ['Database name', meta.name || '—'],
    ['Description', meta.desc || '—'],
    ['Default user', meta.defaultUser || '—'],
    [
      'Format',
      header ? `KDBX ${header.versionMajor}.${header.versionMinor}` : 'Unknown',
    ],
    ['Entries in default group', String(entryCount)],
  ];
  const fragment = document.createDocumentFragment();
  for (const [label, value] of items) {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    fragment.appendChild(dt);
    fragment.appendChild(dd);
  }
  metaEl.appendChild(fragment);
}

function renderEntries(entries) {
  if (!entries.length) {
    entriesFootnote.textContent =
      'No entries were found in the default group (navigate groups manually in a full app).';
    return;
  }
  const sample = entries.slice(0, MAX_PREVIEW_ROWS);
  for (const entry of sample) {
    const row = document.createElement('tr');
    row.appendChild(makeCell(readField(entry, 'Title')));
    row.appendChild(makeCell(readField(entry, 'UserName')));
    row.appendChild(makeCell(readField(entry, 'URL')));
    row.appendChild(makeCell(truncate(readField(entry, 'Notes'), 140)));
    entriesBody.appendChild(row);
  }
  if (entries.length > MAX_PREVIEW_ROWS) {
    entriesFootnote.textContent = `Showing the first ${MAX_PREVIEW_ROWS} entries out of ${entries.length}.`;
  } else {
    entriesFootnote.textContent = `Displayed ${entries.length} entr${entries.length === 1 ? 'y' : 'ies'}.`;
  }
}

function readField(entry, name) {
  const value = entry.fields.get(name);
  if (!value) {
    return '—';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (value instanceof ProtectedValue) {
    return value.getText();
  }
  return '—';
}

function makeCell(text) {
  const cell = document.createElement('td');
  cell.textContent = text || '—';
  return cell;
}

function truncate(value, maxLength) {
  if (!value) {
    return '—';
  }
  if (value.length <= maxLength) {
    return value;
  }
  return value.slice(0, maxLength - 1) + '…';
}
