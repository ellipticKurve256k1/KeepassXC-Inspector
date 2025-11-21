const form = document.getElementById('unlock-form');
const kdbxInput = document.getElementById('kdbx-input');
const passwordInput = document.getElementById('password-input');
const keyFileInput = document.getElementById('keyfile-input');
const unlockButton = document.getElementById('unlock-button');
const clearButton = document.getElementById('clear-button');
const statusEl = document.getElementById('status');
const metaEl = document.getElementById('meta');
const entriesBody = document.getElementById('entries-body');
const entriesFootnote = document.getElementById('entries-footnote');
const merkleTreeEl = document.getElementById('merkle-tree');
const rootBanner = document.getElementById('root-banner');
const rootPrefixEl = document.getElementById('root-prefix');
const rootSuffixEl = document.getElementById('root-suffix');
const passwordVisibilityButton = document.getElementById('password-visibility');

const MAX_PREVIEW_ROWS = 25;
const textEncoder = new TextEncoder();

const STANDARD_FIELD_CANONICALS = new Set(['title', 'username', 'password', 'url', 'notes']);
const TOTP_HINTS = ['otp', 'totp', 'auth'];
const PASSKEY_HINTS = ['passkey', 'webauthn', 'fido', 'securitykey', 'security-key'];

let cachedKdbxweb = null;

function getKdbxweb() {
  if (cachedKdbxweb) {
    return cachedKdbxweb;
  }
  const lib = window.kdbxweb;
  if (!lib) {
    throw new Error(
      'kdbxweb is not available. Serve index.html via a dev server so the library can be loaded.'
    );
  }
  cachedKdbxweb = lib;
  return cachedKdbxweb;
}

const ensureArgon2 = (() => {
  let configured = false;
  return function ensure() {
    if (configured) {
      return;
    }
    if (!window.argon2) {
      throw new Error('Argon2 backend is not loaded.');
    }
    const { CryptoEngine } = getKdbxweb();
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
          .then((result) => {
            const hash = result.hash;
            return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength);
          });
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

    const { Kdbx, Credentials, ProtectedValue } = getKdbxweb();

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
    const merkleSnapshot = await processEntries(entries);
    renderRootHash(merkleSnapshot.root);
    renderEntryHashes(merkleSnapshot.leaves);
    renderMerkleTree(merkleSnapshot.levels);
    setStatus('Database unlocked successfully.', 'ok');
  } catch (error) {
    console.error(error);
    setStatus(error.message || 'Failed to unlock database.', 'error');
  } finally {
    unlockButton.disabled = false;
  }
});

clearButton.addEventListener('click', () => {
  form.reset();
  resetDisplay();
  setStatus('Inputs cleared. Ready for a new KeePass file.', 'info');
});

passwordVisibilityButton.addEventListener('click', () => {
  const isHidden = passwordInput.type === 'password';
  passwordInput.type = isHidden ? 'text' : 'password';
  passwordVisibilityButton.setAttribute('aria-pressed', String(isHidden));
  passwordVisibilityButton.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
  passwordVisibilityButton.classList.toggle('is-active', isHidden);
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
  merkleTreeEl.innerHTML = '';
  rootBanner.hidden = true;
  rootPrefixEl.textContent = '';
  rootSuffixEl.textContent = '';
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

function renderRootHash(root) {
  if (!root) {
    rootBanner.hidden = true;
    rootPrefixEl.textContent = '';
    rootSuffixEl.textContent = '';
    return;
  }
  rootBanner.hidden = false;
  rootPrefixEl.textContent = root.slice(0, 7);
  rootSuffixEl.textContent = root.slice(7);
}

function renderEntryHashes(leaves) {
  entriesBody.innerHTML = '';
  if (!leaves.length) {
    entriesFootnote.textContent = 'No entries could be hashed yet.';
    return;
  }
  const subset = leaves.slice(0, MAX_PREVIEW_ROWS);
  for (const leaf of subset) {
    const row = document.createElement('tr');
    row.appendChild(makeCell(leaf.title || 'Untitled entry'));
    row.appendChild(makeCell(leaf.hash));
    entriesBody.appendChild(row);
  }
  if (leaves.length > MAX_PREVIEW_ROWS) {
    entriesFootnote.textContent = `Showing the first ${MAX_PREVIEW_ROWS} hashed entries out of ${leaves.length}.`;
  } else {
    entriesFootnote.textContent = `Displayed ${leaves.length} hashed entr${
      leaves.length === 1 ? 'y' : 'ies'
    }.`;
  }
}

function renderMerkleTree(levels) {
  merkleTreeEl.innerHTML = '';
  if (!levels.length) {
    const empty = document.createElement('p');
    empty.textContent = 'No Merkle tree available.';
    merkleTreeEl.appendChild(empty);
    return;
  }
  levels.forEach((level, index) => {
    const container = document.createElement('div');
    container.className = 'merkle-level';
    const heading = document.createElement('h4');
    let label = 'Level';
    if (index === 0) {
      label = 'Leaves';
    } else if (index === levels.length - 1) {
      label = 'Root';
    } else {
      label = `Level ${index}`;
    }
    heading.textContent = `${label} (${level.length} node${level.length === 1 ? '' : 's'})`;
    container.appendChild(heading);

    const list = document.createElement('ul');
    list.className = 'merkle-nodes';
    level.forEach((node, nodeIndex) => {
      const item = document.createElement('li');
      item.className = 'merkle-node';
      if (node.isDuplicate) {
        item.classList.add('duplicate');
      }
      const titleSpan = document.createElement('span');
      titleSpan.className = 'node-title';
      titleSpan.textContent =
        node.title || (index === levels.length - 1 ? 'Root' : `Node ${nodeIndex + 1}`);
      const hashSpan = document.createElement('span');
      hashSpan.textContent = node.hash;
      item.appendChild(titleSpan);
      item.appendChild(hashSpan);
      list.appendChild(item);
    });
    container.appendChild(list);
    merkleTreeEl.appendChild(container);
  });
}

function makeCell(text) {
  const cell = document.createElement('td');
  cell.textContent = text || '—';
  return cell;
}

async function processEntries(entries) {
  if (!entries.length) {
    return { root: '', leaves: [], levels: [] };
  }
  const leafRecords = [];
  for (const entry of entries) {
    const normalized = normalizeEntry(entry);
    const canonical = canonicalizeNormalized(normalized);
    const canonicalJson = JSON.stringify(canonical.sortedObject);
    const hashInput = canonical.orderedValues.join('|');
    const [canonicalHash, merkleHash] = await Promise.all([
      sha256Hex(canonicalJson),
      sha256Hex(hashInput),
    ]);
    leafRecords.push({
      title: normalized.title || normalized.uuid || 'Untitled entry',
      canonicalHash,
      merkleHash,
    });
  }
  leafRecords.sort((a, b) => a.canonicalHash.localeCompare(b.canonicalHash));
  const leaves = leafRecords.map((record) => ({
    hash: record.merkleHash,
    title: record.title,
  }));
  const { root, levels } = await buildMerkleTree(leaves);
  return { root, leaves, levels };
}

function normalizeEntry(entry) {
  const normalized = {
    uuid: normalizeText(entry.uuid ? entry.uuid.toString() : ''),
    title: normalizeValue(entry.fields.get('Title')),
    username: normalizeValue(entry.fields.get('UserName')),
    password: normalizeValue(entry.fields.get('Password')),
    url: normalizeValue(entry.fields.get('URL')),
    notes: normalizeValue(entry.fields.get('Notes')),
    totp: '',
    passkey: '',
    lastModified: normalizeDate(entry.times ? entry.times.lastModTime : undefined),
  };
  const totpParts = [];
  const passkeyParts = [];

  entry.fields.forEach((value, key) => {
    const canonicalKey = canonicalizeFieldName(key);
    if (!canonicalKey) {
      return;
    }
    const normalizedValue = normalizeValue(value);
    if (!normalizedValue) {
      return;
    }
    if (!STANDARD_FIELD_CANONICALS.has(canonicalKey)) {
      normalized[`field:${canonicalKey}`] = normalizedValue;
    }
    const lowerKey = canonicalKey.toLowerCase();
    if (TOTP_HINTS.some((hint) => lowerKey.includes(hint))) {
      totpParts.push(`${canonicalKey}:${normalizedValue}`);
    }
    if (PASSKEY_HINTS.some((hint) => lowerKey.includes(hint))) {
      passkeyParts.push(`${canonicalKey}:${normalizedValue}`);
    }
  });

  if (entry.customData) {
    entry.customData.forEach((item, key) => {
      const canonicalKey = canonicalizeFieldName(key);
      if (!canonicalKey) {
        return;
      }
      const normalizedValue = normalizeText(item?.value || '');
      if (!normalizedValue) {
        return;
      }
      normalized[`customdata:${canonicalKey}`] = normalizedValue;
      if (TOTP_HINTS.some((hint) => canonicalKey.includes(hint))) {
        totpParts.push(`${canonicalKey}:${normalizedValue}`);
      }
      if (PASSKEY_HINTS.some((hint) => canonicalKey.includes(hint))) {
        passkeyParts.push(`${canonicalKey}:${normalizedValue}`);
      }
    });
  }

  normalized.totp = normalizeText(totpParts.join('|'));
  normalized.passkey = normalizeText(passkeyParts.join('|'));
  return normalized;
}

function canonicalizeNormalized(record) {
  const keys = Object.keys(record).sort();
  const sortedObject = {};
  const orderedValues = [];
  for (const key of keys) {
    const value = record[key] ?? '';
    sortedObject[key] = value;
    orderedValues.push(value);
  }
  return { sortedObject, orderedValues };
}

function normalizeValue(value) {
  if (value == null) {
    return '';
  }
  if (typeof value === 'string') {
    return normalizeText(value);
  }
  const { ProtectedValue } = getKdbxweb();
  if (value instanceof ProtectedValue) {
    return normalizeText(value.getText());
  }
  return normalizeText(String(value));
}

function normalizeText(value) {
  if (value == null) {
    return '';
  }
  return String(value).normalize('NFC').trim().replace(/\s+/g, ' ');
}

function normalizeDate(value) {
  if (!value) {
    return '';
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return '';
  }
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function canonicalizeFieldName(name) {
  if (!name) {
    return '';
  }
  return String(name)
    .normalize('NFC')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

async function buildMerkleTree(leaves) {
  if (!leaves.length) {
    return { root: '', levels: [] };
  }
  let currentLevel = leaves.map((leaf) => ({
    hash: leaf.hash,
    title: leaf.title,
    isDuplicate: false,
  }));
  const levels = [cloneLevel(currentLevel)];

  while (currentLevel.length > 1) {
    const padded = [...currentLevel];
    if (padded.length % 2 === 1) {
      const duplicateSource = padded[padded.length - 1];
      padded.push({
        hash: duplicateSource.hash,
        title: duplicateSource.title,
        isDuplicate: true,
      });
    }
    const nextLevel = [];
    for (let i = 0; i < padded.length; i += 2) {
      const left = padded[i];
      const right = padded[i + 1];
      const combined = concatBytes(hexToBytes(left.hash), hexToBytes(right.hash));
      const parentHash = await doubleSha256Hex(combined);
      nextLevel.push({ hash: parentHash, title: null, isDuplicate: false });
    }
    levels.push(cloneLevel(nextLevel));
    currentLevel = nextLevel;
  }
  return { root: currentLevel[0].hash, levels };
}

function cloneLevel(level) {
  return level.map((node) => ({
    hash: node.hash,
    title: node.title,
    isDuplicate: node.isDuplicate || false,
  }));
}

async function sha256Hex(data) {
  const digest = await sha256(data);
  return bytesToHex(new Uint8Array(digest));
}

async function sha256(data) {
  const bytes = toUint8Array(data);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const cryptoObj = window.crypto || window.msCrypto;
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('SubtleCrypto is unavailable in this environment.');
  }
  return cryptoObj.subtle.digest('SHA-256', buffer);
}

async function doubleSha256Hex(data) {
  const first = await sha256(data);
  const second = await sha256(new Uint8Array(first));
  return bytesToHex(new Uint8Array(second));
}

function toUint8Array(data) {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (typeof data === 'string') {
    return textEncoder.encode(data);
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError('Unsupported data type for hashing');
}

function hexToBytes(hex) {
  if (!hex) {
    return new Uint8Array();
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function concatBytes(a, b) {
  const output = new Uint8Array(a.length + b.length);
  output.set(a, 0);
  output.set(b, a.length);
  return output;
}
