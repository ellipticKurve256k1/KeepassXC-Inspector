# KeePass Decryptor

Load and decrypt KeePass `.kdbx` databases directly in the browser using `kdbxweb` plus an Argon2 hashing backend. Both password and key-file based databases are supported, and no data leaves the client.

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```
2. Serve the project root with any static file server so that the browser can read the local `node_modules` assets. For example:
   ```bash
   npx http-server . -c-1
   ```
   (You can substitute your preferred static server, such as VS Code Live Server or `python -m http.server`.)
3. Visit `http://localhost:8080` (or the port chosen by your server) and open `index.html`.

## Usage

1. Select the `.kdbx` database file.
2. Provide a KeePass password, a key file, or both.
3. Click **Open database**.

If the file uses Argon2 key derivation (KDBX4), the app automatically routes hashing requests through `argon2-browser` via `kdbxweb.CryptoEngine.setArgon2Impl`. Successfully decrypted databases show metadata plus a preview of the first few entries pulled from the default KeePass group.

> **Note:** This tool is for inspection and comparison experiments only. It never uploads your data, but you should still use it on trusted machines since decrypted content is rendered in the browser.
