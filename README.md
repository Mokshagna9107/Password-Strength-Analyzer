# Password Strength Analyzer

A dependency-free browser tool that evaluates user-entered passwords for length, complexity, uniqueness, and local reuse.

## Features

- Scores passwords from 0 to 100 with clear strength labels.
- Checks length, character variety, common passwords, sequences, repeated patterns, and local reuse.
- Generates stronger passphrase-style alternatives.
- Stores previous password fingerprints as salted SHA-256 hashes in `localStorage`.
- Runs entirely in the browser. The entered password is not sent to a server.

## Run

Start a local server from this folder:

```bash
npm start
```

Then open:

```text
http://127.0.0.1:4173/index.html
```

Do not open `index.html` by double-clicking it. Modern browsers often block JavaScript modules loaded from `file://`, so the page may appear without the analyzer behavior.

## Test

```bash
npm test
```

## Security Notes

This is an educational analyzer, not a replacement for a full password manager or breach-checking service. The local reuse memory is intentionally simple: each saved password is hashed with a random salt, and future entries are compared by hashing the current password with each stored salt.
