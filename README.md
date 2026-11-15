# transcript-vault

Encrypts your idle Claude Code session transcripts on disk, decrypts one when you want to `/resume` it, and lets Claude search the encrypted history.

Claude Code saves every session as a plaintext `.jsonl` file under `~/.claude/projects/`. Those files hold everything that passed through the session: code, file contents, command output, and often API keys and passwords read from `.env` files or printed by tools. transcript-vault keeps them encrypted while you aren't using them.

## Install

At the prompt of a Claude Code terminal session:

```
/plugin install transcript-vault --marketplace mihirraj/transcript-vault-for-claude-code
```

Answer `y` to add the marketplace, then pick a scope (user scope protects every project). From a shell: `claude plugin install transcript-vault --marketplace mihirraj/transcript-vault-for-claude-code`.

Requires a Claude Code build with function-hook plugins (2.1.3xx or newer).

**Nothing is encrypted until you run `/vault setup`.**

## Commands

| Command | What it does |
| --- | --- |
| `/vault setup` | Creates your key and turns on automatic locking |
| `/vault status` | Key mode, locked or unlocked, counts of encrypted and plaintext sessions |
| `/vault lock` | Encrypts every session except the current one now (in passphrase mode it also clears the key from memory) |
| `/vault list [all]` | Lists encrypted sessions for this project (or every project) |
| `/vault open <n\|id>` | Decrypts one session and puts `/resume <id>` in your prompt |
| `/vault open all` | Decrypts everything and turns automatic locking off (do this before uninstalling) |
| `/vault unlock` | Enters your passphrase (passphrase mode) |
| `/vault passphrase` | Sets or changes the passphrase |

Claude also gets a tool, `search_vault`, so you can ask things like *"what did we decide about the cache in last week's session?"*. Search results are sent to the model like any other tool output.

## How it works

- **When things get locked:** at every session start, sessions untouched for `idleMinutes` (default 60) are encrypted. Sessions that ended cleanly are encrypted at the next start regardless of age. The session you're in stays plaintext until it ends, because Claude Code reads and writes it as you go.
- **Resuming:** Claude Code reads transcripts itself, and a plugin can't hook that read. So `/vault open` writes the plaintext back for Claude Code to load, and it's encrypted again once it's idle.
- **Crypto:** each install has an X25519 key pair. Each 2 MiB segment of a transcript is sealed to the public key: an ephemeral X25519 key, then HKDF-SHA256, then XChaCha20-Poly1305. The session id and segment index are bound in as associated data, so segments can't be swapped or reordered undetected. Sealing only needs the public key, which means idle sessions get locked even while a passphrase vault is locked. The code is [noble-ciphers, noble-curves and noble-hashes](https://paulmillr.com/noble/) (MIT, independently audited), bundled unmodified in `hooks/vendor/noble.mjs`.
- **The private key** is protected by one of two modes, set with the `keyMode` option:
  - `keystore` (default): Windows DPAPI (current user), the macOS login Keychain, or the Linux Secret Service (`secret-tool`). No prompts.
  - `passphrase`: scrypt (N=2^17, r=8, p=1) wraps the key. You run `/vault unlock` once per session to search or open. **If you lose the passphrase, the history can't be recovered.**
  - Changing modes moves the key the next time you unlock or set a passphrase. `/vault status` tells you if a move is pending.
- **Files:** `<project>/<session>.jsonl` becomes `<project>/<session>.vault/seg-000001.tv …`. Before the plaintext is deleted, each segment is written, read back and checked. If a file changes while it's being encrypted, it's left alone until next time.

## Options

Set these in `/config` or `pluginConfigs` in your settings:

| Option | Default | |
| --- | --- | --- |
| `keyMode` | `keystore` | `keystore` or `passphrase` |
| `maskSecrets` | `false` | Replace API keys, tokens, private keys and `password=…` values with `[REDACTED:kind]` as each row is saved. **The model sees the masked text too**, so tasks that need the real value can break. Secrets inside a tool call's input (such as a Bash command) can't be rewritten by plugins and are not masked. |
| `idleMinutes` | `60` | How long a session must sit untouched before it's encrypted |
| `projectsDir` | *(empty)* | Overrides the transcripts folder. Useful for trying it on a copy first. |

## What this protects against, and what it doesn't

**Protects:** transcripts readable from a lost or stolen disk without full-disk encryption, backups and cloud-synced folders (OneDrive, iCloud, Dropbox) that pick up `~/.claude`, other user accounts on the same machine, and casual reads by tools and scripts that scan your home folder.

**Doesn't protect:**
- **Malware running as your user.** In keystore mode it can ask the OS keystore for the key just like the plugin does. Passphrase mode helps only while the vault is locked.
- **The session you're in, and any session you've opened.** Both are plaintext until they're encrypted again.
- **Deleted plaintext may still be on disk.** It's removed normally, not securely wiped, and on SSDs the old blocks can survive. Turn on full-disk encryption (BitLocker or Device Encryption, FileVault, LUKS) as well.
- **Other plaintext Claude Code keeps:** prompt history (`~/.claude/history.jsonl`), subagent transcripts and tool-result files inside session folders, file-edit snapshots (`~/.claude/file-history`), and todos. Out of scope for v0.1.
- **Anything already sent to the model provider.** This is about local files only.

## Limitations

- Function-hook plugins are an early-access API in Claude Code, so a future release could change it.
- Passphrase entry uses a pane whose field shows dots. Typing and backspace work; moving the cursor to edit in the middle doesn't.
- `/vault open <id>` only puts `/resume` in your prompt when the session belongs to the current project. For other projects, start Claude Code in that folder.
- Claude Code's own transcript cleanup (`cleanupPeriodDays`) doesn't know about `.vault` folders. Delete old ones by hand if you want them gone.

## Uninstall

Run `/vault open all` first, or your history stays encrypted. Then `/plugin uninstall transcript-vault`. In keystore mode on macOS or Linux, the key stays in your Keychain or Secret Service under the name `transcript-vault`, and you can delete it there.

## Development

```
claude plugin validate .
claude plugin test .                                   # hook logic (no file system)
node test/core.integration.mjs <dir-with-projects-copy> # crypto + files + OS keystore, on a COPY
```

The integration test encrypts and deletes files in the folder you give it. Point it at a copy of `~/.claude/projects` placed at `<dir>/projects`, never at the real one.

## License

MIT. Bundled noble libraries: MIT, © Paul Miller.
