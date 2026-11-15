// transcript-vault core: encryption, key protection, vault files, search, masking.
//
// Everything that touches the outside world goes through `io`, so this module
// runs the same inside a Claude Code hooks module (io built from `$`) and under
// Node for testing (io built from node:fs / child_process).
//
// io = {
//   platform: 'windows' | 'mac' | 'linux',
//   user: string,
//   readBytes(path) -> Promise<Uint8Array>      (files up to ~4 MiB)
//   readText(path)  -> Promise<string>
//   write(path, text) -> Promise<void>           (creates parent dirs)
//   list(dir) -> Promise<{ name, kind, size, mtimeMs }[]>
//   stat(path) -> Promise<{ kind, size, mtimeMs }>
//   exists(path) -> Promise<boolean>
//   run(argv, { env?, stdin?, timeoutMs? }) -> Promise<{ exitCode, stdout, stderr }>
// }

import { xchacha20poly1305, x25519, hkdf, sha256, scryptAsync, randomBytes } from './vendor/noble.mjs'

export const FORMAT = 'transcript-vault/v1'
export const SEG_BYTES = 2 * 1024 * 1024 // plaintext per segment; ~2.7 MiB once base64'd
const DIRECT_READ_MAX = 3 * 1024 * 1024 // above this, read through the host in slices
const SCRYPT = { N: 2 ** 17, r: 8, p: 1 }
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
export const SESSION_FILE = new RegExp(`^(${UUID})\\.jsonl$`)
export const VAULT_DIR = new RegExp(`^(${UUID})\\.vault$`)
const SEG_FILE = /^seg-(\d{6})\.tv$/
const OPENING = 'OPENING'

const utf8 = new TextEncoder()
const fromUtf8 = new TextDecoder('utf-8')

// ---------- bytes ----------

export function b64(bytes) {
  if (typeof bytes.toBase64 === 'function') return bytes.toBase64()
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000))
  return btoa(s)
}

export function unb64(text) {
  const clean = text.replace(/\s+/g, '')
  if (typeof Uint8Array.fromBase64 === 'function') return Uint8Array.fromBase64(clean)
  const s = atob(clean)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

export function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const p of parts) { out.set(p, at); at += p.length }
  return out
}

const join = (...parts) => parts.join('/').replace(/\\/g, '/').replace(/\/+/g, '/')

// ---------- crypto ----------
// Each install has one X25519 key pair. Sealing needs only the public key, so
// idle sessions are locked even while a passphrase-protected vault is locked.
// Each segment: ephemeral X25519 -> HKDF-SHA256 -> XChaCha20-Poly1305, with the
// session id and segment index bound in as associated data (no reordering or
// swapping segments between sessions).

export function newKeypair() {
  const sk = randomBytes(32)
  return { sk, pk: x25519.getPublicKey(sk) }
}

export function newKeypairFrom(sk) {
  return { sk, pk: x25519.getPublicKey(sk) }
}

function segmentKey(shared, epk, pk) {
  return hkdf(sha256, shared, concat([epk, pk]), utf8.encode(`${FORMAT} segment`), 32)
}

const segAad = (sid, index) => utf8.encode(`${FORMAT}|${sid}|${index}`)

export function sealSegment(pk, plaintext, sid, index) {
  const esk = randomBytes(32)
  const epk = x25519.getPublicKey(esk)
  const key = segmentKey(x25519.getSharedSecret(esk, pk), epk, pk)
  const n = randomBytes(24)
  const c = xchacha20poly1305(key, n, segAad(sid, index)).encrypt(plaintext)
  return { f: FORMAT, sid, i: index, epk: b64(epk), n: b64(n), c: b64(c) }
}

export function openSegment(sk, seg, sid, index) {
  if (seg.f !== FORMAT || seg.sid !== sid || seg.i !== index) throw new Error(`segment ${index} of ${sid} is not what its name says`)
  const pk = x25519.getPublicKey(sk)
  const epk = unb64(seg.epk)
  const key = segmentKey(x25519.getSharedSecret(sk, epk), epk, pk)
  return xchacha20poly1305(key, unb64(seg.n), segAad(sid, index)).decrypt(unb64(seg.c))
}

const KEY_AAD = utf8.encode(`${FORMAT} private key`)

export async function wrapWithPassphrase(sk, passphrase) {
  const salt = randomBytes(16)
  const kek = await scryptAsync(utf8.encode(passphrase.normalize('NFC')), salt, { ...SCRYPT, dkLen: 32 })
  const n = randomBytes(24)
  const c = xchacha20poly1305(kek, n, KEY_AAD).encrypt(sk)
  return { kdf: 'scrypt', ...SCRYPT, salt: b64(salt), n: b64(n), c: b64(c) }
}

export async function unwrapWithPassphrase(wrap, passphrase) {
  const kek = await scryptAsync(utf8.encode(passphrase.normalize('NFC')), unb64(wrap.salt), { N: wrap.N, r: wrap.r, p: wrap.p, dkLen: 32 })
  try {
    return xchacha20poly1305(kek, unb64(wrap.n), KEY_AAD).decrypt(unb64(wrap.c))
  } catch {
    throw new Error('wrong passphrase')
  }
}

// ---------- host helpers (platform specific, no shell interpolation) ----------
// Paths and sizes go in through environment variables, never spliced into a
// command line; secrets go in through stdin, never argv.

function ps(io, script, env = {}, stdin) {
  return io.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], { env, stdin, timeoutMs: 120000 })
}

async function must(promise, what) {
  const r = await promise
  if (r.exitCode !== 0) throw new Error(`${what} failed: ${(r.stderr || r.stdout || '').trim().slice(0, 300)}`)
  return r
}

export async function removePath(io, path) {
  if (!(await io.exists(path))) return
  if (io.platform === 'windows') {
    await must(ps(io, "Remove-Item -LiteralPath $env:TV_A -Recurse -Force -ErrorAction Stop", { TV_A: path }), `delete ${path}`)
  } else {
    await must(io.run(['rm', '-rf', '--', path]), `delete ${path}`)
  }
}

export async function movePath(io, from, to) {
  if (io.platform === 'windows') {
    await must(ps(io, "Move-Item -LiteralPath $env:TV_A -Destination $env:TV_B -Force -ErrorAction Stop", { TV_A: from, TV_B: to }), `move ${from}`)
  } else {
    await must(io.run(['mv', '-f', '--', from, to]), `move ${from}`)
  }
}

async function readSlice(io, path, offset, length) {
  let r
  if (io.platform === 'windows') {
    const script = [
      "$f=[IO.File]::Open($env:TV_A,'Open','Read','ReadWrite,Delete')",
      "try { [void]$f.Seek([int64]$env:TV_OFF,'Begin'); $b=New-Object byte[] ([int]$env:TV_LEN); $t=0",
      "while ($t -lt $b.Length) { $n=$f.Read($b,$t,$b.Length-$t); if ($n -le 0) { break }; $t+=$n }",
      "[Console]::Out.Write([Convert]::ToBase64String($b,0,$t)) } finally { $f.Close() }",
    ].join('; ')
    r = await must(ps(io, script, { TV_A: path, TV_OFF: String(offset), TV_LEN: String(length) }), `read ${path}`)
  } else {
    r = await must(io.run(['sh', '-c', 'tail -c +"$((TV_OFF+1))" "$TV_A" | head -c "$TV_LEN" | base64'], { env: { TV_A: path, TV_OFF: String(offset), TV_LEN: String(length) } }), `read ${path}`)
  }
  return unb64(r.stdout)
}

export async function readFileBytes(io, path, size) {
  if (size <= DIRECT_READ_MAX) return io.readBytes(path)
  const parts = []
  for (let at = 0; at < size; at += SEG_BYTES) parts.push(await readSlice(io, path, at, Math.min(SEG_BYTES, size - at)))
  const out = concat(parts)
  if (out.length !== size) throw new Error(`read ${out.length} of ${size} bytes of ${path}`)
  return out
}

/**
 * Writes text of any size. The engine's write takes at most 4 MiB, so a large
 * text is written as numbered parts (split at line ends, each <= SEG_BYTES),
 * joined by the host into a temp file, and moved into place: the target path
 * only ever holds a complete file.
 */
export async function writeText(io, path, text) {
  const bytes = utf8.encode(text)
  if (bytes.length <= DIRECT_READ_MAX) return io.write(path, text)
  const parts = []
  let start = 0
  while (start < bytes.length) {
    let end = Math.min(start + SEG_BYTES, bytes.length)
    if (end < bytes.length) {
      const nl = bytes.lastIndexOf(0x0a, end - 1)
      if (nl >= start) end = nl + 1
      else while (end > start && (bytes[end] & 0xc0) === 0x80) end-- // never split a UTF-8 character
    }
    const part = `${path}.part-${String(parts.length + 1).padStart(4, '0')}`
    await io.write(part, fromUtf8.decode(bytes.subarray(start, end)))
    parts.push(part)
    start = end
  }
  const tmp = `${path}.tmp`
  try {
    if (io.platform === 'windows') {
      const script = "$o=[IO.File]::Create($env:TV_B); try { foreach ($p in ($env:TV_A -split '\\|')) { $i=[IO.File]::OpenRead($p); try { $i.CopyTo($o) } finally { $i.Close() } } } finally { $o.Close() }"
      await must(ps(io, script, { TV_A: parts.join('|'), TV_B: tmp }), `join ${path}`)
    } else {
      await must(io.run(['sh', '-c', 'out="$1"; shift; cat -- "$@" > "$out"', 'sh', tmp, ...parts]), `join ${path}`)
    }
    const st = await io.stat(tmp)
    if (st.size !== bytes.length) throw new Error(`joined ${st.size} of ${bytes.length} bytes for ${path}`)
    await movePath(io, tmp, path)
  } finally {
    for (const p of parts) await removePath(io, p)
    await removePath(io, tmp)
  }
}

// ---------- OS keystore ----------
// windows: DPAPI (CurrentUser), the wrapped blob kept in the plugin's store
// mac: login Keychain item; linux: Secret Service via secret-tool

const KC_SERVICE = 'transcript-vault'

export function keystoreKind(io) {
  return io.platform === 'windows' ? 'dpapi' : io.platform === 'mac' ? 'keychain' : 'secret-tool'
}

export async function keystoreSave(io, sk) {
  const kind = keystoreKind(io)
  if (kind === 'dpapi') {
    const script = "Add-Type -AssemblyName System.Security; $i=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); $o=[Security.Cryptography.ProtectedData]::Protect($i,[Text.Encoding]::UTF8.GetBytes('transcript-vault'),'CurrentUser'); [Console]::Out.Write([Convert]::ToBase64String($o))"
    const r = await must(ps(io, script, {}, b64(sk)), 'DPAPI protect')
    return { kind, blob: r.stdout.trim() }
  }
  if (kind === 'keychain') {
    // `security -i` reads the command from stdin, so the key never sits in argv
    await must(io.run(['security', '-i'], { stdin: `add-generic-password -U -a ${io.user} -s ${KC_SERVICE} -w ${b64(sk)}\n` }), 'Keychain save')
    return { kind }
  }
  await must(io.run(['secret-tool', 'store', `--label=${KC_SERVICE}`, 'service', KC_SERVICE], { stdin: b64(sk) }), 'secret-tool store')
  return { kind }
}

export async function keystoreLoad(io, entry) {
  if (entry.kind === 'dpapi') {
    const script = "Add-Type -AssemblyName System.Security; $i=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); $o=[Security.Cryptography.ProtectedData]::Unprotect($i,[Text.Encoding]::UTF8.GetBytes('transcript-vault'),'CurrentUser'); [Console]::Out.Write([Convert]::ToBase64String($o))"
    return unb64((await must(ps(io, script, {}, entry.blob), 'DPAPI unprotect')).stdout)
  }
  if (entry.kind === 'keychain') {
    return unb64((await must(io.run(['security', 'find-generic-password', '-a', io.user, '-s', KC_SERVICE, '-w']), 'Keychain read')).stdout)
  }
  return unb64((await must(io.run(['secret-tool', 'lookup', 'service', KC_SERVICE]), 'secret-tool lookup')).stdout)
}

export async function keystoreForget(io, entry) {
  if (entry.kind === 'keychain') await io.run(['security', 'delete-generic-password', '-a', io.user, '-s', KC_SERVICE])
  if (entry.kind === 'secret-tool') await io.run(['secret-tool', 'clear', 'service', KC_SERVICE])
  // dpapi: the blob lives in the keyring record, which the caller drops
}

// ---------- vault layout ----------
// <projects>/<project>/<sid>.jsonl          plaintext transcript (Claude Code's)
// <projects>/<project>/<sid>.vault/seg-NNNNNN.tv   encrypted segments, in order
// <projects>/<project>/<sid>.vault/OPENING  marker while a vault is being opened

export async function scan(io, projectsDir) {
  const out = []
  if (!(await io.exists(projectsDir))) return out
  for (const proj of await io.list(projectsDir)) {
    if (proj.kind !== 'directory') continue
    const dir = join(projectsDir, proj.name)
    for (const entry of await io.list(dir)) {
      const plain = entry.kind === 'file' && SESSION_FILE.exec(entry.name)
      const vault = entry.kind === 'directory' && VAULT_DIR.exec(entry.name)
      if (plain) out.push({ kind: 'plain', project: proj.name, dir, sid: plain[1], path: join(dir, entry.name), size: entry.size, mtimeMs: entry.mtimeMs })
      if (vault) out.push({ kind: 'vault', project: proj.name, dir, sid: vault[1], path: join(dir, entry.name), mtimeMs: entry.mtimeMs })
    }
  }
  return out
}

async function segmentsOf(io, vaultPath) {
  if (!(await io.exists(vaultPath))) return []
  return (await io.list(vaultPath))
    .map(e => ({ e, m: SEG_FILE.exec(e.name) }))
    .filter(x => x.m && x.e.kind === 'file')
    .map(x => ({ index: Number(x.m[1]), path: join(vaultPath, x.e.name) }))
    .sort((a, b) => a.index - b.index)
}

const segName = i => `seg-${String(i).padStart(6, '0')}.tv`

async function writeSegments(io, vaultPath, pk, sid, bytes, firstIndex) {
  const count = Math.max(1, Math.ceil(bytes.length / SEG_BYTES))
  for (let k = 0; k < count; k++) {
    const index = firstIndex + k
    const text = JSON.stringify(sealSegment(pk, bytes.subarray(k * SEG_BYTES, (k + 1) * SEG_BYTES), sid, index))
    const path = join(vaultPath, segName(index))
    await io.write(path, text)
    if ((await io.readText(path)) !== text) throw new Error(`write check failed for ${path}`)
  }
}

/**
 * Encrypts one plaintext transcript into its vault and deletes the plaintext.
 * If a vault already exists, the plaintext is a tail that was written after
 * the vault was made (a session kept going): it is appended as new segments.
 * If the vault carries the OPENING marker, a previous open was interrupted and
 * the plaintext is the whole session: the vault is replaced.
 * Returns 'locked' | 'busy' (file changed while reading; left alone) |
 * 'interrupted' (an earlier open did not finish writing; run open again).
 */
export async function lockSession(io, pk, item) {
  const before = await io.stat(item.path)
  const bytes = await readFileBytes(io, item.path, before.size)
  const vaultPath = join(item.dir, `${item.sid}.vault`)
  const existing = await segmentsOf(io, vaultPath)
  const marker = join(vaultPath, OPENING)
  const wasOpening = await io.exists(marker)
  if (wasOpening) {
    // an open was interrupted: only trust the plaintext if it was written in full
    const expected = Number((await io.readText(marker)).trim())
    if (!(expected > 0) || before.size < expected) return 'interrupted'
  }

  if (existing.length === 0 || wasOpening) {
    const tmp = join(item.dir, `${item.sid}.vault.tmp`)
    await removePath(io, tmp)
    await writeSegments(io, tmp, pk, item.sid, bytes, 1)
    const after = await io.stat(item.path)
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs) { await removePath(io, tmp); return 'busy' }
    await removePath(io, vaultPath)
    await movePath(io, tmp, vaultPath)
  } else {
    const first = existing[existing.length - 1].index + 1
    await writeSegments(io, vaultPath, pk, item.sid, bytes, first)
    const after = await io.stat(item.path)
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs) {
      for (const s of await segmentsOf(io, vaultPath)) if (s.index >= first) await removePath(io, s.path)
      return 'busy'
    }
  }
  await removePath(io, item.path)
  return 'locked'
}

/** Decrypts a vault in memory. */
export async function readVault(io, sk, vaultPath, sid) {
  const segs = await segmentsOf(io, vaultPath)
  if (segs.length === 0) throw new Error(`no segments in ${vaultPath}`)
  const parts = []
  segs.forEach((s, k) => { if (s.index !== k + 1) throw new Error(`segment ${k + 1} of ${sid} is missing`) })
  for (const s of segs) parts.push(openSegment(sk, JSON.parse(await io.readText(s.path)), sid, s.index))
  return concat(parts)
}

/**
 * Restores a vault to the plaintext transcript Claude Code reads, so the
 * session can be resumed. Any plaintext tail already there is kept after it.
 */
export async function openSession(io, sk, item) {
  const vaultPath = join(item.dir, `${item.sid}.vault`)
  const plainPath = join(item.dir, `${item.sid}.jsonl`)
  const bytes = await readVault(io, sk, vaultPath, item.sid)
  let text = fromUtf8.decode(bytes)
  if (await io.exists(plainPath) && !(await io.exists(join(vaultPath, OPENING)))) {
    const st = await io.stat(plainPath)
    text += fromUtf8.decode(await readFileBytes(io, plainPath, st.size))
  }
  const size = utf8.encode(text).length
  await io.write(join(vaultPath, OPENING), String(size))
  await writeText(io, plainPath, text)
  const st = await io.stat(plainPath)
  if (st.size !== size) throw new Error(`write check failed for ${plainPath}`)
  await removePath(io, vaultPath)
  return plainPath
}

// ---------- transcript reading ----------

function textOf(content) {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content.map(b => (b && b.type === 'text' ? b.text : b && b.type === 'tool_result' ? textOf(b.content) : '')).filter(Boolean).join('\n')
}

export function rows(bytes) {
  const out = []
  for (const line of fromUtf8.decode(bytes).split('\n')) {
    if (!line.trim()) continue
    try { out.push(JSON.parse(line)) } catch { /* a torn last line */ }
  }
  return out
}

export function summarize(bytes) {
  const all = rows(bytes)
  const firstUser = all.find(r => r.type === 'user' && !r.isMeta && typeof textOf(r.message?.content) === 'string' && textOf(r.message?.content).trim() && !textOf(r.message?.content).startsWith('<'))
  const stamps = all.map(r => r.timestamp).filter(Boolean)
  return {
    title: (all.find(r => r.type === 'summary')?.summary || (firstUser ? textOf(firstUser.message.content) : '') || '(no prompt)').replace(/\s+/g, ' ').slice(0, 80),
    cwd: all.find(r => r.cwd)?.cwd,
    first: stamps[0],
    last: stamps[stamps.length - 1],
    messages: all.filter(r => r.type === 'user' || r.type === 'assistant').length,
  }
}

export function searchRows(bytes, query, max) {
  const q = query.toLowerCase()
  const hits = []
  for (const r of rows(bytes)) {
    if (r.type !== 'user' && r.type !== 'assistant') continue
    const text = textOf(r.message?.content)
    const at = text.toLowerCase().indexOf(q)
    if (at < 0) continue
    const start = Math.max(0, at - 160)
    hits.push({ role: r.message?.role || r.type, timestamp: r.timestamp, snippet: (start > 0 ? '…' : '') + text.slice(start, at + q.length + 160).replace(/\s+/g, ' ') + (at + q.length + 160 < text.length ? '…' : '') })
    if (hits.length >= max) break
  }
  return hits
}

// ---------- secret masking ----------

export const SECRET_PATTERNS = [
  ['private-key', /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----/g],
  ['anthropic-key', /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ['openai-key', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g],
  ['aws-access-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g],
  ['gitlab-token', /\bglpat-[A-Za-z0-9_-]{20,}\b/g],
  ['slack-token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
  ['google-api-key', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['stripe-key', /\b[rs]k_live_[A-Za-z0-9]{20,}\b/g],
  ['npm-token', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  ['assigned-secret', /\b((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?)([^\s"',;]{8,})/gi],
]

export function maskSecrets(text) {
  let count = 0
  let out = text
  for (const [kind, re] of SECRET_PATTERNS) {
    out = out.replace(re, (...m) => {
      count++
      return kind === 'assigned-secret' ? `${m[1]}[REDACTED:${kind}]` : `[REDACTED:${kind}]`
    })
  }
  return { text: out, count }
}

/** Masks the rewritable parts of one session.append row; returns null when nothing changed. */
export function maskContent(content) {
  let total = 0
  const fix = s => { const r = maskSecrets(s); total += r.count; return r.text }
  const next = content.map(block => {
    if (block.type === 'text') return { ...block, text: fix(block.text) }
    if (block.type === 'tool_result') {
      if (typeof block.content === 'string') return { ...block, content: fix(block.content) }
      if (Array.isArray(block.content)) return { ...block, content: block.content.map(b => (b.type === 'text' ? { ...b, text: fix(b.text) } : b)) }
    }
    return block
  })
  return total > 0 ? { content: next, count: total } : null
}
