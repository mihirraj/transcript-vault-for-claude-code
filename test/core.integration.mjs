// Integration test for transcript-vault's core.mjs against real files, under Node.
// usage: node test/core.integration.mjs <work dir holding a COPY of ~/.claude/projects as projects/>
// Never point it at your real ~/.claude: it encrypts and deletes files there.
import fs from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

// Obviously fake test keys, built from pieces so secret scanners do not
// mistake them for real ones. They only need the shape the masker matches.
const FAKE_ANTHROPIC = 'sk-ant-' + 'FAKE-not-a-real-key-0000000000'
const FAKE_AWS = 'AKIA' + 'FAKEFAKEFAKEFAKE'
const FAKE_GITHUB = 'ghp_' + 'FAKE'.repeat(9)
const FAKE_SLACK = 'xoxb-' + 'FAKE-0000000000'

const work = process.argv[2]
if (!work) { console.error('usage: node test/core.integration.mjs <work dir>'); process.exit(2) }
const corePath = fileURLToPath(new URL('../hooks/core.mjs', import.meta.url))
const core = await import(pathToFileURL(corePath).href)
const projects = path.join(work, 'projects').replace(/\\/g, '/')

const io = {
  platform: process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'mac' : 'linux',
  user: process.env.USERNAME || process.env.USER,
  async readBytes(p) { const st = await fs.stat(p); if (st.size > 4 * 1024 * 1024) throw new Error('over 4 MiB (engine limit)'); return new Uint8Array(await fs.readFile(p)) },
  readText: p => fs.readFile(p, 'utf8'),
  async write(p, t) { if (Buffer.byteLength(t) > 4 * 1024 * 1024) throw new Error("over 4 MiB (engine limit)"); await fs.mkdir(path.dirname(p), { recursive: true }); await fs.writeFile(p, t) },
  async list(d) { return Promise.all((await fs.readdir(d, { withFileTypes: true })).map(async e => { const st = await fs.stat(path.join(d, e.name)); return { name: e.name, kind: e.isDirectory() ? 'directory' : e.isFile() ? 'file' : 'other', size: e.isFile() ? st.size : 0, mtimeMs: e.isFile() ? st.mtimeMs : 0 } })) },
  async stat(p) { const st = await fs.stat(p); return { kind: st.isDirectory() ? 'directory' : 'file', size: st.size, mtimeMs: st.mtimeMs } },
  exists: p => fs.access(p).then(() => true, () => false),
  run(argv, init = {}) {
    return new Promise((res, rej) => {
      const c = spawn(argv[0], argv.slice(1), { env: { ...process.env, ...(init.env || {}) } })
      let stdout = '', stderr = ''
      c.stdout.on('data', d => (stdout += d)); c.stderr.on('data', d => (stderr += d))
      c.on('error', rej); c.on('close', code => res({ exitCode: code, stdout, stderr }))
      c.stdin.end(init.stdin ?? '')
    })
  },
}

let failures = 0
const ok = (cond, what) => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`); if (!cond) failures++ }
const sha = b => createHash('sha256').update(b).digest('hex')
const throws = async (fn) => { try { await fn(); return false } catch { return true } }

// 1. crypto
const { sk, pk } = core.newKeypair()
const msg = new TextEncoder().encode('hello vault')
const seg = core.sealSegment(pk, msg, 'sid-a', 1)
ok(new TextDecoder().decode(core.openSegment(sk, seg, 'sid-a', 1)) === 'hello vault', 'segment round-trip')
ok(await throws(() => core.openSegment(sk, seg, 'sid-b', 1)), 'segment bound to session id')
ok(await throws(() => core.openSegment(sk, { ...seg, i: 2 }, 'sid-a', 2)), 'segment bound to index')
const bad = core.unb64(seg.c); bad[0] ^= 1
ok(await throws(() => core.openSegment(sk, { ...seg, c: core.b64(bad) }, 'sid-a', 1)), 'tampered ciphertext rejected')
ok(await throws(() => core.openSegment(core.newKeypair().sk, seg, 'sid-a', 1)), 'wrong private key rejected')

// 2. passphrase wrap
const t0 = Date.now()
const wrap = await core.wrapWithPassphrase(sk, 'correct horse')
ok(sha(await core.unwrapWithPassphrase(wrap, 'correct horse')) === sha(sk), `passphrase unwrap (${Date.now() - t0} ms incl. wrap)`)
ok(await throws(() => core.unwrapWithPassphrase(wrap, 'wrong horse')), 'wrong passphrase rejected')

// 3. OS keystore
const ks = await core.keystoreSave(io, sk)
ok(sha(await core.keystoreLoad(io, ks)) === sha(sk), `keystore (${ks.kind}) round-trip`)

// 4. lock + open every copied transcript, byte-identical
const originals = new Map()
for (const item of await core.scan(io, projects)) if (item.kind === 'plain') originals.set(item.path, { item, hash: sha(await fs.readFile(item.path)), size: item.size })
ok(originals.size > 0, `found ${originals.size} transcripts (largest ${Math.max(...[...originals.values()].map(o => o.size))} bytes)`)
for (const { item } of originals.values()) {
  const r = await core.lockSession(io, pk, item)
  ok(r === 'locked', `lock ${item.sid.slice(0, 8)} (${item.size} B) -> ${r}`)
  ok(!(await io.exists(item.path)), `  plaintext removed`)
}
const scanned = await core.scan(io, projects)
ok(scanned.every(i => i.kind === 'vault'), 'only vaults remain after lock')
for (const { item, hash } of originals.values()) {
  const v = scanned.find(i => i.sid === item.sid)
  const s = core.summarize(await core.readVault(io, sk, v.path, v.sid))
  ok(typeof s.title === 'string', `  summary: "${s.title.slice(0, 40)}" (${s.messages} msgs)`)
  await core.openSession(io, sk, v)
  ok(sha(await fs.readFile(item.path)) === hash, `open ${item.sid.slice(0, 8)} byte-identical`)
  ok(!(await io.exists(v.path)), '  vault removed after open')
}

// 5. tail appended after lock (a session kept writing)
const first = [...originals.values()][0].item
const origBytes = await fs.readFile(first.path)
await core.lockSession(io, pk, first)
const tail = '{"type":"user","message":{"role":"user","content":"tail line"}}\n'
await fs.writeFile(first.path, tail)
const r5 = await core.lockSession(io, pk, { ...first, size: tail.length })
ok(r5 === 'locked', 'lock tail into existing vault')
const segs = (await fs.readdir(path.join(first.dir, `${first.sid}.vault`))).length
ok(segs >= 2, `  vault now has ${segs} segments`)
const v5 = (await core.scan(io, projects)).find(i => i.sid === first.sid)
await core.openSession(io, sk, v5)
ok(sha(await fs.readFile(first.path)) === sha(Buffer.concat([origBytes, Buffer.from(tail)])), '  open gives original + tail')

// 6. interrupted open: partial plaintext must not replace the vault
await core.lockSession(io, pk, { ...first, size: (await fs.stat(first.path)).size })
const vdir = path.join(first.dir, `${first.sid}.vault`)
await fs.writeFile(path.join(vdir, 'OPENING'), String(origBytes.length + tail.length))
await fs.writeFile(first.path, origBytes.subarray(0, 100))
ok((await core.lockSession(io, pk, first)) === 'interrupted', 'interrupted open detected, vault kept')
const v6 = (await core.scan(io, projects)).find(i => i.kind === 'vault' && i.sid === first.sid)
await core.openSession(io, sk, v6)
ok(sha(await fs.readFile(first.path)) === sha(Buffer.concat([origBytes, Buffer.from(tail)])), '  re-open recovers the full session')

// 7. search
await core.lockSession(io, pk, { ...first, size: (await fs.stat(first.path)).size })
const v7 = (await core.scan(io, projects)).find(i => i.sid === first.sid)
const hits = core.searchRows(await core.readVault(io, sk, v7.path, v7.sid), 'tail line', 5)
ok(hits.length === 1 && hits[0].snippet.includes('tail line'), 'search finds text inside a vault')

// 8. masking
const m = core.maskSecrets(`key ${FAKE_ANTHROPIC} and ${FAKE_AWS} and password=fake-password-1234 ok`)
ok(m.count === 3 && !m.text.includes('fake-password-1234') && !m.text.includes('AKIA') && m.text.includes('password=[REDACTED'), `masking: ${m.text}`)
ok(core.maskSecrets('a normal sentence about passwords and keys').count === 0, 'masking leaves prose alone')
const mc = core.maskContent([{ type: 'text', text: FAKE_GITHUB }, { type: 'tool_use', id: 'x', input: {} }, { type: 'tool_result', tool_use_id: 'x', content: `token ${FAKE_SLACK}` }])
ok(mc && mc.count === 2 && mc.content[1].type === 'tool_use', 'maskContent rewrites text + tool_result only')

console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED')
process.exit(failures ? 1 : 0)
