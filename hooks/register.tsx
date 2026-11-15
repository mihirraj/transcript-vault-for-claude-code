import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import * as core from './core.mjs'
import type { VaultStage } from '../types'

type Engine = EngineInterface
type Io = Parameters<typeof core.scan>[0]
type Wrap = Awaited<ReturnType<typeof core.wrapWithPassphrase>>
type KeystoreEntry = Awaited<ReturnType<typeof core.keystoreSave>>
type Keyring = { v: 1; pk: string; keystore?: KeystoreEntry; passphrase?: Wrap; createdAt: number }
type Item = Awaited<ReturnType<typeof core.scan>>[number]

const NAME = 'transcript-vault'
const PANE = 'transcript-vault-passphrase'
const TOOL = 'search_vault'
const DOT = '•'

const typedLen = atom({ plugin: 'transcript-vault', key: 'typedLen' } as const, 0)
const stage = atom({ plugin: 'transcript-vault', key: 'stage' } as const, 'unlock' as VaultStage)
const note = atom({ plugin: 'transcript-vault', key: 'note' } as const, '')

// Memory only, never written anywhere: the unlocked private key, the
// passphrase being typed, and a key pair waiting for its first passphrase.
let unlocked: Uint8Array | undefined
let typed = ''
let firstEntry: string | undefined
let pending: { sk: Uint8Array; pk: Uint8Array } | undefined
let lastList: Item[] = []
let ioCache: Io | undefined

// Settings from the manifest's userConfig, set when register runs.
let mode: 'keystore' | 'passphrase' = 'keystore'
let idleMs = 60 * 60_000
let maskOn = false
let projectsOverride = ''

// ---------- environment ----------

async function io($: Engine): Promise<Io> {
  if (ioCache) return ioCache
  const isWindows = (await $.env.get('OS')) === 'Windows_NT'
  const platform = isWindows ? 'windows' : (await $.process.run(['uname', '-s'])).stdout.trim() === 'Darwin' ? 'mac' : 'linux'
  const user = (await $.env.get('USERNAME')) ?? (await $.env.get('USER')) ?? 'user'
  ioCache = {
    platform,
    user,
    readBytes: async p => core.unb64((await $.fs.read(p, { as: 'bytes' })).base64),
    readText: p => $.fs.read(p),
    write: (p, t) => $.fs.write(p, t),
    list: async d => (await $.fs.list(d)).map(e => ({ name: e.name, kind: e.kind === 'dir' ? 'directory' : e.kind, size: e.size, mtimeMs: e.mtimeMs })),
    stat: async p => { const s = await $.fs.stat(p); return { kind: s.kind === 'dir' ? 'directory' : s.kind, size: s.size, mtimeMs: s.mtimeMs } },
    exists: p => $.fs.exists(p),
    run: (argv, init) => $.process.run(argv, init),
  } as Io
  return ioCache
}

async function configDir($: Engine): Promise<string> {
  const config = (await $.env.get('CLAUDE_CONFIG_DIR')) ?? `${(await $.env.get('USERPROFILE')) ?? (await $.env.get('HOME')) ?? '~'}/.claude`
  return config.replace(/\\/g, '/')
}

async function projectsDir($: Engine): Promise<string> {
  const override = projectsOverride
  if (override) return override.replace(/\\/g, '/')
  return `${await configDir($)}/projects`
}

function projectSlug(cwd: string) {
  return cwd.replace(/[^A-Za-z0-9]/g, '-')
}

// The key record lives in a fixed file, <config>/transcript-vault/vault.json,
// not in the plugin's store: a store is per installed copy, so a reinstall,
// another marketplace or a dev copy would not find the key and could not open
// the vaults. Holds the public key, the wrapped private key and whether
// automatic locking is on. Nothing in it opens a vault without the OS
// keystore or the passphrase.
type VaultFile = { keyring?: Keyring; enabled?: boolean }

async function vaultFilePath($: Engine): Promise<string> {
  return `${await configDir($)}/transcript-vault/vault.json`
}

async function readVaultFile($: Engine): Promise<VaultFile> {
  const path = await vaultFilePath($)
  if (!(await $.fs.exists(path))) {
    // v0.1.0 kept the record in the plugin's store: move it once.
    const legacy = (await $.store.get('keyring')) as Keyring | undefined
    if (!legacy) return {}
    const moved: VaultFile = { keyring: legacy, enabled: (await $.store.get('enabled')) === true }
    await $.fs.write(path, JSON.stringify(moved, null, 2))
    return moved
  }
  // A file that exists but does not parse is an error, never "not set up":
  // treating it as missing would let /vault setup make a new key.
  return JSON.parse(await $.fs.read(path)) as VaultFile
}

async function writeVaultFile($: Engine, change: VaultFile) {
  const next = { ...(await readVaultFile($)), ...change }
  await $.fs.write(await vaultFilePath($), JSON.stringify(next, null, 2))
}

async function getKeyring($: Engine) {
  return (await readVaultFile($)).keyring
}
async function setKeyring($: Engine, kr: Keyring) {
  await writeVaultFile($, { keyring: kr })
}
async function isEnabled($: Engine) {
  return (await readVaultFile($)).enabled === true
}
async function setEnabled($: Engine, on: boolean) {
  await writeVaultFile($, { enabled: on })
}

/** The private key, if it can be had without asking the person. */
async function key($: Engine): Promise<Uint8Array | undefined> {
  if (unlocked) return unlocked
  const kr = await getKeyring($)
  // In passphrase mode the keystore copy only exists until a passphrase takes
  // its place; using it meanwhile lets `/vault passphrase` finish the switch.
  if (!kr?.keystore || (mode !== 'keystore' && kr.passphrase)) return undefined
  const sk = await core.keystoreLoad(await io($), kr.keystore)
  if (core.b64(core.newKeypairFrom(sk).pk) !== kr.pk) throw new Error('the key in the OS keystore does not match this vault')
  unlocked = sk
  return sk
}

// ---------- locking ----------

async function sweep($: Engine, all: boolean) {
  const kr = await getKeyring($)
  if (!kr || !(await isEnabled($))) return undefined
  const pk = core.unb64(kr.pk)
  const current = await $.session.id()
  const ended = ((await $.store.get('ended')) as string[] | undefined) ?? []
  const now = await $.clock.now()
  const counts = { locked: 0, busy: 0, interrupted: 0, skipped: 0, failed: [] as string[] }
  for (const item of await core.scan(await io($), await projectsDir($))) {
    if (item.kind !== 'plain' || item.sid === current) continue
    const age = now - item.mtimeMs
    const isEligible = ended.includes(item.sid) ? age > 30_000 : all ? age > 120_000 : age > idleMs
    if (!isEligible) { counts.skipped++; continue }
    try {
      const r = await core.lockSession(await io($), pk, item)
      counts[r as 'locked' | 'busy' | 'interrupted']++
    } catch (err) {
      counts.failed.push(`${item.sid.slice(0, 8)}: ${String((err as Error).message ?? err).slice(0, 120)}`)
    }
  }
  const still = (await core.scan(await io($), await projectsDir($))).filter(i => i.kind === 'plain').map(i => i.sid)
  await $.store.set('ended', ended.filter(id => still.includes(id)))
  return counts
}

const describeSweep = (c: NonNullable<Awaited<ReturnType<typeof sweep>>>) =>
  [
    `Encrypted ${c.locked} session${c.locked === 1 ? '' : 's'}.`,
    c.skipped ? `${c.skipped} left as they are (in use or not idle yet).` : '',
    c.busy ? `${c.busy} changed while being read and were left for next time.` : '',
    c.interrupted ? `${c.interrupted} had an interrupted open; run \`/vault open\` on them again.` : '',
    c.failed.length ? `Failed: ${c.failed.join('; ')}` : '',
  ].filter(Boolean).join(' ')

// ---------- listing ----------

async function vaults($: Engine, everywhere: boolean) {
  const slug = projectSlug(await $.session.cwd())
  const all = (await core.scan(await io($), await projectsDir($))).filter(i => i.kind === 'vault')
  const mine = everywhere ? all : all.filter(i => i.project.toLowerCase() === slug.toLowerCase())
  return mine.sort((a, b) => b.mtimeMs - a.mtimeMs)
}

async function titled($: Engine, item: Item, sk: Uint8Array | undefined) {
  if (!sk) return `${item.sid}  (locked: \`/vault unlock\` to see titles)`
  try {
    const s = core.summarize(await core.readVault(await io($), sk, item.path, item.sid))
    return `${(s.last ?? '').slice(0, 10) || '?'}  ${s.title}  _(${s.messages} msgs, ${item.sid.slice(0, 8)})_`
  } catch (err) {
    return `${item.sid}  (cannot decrypt: ${String((err as Error).message).slice(0, 80)})`
  }
}

// ---------- passphrase pane ----------

async function openPane($: Engine, s: VaultStage, message: string) {
  typed = ''
  await update($, typedLen, () => 0)
  await update($, stage, () => s)
  await update($, note, () => message)
  await $.ui.open({ id: PANE, title: 'transcript-vault', focus: true, closeOnEscape: true, rows: 8 })
}

async function finishPassphrase($: Engine, value: string) {
  const s = await read($, stage)
  const kr = await getKeyring($)
  if (s === 'unlock') {
    if (!kr?.passphrase) return update($, note, () => 'There is no passphrase to unlock with.')
    await update($, note, () => 'Checking…')
    try {
      const sk = await core.unwrapWithPassphrase(kr.passphrase, value)
      unlocked = sk
      if (mode === 'keystore' && !kr.keystore) {
        const entry = await core.keystoreSave(await io($), sk)
        const { passphrase: _gone, ...rest } = kr
        await setKeyring($, { ...rest, keystore: entry })
        $.ui.toast('Vault unlocked; key moved to the OS keystore (keyMode is "keystore").')
      } else {
        $.ui.toast('Vault unlocked for this session.')
      }
      return $.ui.close({ id: PANE })
    } catch {
      return update($, note, () => 'Wrong passphrase. Try again, or Esc to cancel.')
    }
  }
  if (s === 'set') {
    if (value.length < 8) return update($, note, () => 'Use at least 8 characters.')
    firstEntry = value
    typed = ''
    await update($, typedLen, () => 0)
    await update($, stage, () => 'confirm')
    return update($, note, () => 'Type it again to confirm.')
  }
  // confirm
  if (value !== firstEntry) {
    firstEntry = undefined
    typed = ''
    await update($, typedLen, () => 0)
    await update($, stage, () => 'set')
    return update($, note, () => 'They did not match. Choose a passphrase again.')
  }
  await update($, note, () => 'Protecting the key…')
  const sk = unlocked ?? pending?.sk
  if (!sk) return update($, note, () => 'No key to protect; run `/vault setup` first.')
  const base: Keyring = kr ?? { v: 1, pk: core.b64(pending!.pk), createdAt: await $.clock.now() }
  const next: Keyring = { ...base, passphrase: await core.wrapWithPassphrase(sk, value) }
  if (mode === 'passphrase' && next.keystore) {
    await core.keystoreForget(await io($), next.keystore)
    delete next.keystore
  }
  await setKeyring($, next)
  unlocked = sk
  firstEntry = undefined
  const wasSetup = pending !== undefined
  pending = undefined
  await $.ui.close({ id: PANE })
  if (wasSetup) {
    await setEnabled($, true)
    const c = await sweep($, false)
    $.ui.toast(`Vault set up with a passphrase. ${c ? describeSweep(c) : ''}`)
  } else {
    $.ui.toast('Passphrase set.')
  }
}


export const register: Register = (on, options) => {
  mode = options.keyMode === 'passphrase' ? 'passphrase' : 'keystore'
  idleMs = Math.max(1, Number(options.idleMinutes ?? 60)) * 60_000
  maskOn = options.maskSecrets === true
  projectsOverride = String(options.projectsDir ?? '').trim()

  // ---------- events ----------

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'vault',
      description: 'Encrypt idle Claude Code transcripts at rest (setup, status, lock, list, open, unlock, passphrase)',
      argumentHint: '[setup|status|lock|list [all]|open <n|id|all>|unlock|passphrase]',
    })
    await $.tool.register({
      name: TOOL,
      description:
        'Search the user\'s encrypted Claude Code session history (transcript-vault) for a phrase. ' +
        'Returns matching message snippets with session id and time. Use when the user asks about a past conversation ' +
        'that is no longer in plain text. Fails with a note when the vault is locked.',
      inputSchema: {
        type: 'object',
        properties: {
          query: { type: 'string', description: 'Case-insensitive text to find' },
          allProjects: { type: 'boolean', description: 'Search every project, not just the current one (default false)' },
          limit: { type: 'number', description: 'Most snippets to return (default 20, max 50)' },
        },
        required: ['query'],
      },
    })
    const r = await next(e)
    $.clock.after(5_000, async () => {
      try {
        const c = await sweep($, false)
        if (c && (c.locked || c.failed.length)) $.ui.toast(`transcript-vault: ${describeSweep(c)}`)
        const kr = await getKeyring($)
        if (kr && mode === 'passphrase' && kr.keystore && !kr.passphrase) $.ui.toast('transcript-vault: keyMode is "passphrase" but no passphrase is set yet. Run `/vault passphrase`.')
      } catch (err) {
        $.ui.toast(`transcript-vault: background lock failed: ${String((err as Error).message ?? err).slice(0, 200)}`)
      }
    })
    return r
  })

  on('session.end', async ($, e, next) => {
    try {
      const id = await $.session.id()
      const ended = ((await $.store.get('ended')) as string[] | undefined) ?? []
      if (!ended.includes(id)) await $.store.set('ended', [...ended, id].slice(-100))
    } catch { /* never hold up an exit */ }
    return next(e)
  })

  if (maskOn) {
    on('session.append', async ($, e, next) => {
      const masked = core.maskContent(e.message.content as Parameters<typeof core.maskContent>[0])
      if (!masked) return next(e)
      return next({ ...e, message: { ...e.message, content: masked.content as typeof e.message.content } })
    }).catch(($, e, next) => next(e)) // masking failed: keep the row as it was, never drop it
  }

  on('command.run', { command: 'vault' }, async ($, e) => {
    const [sub = 'help', ...rest] = e.args.trim().split(/\s+/).filter(Boolean)
    const arg = rest.join(' ')
    const kr = await getKeyring($)
    const enabled = await isEnabled($)

    if (sub === 'setup') {
      if (kr && enabled) return { text: 'Already set up. `/vault status` shows the details.' }
      if (kr && !enabled) {
        await setEnabled($, true)
        const c = await sweep($, false)
        return { text: `Automatic locking is back on. ${c ? describeSweep(c) : ''}` }
      }
      if (mode === 'keystore') {
        const kp = core.newKeypair()
        const entry = await core.keystoreSave(await io($), kp.sk)
        await setKeyring($, { v: 1, pk: core.b64(kp.pk), keystore: entry, createdAt: await $.clock.now() })
        await setEnabled($, true)
        unlocked = kp.sk
        const c = await sweep($, false)
        return {
          text:
            `Vault set up. Your key is protected by the OS keystore (${entry.kind}). ` +
            `Sessions idle for more than ${idleMs / 60_000} minutes are encrypted at each session start. ${c ? describeSweep(c) : ''}\n\n` +
            'Run `/vault lock` to encrypt everything except this session now.',
        }
      }
      pending = core.newKeypair()
      await openPane($, 'set', 'Choose a passphrase (8+ characters). If you lose it, your encrypted history cannot be recovered.')
      return { text: 'Choose a passphrase in the pane to finish setting up.' }
    }

    if (!kr && sub === 'status') {
      const items = await core.scan(await io($), await projectsDir($))
      return {
        text: [
          '**Not set up yet**: nothing is encrypted. `/vault setup` starts it.',
          `**Key mode when set up:** ${mode}`,
          `**Plaintext sessions it would look at:** ${items.filter(i => i.kind === 'plain').length}`,
          `**Transcripts folder:** ${await projectsDir($)}`,
        ].join('\n'),
      }
    }

    if (!kr) return { text: 'transcript-vault is not set up yet. Run `/vault setup` to create a key and start encrypting idle sessions. Nothing is encrypted until you do.\n\n' + HELP }

    if (sub === 'status') {
      const items = await core.scan(await io($), await projectsDir($))
      const sk = await key($).catch(() => undefined)
      return {
        text: [
          `**Key mode:** ${mode}${kr.keystore ? ` (OS keystore: ${kr.keystore.kind})` : ''}${kr.passphrase ? ' (passphrase set)' : ''}`,
          `**Vault:** ${sk ? 'unlocked' : 'locked'}; automatic locking ${enabled ? 'on' : 'off'} (idle > ${idleMs / 60_000} min)`,
          `**Encrypted sessions:** ${items.filter(i => i.kind === 'vault').length}; **plaintext sessions:** ${items.filter(i => i.kind === 'plain').length} (this one included)`,
          `**Secret masking:** ${maskOn ? 'on' : 'off'}`,
          `**Transcripts folder:** ${await projectsDir($)}`,
          mode === 'passphrase' && kr.keystore ? '\n⚠ A copy of the key is still in the OS keystore. Run `/vault passphrase` to finish switching.' : '',
          mode === 'keystore' && !kr.keystore ? '\n⚠ The key is only passphrase-protected. Run `/vault unlock` once to move it to the OS keystore.' : '',
        ].filter(Boolean).join('\n'),
      }
    }

    if (sub === 'lock') {
      if (!enabled) await setEnabled($, true)
      const c = await sweep($, true)
      if (mode === 'passphrase') unlocked = undefined
      return { text: `${c ? describeSweep(c) : ''}${mode === 'passphrase' ? ' The key was cleared from memory.' : ''}\n\nThis session stays readable until it ends; it is encrypted at the next session start.` }
    }

    if (sub === 'list') {
      const everywhere = arg === 'all'
      lastList = (await vaults($, everywhere)).slice(0, 25)
      if (lastList.length === 0) return { text: everywhere ? 'No encrypted sessions yet.' : 'No encrypted sessions for this project. `/vault list all` shows every project.' }
      const sk = await key($).catch(() => undefined)
      const lines = await Promise.all(lastList.map(async (item, n) => `${n + 1}. ${await titled($, item, sk)}${everywhere ? `  — ${item.project}` : ''}`))
      return { text: `${lines.join('\n')}\n\n\`/vault open <number>\` decrypts one so you can \`/resume\` it.` }
    }

    if (sub === 'open') {
      if (!arg) return { text: 'Which one? `/vault list` numbers them; then `/vault open <number>` (or a session id prefix).' }
      const sk = await key($).catch(() => undefined)
      if (!sk) return { text: 'The vault is locked. Run `/vault unlock` first.' }
      if (arg === 'all') {
        const every = await vaults($, true)
        const failed: string[] = []
        for (const item of every) {
          try { await core.openSession(await io($), sk, item) } catch (err) { failed.push(`${item.sid.slice(0, 8)}: ${String((err as Error).message).slice(0, 100)}`) }
        }
        await setEnabled($, false)
        return {
          text:
            `Decrypted ${every.length - failed.length} of ${every.length} sessions and turned automatic locking off ` +
            `(\`/vault setup\` turns it back on).${failed.length ? ` Failed: ${failed.join('; ')}` : ''}`,
        }
      }
      const n = Number(arg)
      const isNumber = /^\d+$/.test(arg)
      // A number only means something against the list the person just saw.
      if (isNumber && lastList.length === 0) return { text: 'Run `/vault list` first, so the number points at the session you see (numbers are not kept across reloads or opens).' }
      const item = isNumber
        ? (n >= 1 && n <= lastList.length ? lastList[n - 1] : undefined)
        : (await vaults($, true)).find(i => i.sid.startsWith(arg.toLowerCase()))
      if (!item) return { text: `No encrypted session matches "${arg}". Use the number from \`/vault list\` (for example \`/vault open 2\`) or the start of a session id.` }
      try {
        await core.openSession(await io($), sk, item)
      } catch (err) {
        return { text: `Could not decrypt ${item.sid}: ${String((err as Error).message ?? err).slice(0, 300)}\n\nThe encrypted copy is untouched; nothing was lost.` }
      }
      lastList = []
      if (projectsOverride) {
        return {
          text:
            `Decrypted session ${item.sid} into ${await projectsDir($)}. ` +
            'That is the transcripts folder override (test mode), which `/resume` does not read, so there is nothing to resume. ' +
            'It is encrypted again at the next session start or `/vault lock`.',
        }
      }
      const here = item.project.toLowerCase() === projectSlug(await $.session.cwd()).toLowerCase()
      if (here) await $.prompt.fill({ text: `/resume ${item.sid}`, mode: 'replace' }).catch(() => undefined)
      return {
        text:
          `Decrypted session ${item.sid}. ` +
          (here ? 'Press Enter to resume it (the command is in your prompt).' : `It belongs to another project (${item.project}); start Claude Code there and run \`/resume ${item.sid}\`.`) +
          ' It is encrypted again once it has been idle and a new session starts.',
      }
    }

    const typedSecret = (sub === 'unlock' || sub === 'passphrase') && arg
      ? '\n\n⚠ Text typed after a command is saved in this session\'s transcript, so it was ignored. If that was your passphrase, choose a new one (`/vault passphrase`) and type it only in the pane.'
      : ''

    if (sub === 'unlock') {
      if (await key($).catch(() => undefined)) return { text: 'The vault is already unlocked.' + typedSecret }
      if (!kr.passphrase) return { text: 'There is no passphrase on this vault and the OS keystore did not answer. `/vault status` has details.' }
      await openPane($, 'unlock', 'Enter your vault passphrase.')
      return { text: 'Enter your passphrase in the pane.' + typedSecret }
    }

    if (sub === 'passphrase') {
      const sk = await key($).catch(() => undefined)
      if (!sk) return { text: 'Unlock the vault first (`/vault unlock`).' }
      await openPane($, 'set', kr.passphrase ? 'Choose a new passphrase (8+ characters).' : 'Choose a passphrase (8+ characters). If you lose it, your encrypted history cannot be recovered.')
      return { text: 'Choose a passphrase in the pane.' + typedSecret }
    }

    return { text: HELP }
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text, Input, Button } = $.ui.resolve(e)
    const len = await read($, typedLen)
    const s = await read($, stage)
    const message = await read($, note)
    const track = (value: string) => {
      // The field shows dots; keep the real text here. Typing at the end and
      // backspace are tracked; editing in the middle is not supported.
      if (value.length >= typed.length) typed += value.slice(typed.length)
      else typed = typed.slice(0, value.length)
      void update($, typedLen, () => typed.length)
    }
    return (
      <Box flexDirection="column">
        <Text bold>{s === 'unlock' ? 'Unlock vault' : s === 'set' ? 'Set vault passphrase' : 'Confirm passphrase'}</Text>
        <Input
          key="passphrase"
          label="Passphrase: "
          value={DOT.repeat(len)}
          autoFocus
          submitLabel={s === 'unlock' ? 'unlock' : 'next'}
          onInput={track}
          onSubmit={value => {
            track(value)
            const entered = typed
            typed = ''
            void update($, typedLen, () => 0)
            void finishPassphrase($, entered).catch(err => update($, note, () => `Error: ${String((err as Error).message ?? err).slice(0, 200)}`))
          }}
        />
        {message ? <Text dimColor>{message}</Text> : null}
        <Button key="cancel" label="Cancel" role="dismiss" onPress={() => { typed = ''; firstEntry = undefined; void $.ui.close({ id: PANE }) }} />
      </Box>
    )
  })

  on('tool.call', { tool: /^mcp__transcript-vault__search_vault$/ }, async ($, e) => {
    const input = e as unknown as { query?: string; allProjects?: boolean; limit?: number }
    const query = String(input.query ?? '').trim()
    if (!query) return { deny: 'query is required' }
    const sk = await key($).catch(() => undefined)
    if (!sk) return { deny: 'The vault is locked. Ask the user to run `/vault unlock`, then try again.' }
    const limit = Math.min(50, Math.max(1, Number(input.limit ?? 20)))
    const out: string[] = []
    let searched = 0
    for (const item of await vaults($, input.allProjects === true)) {
      if (out.length >= limit) break
      searched++
      try {
        const bytes = await core.readVault(await io($), sk, item.path, item.sid)
        for (const h of core.searchRows(bytes, query, limit - out.length)) out.push(`[${item.sid}${input.allProjects ? ` ${item.project}` : ''} ${h.timestamp ?? ''} ${h.role}] ${h.snippet}`)
      } catch { /* an unreadable vault is skipped */ }
    }
    return { result: out.length ? `${out.length} match(es) in ${searched} encrypted session(s):\n${out.join('\n')}` : `No matches for "${query}" in ${searched} encrypted session(s).` }
  }).catch(() => ({ deny: 'transcript-vault: the search failed.' }))
}

const HELP = [
  '**transcript-vault** encrypts idle Claude Code transcripts on disk.',
  '- `/vault setup`: create the key and start encrypting idle sessions',
  '- `/vault status`: key mode, locked or not, counts',
  '- `/vault lock`: encrypt every session but this one now',
  '- `/vault list [all]`: encrypted sessions for this project (or all)',
  '- `/vault open <n|id>`: decrypt one so `/resume` can load it (`all`: decrypt everything and stop locking)',
  '- `/vault unlock`: enter your passphrase (passphrase mode)',
  '- `/vault passphrase`: set or change the passphrase',
].join('\n')
