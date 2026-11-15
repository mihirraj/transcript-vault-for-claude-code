import { expect, mock, test } from 'claude-code/testing'

// Obviously fake test keys, built from pieces so secret scanners do not
// mistake them for real ones. They only need the shape the masker matches.
const FAKE_ANTHROPIC = 'sk-ant-' + 'FAKE-not-a-real-key-0000000000'
const FAKE_AWS = 'AKIA' + 'FAKEFAKEFAKEFAKE'
const FAKE_GITHUB = 'ghp_' + 'FAKE'.repeat(9)
const FAKE_SLACK = 'xoxb-' + 'FAKE-0000000000'


// The kit has no file system or processes, so these tests cover what the
// plugin decides on its own. core.mjs is covered against real files by the
// Node harness in test/core.integration.mjs.

test('secrets are masked as rows are saved, when masking is on', { options: { maskSecrets: true } }, async ($, on) => {
  const session = mock.session(on)
  await $.session.append({
    message: {
      type: 'user',
      content: [{ type: 'text', text: `my key is ${FAKE_ANTHROPIC} and ${FAKE_AWS}` }],
    },
  } as never)
  const text = JSON.stringify(session.appended().at(-1)?.message.content)
  expect(text).toContain('[REDACTED:anthropic-key]')
  expect(text).toContain('[REDACTED:aws-access-key]')
  expect(text.includes(FAKE_ANTHROPIC)).toBe(false)
})

test('rows are left alone when masking is off (the default)', async ($, on) => {
  const session = mock.session(on)
  await $.session.append({
    message: { type: 'user', content: [{ type: 'text', text: `token ${FAKE_GITHUB}` }] },
  } as never)
  expect(JSON.stringify(session.appended().at(-1)?.message.content)).toContain(FAKE_GITHUB)
})

test('nothing is encrypted until /vault setup; the command says so', async ($, on) => {
  mock.store(on)
  mock.env(on, { HOME: '/home/test' })
  on('fs.exists', () => ({ value: false })) // no vault.json yet
  const out = await $.command.run({ command: "vault", args: "list" } as never)
  expect(String((out as { text?: string }).text)).toContain('not set up yet')
})

test('a key record from v0.1.0 (plugin store) is moved to vault.json, not lost', async ($, on) => {
  const legacy = { v: 1, pk: 'AAAA', createdAt: 1, passphrase: { kdf: 'scrypt' } }
  mock.store(on, { keyring: legacy, enabled: true })
  mock.env(on, { HOME: '/home/test' })
  const written: Record<string, string> = {}
  on('fs.exists', ($, e) => ({ value: (e as { path: string }).path in written }))
  on('fs.read', ($, e) => ({ value: written[(e as { path: string }).path] ?? '' }))
  on('fs.write', ($, e) => { const w = e as { path: string; text: string }; written[w.path] = w.text; return { value: undefined } })
  on('fs.list', () => ({ value: [] }))
  on('session.cwd', () => ({ value: '/home/test/proj' }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: 'Linux\n', stderr: '', isStdoutTruncated: false, isStderrTruncated: false } }))
  const out = await $.command.run({ command: "vault", args: "list" } as never)
  expect(String((out as { text?: string }).text).includes('not set up')).toBe(false)
  // the engine normalizes paths for the platform, so match on the ending
  const name = Object.keys(written).find(p => /[\\/]\.claude[\\/]transcript-vault[\\/]vault\.json$/.test(p))
  expect(name).toBeDefined()
  const file = written[name!] ?? '{}'
  expect(JSON.parse(file).keyring.pk).toBe('AAAA')
  expect(JSON.parse(file).enabled).toBe(true)
})

test('the search tool refuses while there is no key', async ($, on) => {
  mock.store(on)
  const r = await $.tool.call({ tool: 'mcp__transcript-vault__search_vault', query: 'anything' } as never)
  expect(JSON.stringify(r)).toContain('locked')
})
