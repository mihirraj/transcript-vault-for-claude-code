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
  const out = await $.command.run({ command: "vault", args: "list" } as never)
  expect(String((out as { text?: string }).text)).toContain('not set up yet')
})

test('the search tool refuses while there is no key', async ($, on) => {
  mock.store(on)
  const r = await $.tool.call({ tool: 'mcp__transcript-vault__search_vault', query: 'anything' } as never)
  expect(JSON.stringify(r)).toContain('locked')
})
