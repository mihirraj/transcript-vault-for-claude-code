export type Platform = 'windows' | 'mac' | 'linux'
export type IoEntry = { name: string; kind: 'file' | 'directory' | 'other'; size: number; mtimeMs: number }
export type IoRunResult = { exitCode: number; stdout: string; stderr: string }
export type Io = {
  platform: Platform
  user: string
  readBytes(path: string): Promise<Uint8Array>
  readText(path: string): Promise<string>
  write(path: string, text: string): Promise<void>
  list(dir: string): Promise<IoEntry[]>
  stat(path: string): Promise<{ kind: string; size: number; mtimeMs: number }>
  exists(path: string): Promise<boolean>
  run(argv: readonly string[], init?: { env?: Record<string, string>; stdin?: string; timeoutMs?: number }): Promise<IoRunResult>
}
export type Item = {
  kind: 'plain' | 'vault'
  project: string
  dir: string
  sid: string
  path: string
  size?: number
  mtimeMs: number
}
export type Segment = { f: string; sid: string; i: number; epk: string; n: string; c: string }
export type PassphraseWrap = { kdf: 'scrypt'; N: number; r: number; p: number; salt: string; n: string; c: string }
export type KeystoreEntry = { kind: 'dpapi' | 'keychain' | 'secret-tool'; blob?: string }
export type Block = { type: string; text?: string; content?: unknown; [k: string]: unknown }

export const FORMAT: string
export const SEG_BYTES: number
export const SESSION_FILE: RegExp
export const VAULT_DIR: RegExp
export const SECRET_PATTERNS: [string, RegExp][]

export function b64(bytes: Uint8Array): string
export function unb64(text: string): Uint8Array
export function concat(parts: Uint8Array[]): Uint8Array

export function newKeypair(): { sk: Uint8Array; pk: Uint8Array }
export function newKeypairFrom(sk: Uint8Array): { sk: Uint8Array; pk: Uint8Array }
export function sealSegment(pk: Uint8Array, plaintext: Uint8Array, sid: string, index: number): Segment
export function openSegment(sk: Uint8Array, seg: Segment, sid: string, index: number): Uint8Array
export function wrapWithPassphrase(sk: Uint8Array, passphrase: string): Promise<PassphraseWrap>
export function unwrapWithPassphrase(wrap: PassphraseWrap, passphrase: string): Promise<Uint8Array>

export function removePath(io: Io, path: string): Promise<void>
export function movePath(io: Io, from: string, to: string): Promise<void>
export function readFileBytes(io: Io, path: string, size: number): Promise<Uint8Array>

export function keystoreKind(io: Io): KeystoreEntry['kind']
export function keystoreSave(io: Io, sk: Uint8Array): Promise<KeystoreEntry>
export function keystoreLoad(io: Io, entry: KeystoreEntry): Promise<Uint8Array>
export function keystoreForget(io: Io, entry: KeystoreEntry): Promise<void>

export function scan(io: Io, projectsDir: string): Promise<Item[]>
export function lockSession(io: Io, pk: Uint8Array, item: Item): Promise<'locked' | 'busy' | 'interrupted'>
export function readVault(io: Io, sk: Uint8Array, vaultPath: string, sid: string): Promise<Uint8Array>
export function openSession(io: Io, sk: Uint8Array, item: Item): Promise<string>

export function rows(bytes: Uint8Array): any[]
export function summarize(bytes: Uint8Array): { title: string; cwd?: string; first?: string; last?: string; messages: number }
export function searchRows(bytes: Uint8Array, query: string, max: number): { role: string; timestamp?: string; snippet: string }[]

export function maskSecrets(text: string): { text: string; count: number }
export function maskContent<T extends Block>(content: T[]): { content: T[]; count: number } | null
export function writeText(io: Io, path: string, text: string): Promise<void>
