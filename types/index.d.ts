export type VaultStage = 'unlock' | 'set' | 'confirm'

declare module 'claude-code' {
  interface PluginState {
    'transcript-vault': { typedLen: number; stage: VaultStage; note: string }
  }
}
