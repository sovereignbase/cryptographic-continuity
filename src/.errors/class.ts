export type CrypconErrorCode = 'NOT_INITIALIZED'

export class CrypconError extends Error {
  readonly code: CrypconErrorCode

  constructor(code: CrypconErrorCode, message?: string) {
    const detail = message ?? code
    super(`{@sovereignbase/cryptographic-continuity} ${detail}`)
    this.code = code
    this.name = 'CrypconError'
  }
}
