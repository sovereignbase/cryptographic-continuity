import type { SignKey, VerifyKey } from '@sovereignbase/cryptosuite'
import type { CRMapSnapshot } from '@sovereignbase/convergent-replicated-map'
import type { CRListSnapshot } from '@sovereignbase/convergent-replicated-list'
import type { CRStructSnapshot } from '@sovereignbase/convergent-replicated-struct'
import { FrontierStoreSnapshot } from '@sovereignbase/frontier-store'

export type CrypconAssertionMethod = {
  keypairIdentifier: Base64URLString
  signKey: SignKey
}

export type CrypconVerificationMethod = {
  keypairIdentifier: Base64URLString
  verifyKey: VerifyKey
  since: number
}

export type CrypconVerificationMethodsEntry = {
  verificationMethod: CrypconVerificationMethod
  authorization: Base64URLString
}

export type CrypconSnapshot = {
  frontierStore: FrontierStoreSnapshot
  trustedKeyStore: CRMapSnapshot<string, VerifyKey>
  assertionMethod: CRStructSnapshot<CrypconAssertionMethod>
  verificationMethods: CRListSnapshot<CrypconVerificationMethodsEntry>
}

export type CrypconDelta = Partial<CrypconSnapshot>

export type CrypconDataToBeSigned = {
  type: 'CryptographicContinuityAssertion'
  asserts: unknown
  assertedAt: number
  keypairIdentifier: CrypconAssertionMethod['keypairIdentifier']
  verificationMethods: CrypconSnapshot['verificationMethods']
}

export type CrypconAssertion = CrypconDataToBeSigned & {
  authorization: Base64URLString
}
