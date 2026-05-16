import type { SignKey, VerifyKey } from '@sovereignbase/cryptosuite'
import type {
  CRList,
  CRListSnapshot,
  CRListState,
} from '@sovereignbase/convergent-replicated-list'
import type {
  CRStruct,
  CRStructSnapshot,
  CRStructState,
} from '@sovereignbase/convergent-replicated-struct'

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

export type CrypconState = {
  assertionMethod: CRStruct<CrypconAssertionMethod>
  verificationMethods: CRList<CrypconVerificationMethodsEntry>
}

export type CrypconSnapshot = {
  assertionMethod: CRStructSnapshot<CrypconAssertionMethod>
  verificationMethods: CRListSnapshot<CrypconVerificationMethodsEntry>
}

export type CrypconDelta = Partial<CrypconSnapshot>

export type CrypconDataToBeSigned = {
  type: 'VerifiableContinuityAssertion'
  asserts: unknown
  assertedAt: number
  keypairIdentifier: CrypconAssertionMethod['keypairIdentifier']
  verificationMethods: CrypconSnapshot['verificationMethods']
}

export type CrypconAssertion = CrypconDataToBeSigned & {
  authorization: Base64URLString
}
