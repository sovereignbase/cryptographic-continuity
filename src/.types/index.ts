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

export type VerconAssertionMethod = {
  keypairIdentifier: Base64URLString
  signKey: SignKey
}

export type VerconVerificationMethod = {
  keypairIdentifier: Base64URLString
  verifyKey: VerifyKey
  since: number
}

export type VerconVerificationMethodsEntry = {
  verificationMethod: VerconVerificationMethod
  proof: Base64URLString
}

export type VerconState = {
  assertionMethod: CRStruct<VerconAssertionMethod>
  verificationMethods: CRList<VerconVerificationMethodsEntry>
}

export type VerconSnapshot = {
  assertionMethod: CRStructSnapshot<VerconAssertionMethod>
  verificationMethods: CRListSnapshot<VerconVerificationMethodsEntry>
}

export type VerconDelta = Partial<VerconSnapshot>

export type VerconDataToBeSigned = {
  kind: 'vcs'
  asserts: unknown
  assertedAt: number
  keypairIdentifier: VerconAssertionMethod['keypairIdentifier']
  verificationMethods: VerconSnapshot['verificationMethods']
}

export type VerconSignature = VerconDataToBeSigned & {
  proof: Base64URLString
}
