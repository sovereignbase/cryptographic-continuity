import { CRStruct } from '@sovereignbase/convergent-replicated-struct'
import { CRList } from '@sovereignbase/convergent-replicated-list'
import type {
  VerconSnapshot,
  VerconState,
  VerconVerificationMethodsEntry,
} from '../../../.types/index.js'
import { prototype } from '@sovereignbase/utils'
import { Cryptographic, SignKey } from '@sovereignbase/cryptosuite'

export async function __create(
  snapshot?: VerconSnapshot
): Promise<VerconState> {
  let verificationMethods = new CRList<VerconVerificationMethodsEntry>(
    snapshot?.verificationMethods
  )

  const assertionMethod = new CRStruct<{
    keypairIdentifier: Base64URLString
    signKey: SignKey
  }>(
    { keypairIdentifier: '', signKey: {} as SignKey },
    snapshot?.assertionMethod
  )

  if (!assertionMethod.signKey) {
    const { signKey, verifyKey } =
      await Cryptographic.digitalSignature.generateKeypair()
    const keypairIdentifier = await Cryptographic.identifier.generate()
    assertionMethod.keypairIdentifier = keypairIdentifier
    assertionMethod.signKey = signKey

    const verificationMethod = {keypairIdentifier,verifyKey,since: Math.floor(Date.now() /1000)}
    const verification

    verificationMethods = new CRList<VerconVerificationMethodsEntry>()
    verificationMethods.append({})
  }

  return { assertionMethod, verificationMethods }
}
