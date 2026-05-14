import { Cryptographic, type SignKey } from '@sovereignbase/cryptosuite'
import type {
  VerconDataToBeSigned,
  VerconSignature,
  VerconState,
  VerconVerificationMethodEntry,
} from '../../../.types/index.js'
import { canonicalize } from 'json-canonicalize'
import { __snapshot } from '@sovereignbase/convergent-replicated-list'
import { Bytes } from '@sovereignbase/bytecodec'

export async function __assert(
  claims: unknown,
  signKey: SignKey,
  verconReplica: VerconState
): Promise<VerconSignature> {
  const verificationMethods =  verconReplica.verificationMethods.snapshot()
  const dataToBeSinged: VerconDataToBeSigned = {
    kind: 'vcs',
    asserts: claims,
    assertedAt: Math.floor(Date.now() / 100),
    keypairIdentifier:
      verconReplica.assertionMethod.entries.keypairIdentifier.value,
    verificationMethods,
  }
  const canonicalizedBytes = Bytes.fromString(canonicalize(dataToBeSinged))

  const signature = await Cryptographic.digitalSignature.sign(
    signKey,
    canonicalizedBytes
  )

  return {
    ...dataToBeSinged,
    proof: Bytes.toBase64UrlString(signature),
  }
}
