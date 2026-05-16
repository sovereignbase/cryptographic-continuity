import { Cryptographic, SignKey, VerifyKey } from '@sovereignbase/cryptosuite'
import type {
  CrypconVerificationMethod,
  CrypconVerificationMethodsEntry,
} from '../../.types/type.js'
import { canonicalize } from 'json-canonicalize'
import { Bytes } from '@sovereignbase/bytecodec'

export async function createVerificationMethodsEntry(
  signKey: SignKey,
  verifyKey: VerifyKey
): Promise<CrypconVerificationMethodsEntry> {
  const verifyKeyBytes = Bytes.fromString(canonicalize(verifyKey))

  const verificationMethod: CrypconVerificationMethod = {
    keypairIdentifier: await Cryptographic.identifier.derive(verifyKeyBytes),
    verifyKey,
    since: Date.now(),
  }

  const authorization = Bytes.toBase64UrlString(
    await Cryptographic.digitalSignature.sign(
      signKey,
      Bytes.fromString(canonicalize(verificationMethod))
    )
  )

  return {
    verificationMethod,
    authorization,
  }
}
