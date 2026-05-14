import { Cryptographic, VerifyKey } from '@sovereignbase/cryptosuite'
import {
  VERCONDataToBeSinged,
  VERCONSignature,
  VERCONState,
  VERCONStateEntry,
} from '../../../.types/index.js'
import {
  __create,
  __read,
  CRListStateEntry,
} from '@sovereignbase/convergent-replicated-list'
import { Bytes } from '@sovereignbase/bytecodec'
import { canonicalize } from 'json-canonicalize'
import { safeStructuredClone } from '@sovereignbase/utils'

export async function __verify(
  trustedKey: VerifyKey,
  verconSignature: VERCONSignature
): Promise<boolean> {
  if (
    verconSignature.kind !== 'vcs' ||
    typeof verconSignature.assertedAt !== 'number' ||
    typeof verconSignature.proof !== 'string'
  )
    return false

  const [cloned, copiedSignature] = safeStructuredClone(verconSignature)

  if (!cloned) return false

  const verifiableContinuity = __create(copiedSignature.verificationMethod)

  if (!verifiableContinuity.cursor) return false

  void __read(0, verifiableContinuity)

  const trustedKeyId = await Cryptographic.identifier.derive(
    Bytes.fromString(canonicalize(trustedKey))
  )

  while (verifiableContinuity.cursor.value.state.keyId !== trustedKeyId) {
    if (!verifiableContinuity.cursor.next) return false
    verifiableContinuity.cursor = verifiableContinuity.cursor.next
  }

  while (verifiableContinuity.cursor.next) {
    const next: CRListStateEntry<VERCONStateEntry> =
      verifiableContinuity.cursor.next
    const verifyKey = verifiableContinuity.cursor.value.state.verifyKey
    const nextStateCanonicalizedBytes = Bytes.fromString(
      canonicalize(next.value.state)
    )
    const canTrustNext = await Cryptographic.digitalSignature.verify(
      verifyKey,
      nextStateCanonicalizedBytes,
      Bytes.fromBase64UrlString(next.value.proof)
    )

    if (!canTrustNext) return false

    verifiableContinuity.cursor = next

    if (
      verifiableContinuity.cursor.value.state.since <
        copiedSignature.assertedAt &&
      verifiableContinuity.cursor.next &&
      verifiableContinuity.cursor.next.value.state.since >
        copiedSignature.assertedAt
    )
      break
  }

  const verifyKey = verifiableContinuity.cursor.value.state.verifyKey
  const proofBytes = Bytes.fromBase64UrlString(copiedSignature.proof)
  const { kind, asserts, assertedAt, verificationMethod } = copiedSignature
  const assertionBytes = Bytes.fromString(
    canonicalize({
      kind,
      asserts,
      assertedAt,
      verificationMethod,
    } satisfies VERCONDataToBeSinged)
  )

  return await Cryptographic.digitalSignature.verify(
    verifyKey,
    assertionBytes,
    proofBytes
  )
}
