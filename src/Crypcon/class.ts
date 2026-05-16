import { CRList } from '@sovereignbase/convergent-replicated-list'
import type {
  CrypconSnapshot,
  CrypconDelta,
  CrypconAssertion,
  CrypconDataToBeSigned,
  CrypconVerificationMethodsEntry,
  CrypconAssertionMethod,
} from '../.types/type.js'
import { Cryptographic, SignKey, VerifyKey } from '@sovereignbase/cryptosuite'
import { CRStruct } from '@sovereignbase/convergent-replicated-struct'
import { createVerificationMethodsEntry } from '../.helpers/index.js'
import { canonicalize } from 'json-canonicalize'
import { Bytes } from '@sovereignbase/bytecodec'
import { CRMap } from '@sovereignbase/convergent-replicated-map'

export class Crypcon {
  declare public static readonly trustedKeyStore: CRMap<VerifyKey>
  declare private static readonly assertionMethod: CRStruct<CrypconAssertionMethod>
  declare public static readonly verificationMethods: CRList<CrypconVerificationMethodsEntry>

  public static async initialize(snapshot?: CrypconSnapshot) {
    void Object.defineProperty(this, 'assertionMethod', {
      value: new CRStruct<{
        keypairIdentifier: unknown
        signKey: unknown
      }>(
        {
          keypairIdentifier: undefined,
          signKey: undefined,
        },
        snapshot?.assertionMethod
      ),
      enumerable: false,
      writable: false,
      configurable: false,
    })

    void Object.defineProperty(this, 'verificationMethods', {
      value: new CRList<CrypconVerificationMethodsEntry>(
        snapshot?.verificationMethods
      ),
      enumerable: false,
      writable: false,
      configurable: false,
    })

    if (
      typeof this.assertionMethod.keypairIdentifier !== 'string' ||
      typeof this.assertionMethod.signKey !== 'object' ||
      this.assertionMethod.signKey === undefined
    ) {
      const { signKey, verifyKey } =
        await Cryptographic.digitalSignature.generateKeypair()

      const verificationMethodsEntry: CrypconVerificationMethodsEntry =
        await createVerificationMethodsEntry(signKey, verifyKey)

      void this.verificationMethods.append(verificationMethodsEntry)

      ;((this.assertionMethod.keypairIdentifier =
        verificationMethodsEntry.verificationMethod.keypairIdentifier),
        (this.assertionMethod.signKey = signKey))
    }
  }

  /**
   * @param data - JSON Compatible data you want to be backed by identity
   */
  public static async assert(data: unknown): Promise<CrypconAssertion> {
    const dtbs: CrypconDataToBeSigned = {
      type: 'VerifiableContinuityAssertion',
      asserts: data,
      assertedAt: Date.now(),
      keypairIdentifier: this.assertionMethod.keypairIdentifier,
      verificationMethods: this.verificationMethods.toJSON(),
    }

    const authorization = Bytes.toBase64UrlString(
      await Cryptographic.digitalSignature.sign(
        this.assertionMethod.signKey,
        Bytes.fromString(canonicalize(dtbs))
      )
    )

    return {
      ...dtbs,
      authorization,
    }
  }

  /**
   * Continues the protection of the current signing key in to the new signing key
   * @param currentSignKey
   * @returns
   */
  async rotate(currentSignKey: SignKey) {}

  /**
   * Drops the specified amount verify keys and proofs from root.
   * !! CLAIMS SINGED WITH THE DROPPED KEYS BECOME UNVERIFIABLE AS WELL AS VERIFIERS WITH TRUSTING AN DROPPED KEY CANT VERIFY CONTINUITY!!
   * @param count
   */
  public static async erase(count: number) {}

  public static async merge() {}
  public static async snapshot() {}

  /**
   * @returns the latest verifiable key you trust or false inicating continuity couldn't be cryptographically verified
   */
  public static async verify(
    assertion: CrypconAssertion,
    trustedVerifyKey: VerifyKey
  ): Promise<VerifyKey | false> {
    const view = new CRList<CrypconVerificationMethodsEntry>(
      assertion.verificationMethods
    )
    let index: number | undefined = undefined
    let trustCheckpoint = view.find(async (entry, i) => {
      const trustedKeypairIdentifier = await Cryptographic.identifier.derive(
        Bytes.fromString(canonicalize(trustedVerifyKey))
      )
      index = i
      return (
        entry.verificationMethod.keypairIdentifier === trustedKeypairIdentifier
      )
    })

    if (index === undefined) return false

    while (trustCheckpoint) {
      index++
      const current = trustCheckpoint
      const next = view[index]

      if (
        current.verificationMethod.since < assertion.assertedAt &&
        (!next || next.verificationMethod.since > assertion.assertedAt)
      ) {
        const {
          type,
          asserts,
          assertedAt,
          authorization,
          keypairIdentifier,
          verificationMethods,
        } = assertion

        const protectedBytes = Bytes.fromString(
          canonicalize({
            type,
            asserts,
            assertedAt,
            keypairIdentifier,
            verificationMethods,
          })
        )

        const authorized = await Cryptographic.digitalSignature.verify(
          current.verificationMethod.verifyKey,
          protectedBytes,
          Bytes.fromBase64UrlString(authorization)
        )

        return authorized ? current.verificationMethod.verifyKey : false
      }

      const protectedBytes = Bytes.fromString(
        canonicalize(next.verificationMethod)
      )

      const continues = await Cryptographic.digitalSignature.verify(
        current.verificationMethod.verifyKey,
        protectedBytes,
        Bytes.fromBase64UrlString(next.authorization)
      )

      if (!continues) return false

      trustCheckpoint = next
    }

    return false
  }
}
