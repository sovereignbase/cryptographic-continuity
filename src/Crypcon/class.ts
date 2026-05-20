import { CRList, CRListAck } from '@sovereignbase/convergent-replicated-list'
import type {
  CrypconSnapshot,
  CrypconAssertion,
  CrypconDataToBeSigned,
  CrypconVerificationMethodsEntry,
  CrypconAssertionMethod,
  CrypconEventMap,
  CrypconEventListenerFor,
} from '../.types/type.js'
import {
  Cryptographic,
  type OpaqueIdentifier,
  type SignKey,
  type VerifyKey,
} from '@sovereignbase/cryptosuite'
import {
  CRStruct,
  CRStructAck,
} from '@sovereignbase/convergent-replicated-struct'
import { createVerificationMethodsEntry } from '../.helpers/index.js'
import { canonicalize } from 'json-canonicalize'
import { Bytes } from '@sovereignbase/bytecodec'
import { CRMap, type CRMapAck } from '@sovereignbase/convergent-replicated-map'
import { CrypconError } from '../.errors/class.js'
import { FrontierStore } from '@sovereignbase/frontier-store'

export class Crypcon {
  declare private static readonly id: OpaqueIdentifier
  declare private static readonly eventTarget: EventTarget
  declare private static readonly frontierStore: FrontierStore
  declare public static readonly trustedKeyStore: CRMap<VerifyKey>
  declare private static readonly assertionMethod: CRStruct<CrypconAssertionMethod>
  declare public static readonly verificationMethods: CRList<CrypconVerificationMethodsEntry>

  public static async initialize(snapshot?: CrypconSnapshot) {
    void Object.defineProperty(this, 'id', {
      value: snapshot?.id ?? Cryptographic.identifier.generate(),
      enumerable: false,
      writable: false,
      configurable: false,
    })
    void Object.defineProperty(this, 'eventTarget', {
      value: new EventTarget(),
      enumerable: false,
      writable: false,
      configurable: false,
    })
    void Object.defineProperty(this, 'frontierStore', {
      value: new FrontierStore(snapshot?.frontierStore),
      enumerable: false,
      writable: false,
      configurable: false,
    })
    void Object.defineProperty(this, 'trustedKeyStore', {
      value: new CRMap<VerifyKey>(snapshot?.trustedKeyStore),
      enumerable: false,
      writable: false,
      configurable: false,
    })
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
      void this.continue()
    }

    const crdtProps = [
      'trustedKeyStore',
      'assertionMethod',
      'verificationMethods',
    ] as const

    for (const prop of crdtProps) {
      void this[prop].addEventListener('change', async () => {
        void this[prop].acknowledge()
        void this.eventTarget.dispatchEvent(
          new CustomEvent('snapshot', { detail: this.toJSON() })
        )
      })

      void this[prop].addEventListener('ack', async (event: unknown) => {
        switch (prop) {
          case 'assertionMethod': {
            const kind = 'struct'
            const targetId = 'crypcon.assertionMethod'
            const { detail } = event as CustomEvent<
              CRStructAck<{
                keypairIdentifier: OpaqueIdentifier
                signKey: SignKey
              }>
            >
            void this.frontierStore.set(kind, targetId, this.id, detail)

            void this.assertionMethod.garbageCollect(
              this.frontierStore.get(kind, targetId)
            )
            break
          }
          case 'trustedKeyStore': {
            const kind = 'map'
            const targetId = 'crypcon.trustedKeyStore'
            const { detail } = event as CustomEvent<CRMapAck>

            void this.frontierStore.set(kind, targetId, this.id, detail)
            void this.trustedKeyStore.garbageCollect(
              this.frontierStore.get(kind, targetId)
            )
            break
          }
          case 'verificationMethods': {
            const kind = 'list'
            const targetId = 'crypcon.verificationMethods'
            const { detail } = event as CustomEvent<CRListAck>
            void this.frontierStore.set(
              'list',
              'crypcon.verificationMethods',
              this.id,
              detail
            )
            void this.verificationMethods.garbageCollect(
              this.frontierStore.get(kind, targetId)
            )
            break
          }
        }
      })
    }
  }

  /**
   * @param data - JSON Compatible data you want to be backed by identity
   */
  public static async assert(data: unknown): Promise<CrypconAssertion> {
    if (!this.assertionMethod || !this.verificationMethods)
      throw new CrypconError('NOT_INITIALIZED')

    const dtbs: CrypconDataToBeSigned = {
      type: 'CryptographicContinuityAssertion',
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
   * @param assertion expected Crypcon assertion your application needs to verify
   * @param assertingEntityIdentifier the claiemed identity of the asserter known to you your application perhaps via information in the assertion `asserts` property
   * @returns a boolean indicating wheter a trustedkey for the entity was known and it verified up to the assertion if true the trustedKey store gets updated automatically if false there is a verifyKey provided if in the second index if the verification methods had one. So you can let your user decide wheter to trust or not and then on user intent store to the trusted key store
   */
  public static async verify(
    assertion: CrypconAssertion,
    assertingEntityIdentifier: string
  ): Promise<[true, undefined] | [false, VerifyKey | undefined]> {
    if (!this.trustedKeyStore) throw new CrypconError('NOT_INITIALIZED')

    if (assertion.type !== 'CryptographicContinuityAssertion')
      throw new CrypconError('WRONG_ASSERTION_TYPE')

    const view = new CRList<CrypconVerificationMethodsEntry>(
      assertion.verificationMethods
    )

    const latestVerifyKey: VerifyKey =
      view[view.size - 1].verificationMethod.verifyKey

    const trustedVerifyKey = this.trustedKeyStore.get(assertingEntityIdentifier)
    if (!trustedVerifyKey) return [false, latestVerifyKey]

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

    if (index === undefined) return [false, latestVerifyKey]

    while (trustCheckpoint) {
      index++
      const current = trustCheckpoint
      const next = view[index]

      if (
        assertion.keypairIdentifier ===
        current.verificationMethod.keypairIdentifier
      ) {
        if (
          !(
            current.verificationMethod.since < assertion.assertedAt &&
            (!next || next.verificationMethod.since > assertion.assertedAt)
          )
        )
          return [false, latestVerifyKey]

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

        if (authorized)
          void this.trustedKeyStore.set(
            assertingEntityIdentifier,
            current.verificationMethod.verifyKey
          )

        return authorized ? [true, undefined] : [false, latestVerifyKey]
      }

      const protectedBytes = Bytes.fromString(
        canonicalize(next.verificationMethod)
      )

      const continues = await Cryptographic.digitalSignature.verify(
        current.verificationMethod.verifyKey,
        protectedBytes,
        Bytes.fromBase64UrlString(next.authorization)
      )

      if (!continues) return [false, latestVerifyKey]

      trustCheckpoint = next
    }

    return [false, latestVerifyKey]
  }

  /**
   * Continues the protection of the current assertionMethod in to a new assertionMethod
   */
  public static async continue(): Promise<void> {
    if (!this.verificationMethods || !this.assertionMethod)
      throw new CrypconError('NOT_INITIALIZED')

    const { signKey, verifyKey } =
      await Cryptographic.digitalSignature.generateKeypair()

    const verificationMethodsEntry: CrypconVerificationMethodsEntry =
      await createVerificationMethodsEntry(signKey, verifyKey)

    void this.verificationMethods.append(verificationMethodsEntry)

    this.assertionMethod.keypairIdentifier =
      verificationMethodsEntry.verificationMethod.keypairIdentifier

    this.assertionMethod.signKey = signKey
  }

  public static async merge(snapshot?: CrypconSnapshot): Promise<void> {}

  /**
   * Registers an event listener.
   *
   * @param type - The event type to listen for.
   * @param listener - The listener to register.
   * @param options - Listener registration options.
   */
  public static addEventListener<K extends keyof CrypconEventMap>(
    type: K,
    listener: CrypconEventListenerFor<K> | null,
    options?: boolean | AddEventListenerOptions
  ): void {
    void this.eventTarget.addEventListener(
      type,
      listener as EventListenerOrEventListenerObject | null,
      options
    )
  }

  /**
   * Removes an event listener.
   *
   * @param type - The event type to stop listening for.
   * @param listener - The listener to remove.
   * @param options - Listener removal options.
   */
  public static removeEventListener<K extends keyof CrypconEventMap>(
    type: K,
    listener: CrypconEventListenerFor<K> | null,
    options?: boolean | EventListenerOptions
  ): void {
    void this.eventTarget.removeEventListener(
      type,
      listener as EventListenerOrEventListenerObject | null,
      options
    )
  }

  /**
   * Returns a serializable snapshot.
   *
   * Snapshot value payloads are live references. Mutating them can mutate
   * replica state without emitting a delta.
   *
   * Called automatically by `JSON.stringify`.
   */
  public static toJSON(): CrypconSnapshot {
    return {
      id: this.id,
      frontierStore: this.frontierStore.snapshot(),
      trustedKeyStore: this.trustedKeyStore.toJSON(),
      assertionMethod: this.assertionMethod.toJSON(),
      verificationMethods: this.verificationMethods.toJSON(),
    }
  }
  /**
   * Attempts to return this list snapshot as a JSON string.
   *
   * This can fail when values are not JSON-compatible.
   */
  public static toString(): string {
    return JSON.stringify(this)
  }
  /**
   * Returns the Node.js console inspection representation.
   */
  public static [Symbol.for('nodejs.util.inspect.custom')](): CrypconSnapshot {
    return this.toJSON()
  }
  /**
   * Returns the Deno console inspection representation.
   */
  public static [Symbol.for('Deno.customInspect')](): CrypconSnapshot {
    return this.toJSON()
  }
}
