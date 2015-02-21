# Proteus

`proteus` is an implementation of the [axolotl protocol](https://github.com/trevp/axolotl/wiki) without header keys [1].
It is suitable for use in asynchronous environments through its use of [prekeys](https://whispersystems.org/blog/asynchronous-security/
) [2].

## Implementation Details

### Roles

The roles of the axolotl protocol for a particular session are fixed through the use of prekeys:

  * The side that obtains a prekey and uses it to initiate a session is `Alice`.
  * The side that receives a prekey message and uses it to initiate a session is `Bob`.

### Cryptographic Building Blocks

All cryptographic primitives used in the implementation of the protocol are provided by [libsodium](https://github.com/jedisct1/libsodium).

  * Cipher: [XSalsa20](http://en.wikipedia.org/wiki/Salsa20)
  * Diffie-Hellman: [Curve25519](http://en.wikipedia.org/wiki/Curve25519)
  * KDF: [HKDF](https://tools.ietf.org/html/rfc5869) ([implementation](https://github.com/twittner/hkdf))

## References

[1] https://github.com/trevp/axolotl/wiki

[2] https://whispersystems.org/blog/asynchronous-security/

