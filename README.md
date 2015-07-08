[![Build Status](https://travis-ci.org/twittner/proteus.svg?branch=develop)][1]

`libproteus` is an implementation of the [axolotl protocol][2] without header
keys. It is suitable for use in asynchronous environments through its use of
[prekeys][3].

The roles of the axolotl protocol for a particular session are fixed through
the use of prekeys:

  * The side that obtains a prekey and uses it to initiate a session is `Alice`.
  * The side that receives a prekey message and uses it to initiate a session is `Bob`.

All cryptographic primitives used in the implementation of the protocol are
provided by [libsodium][4]:

  * Cipher: [XSalsa20][5]
  * Diffie-Hellman: [Curve25519][6]
  * KDF: [HKDF][7] ([implementation][8])

[1]: https://travis-ci.org/twittner/proteus
[2]: https://github.com/trevp/axolotl/wiki
[3]: https://whispersystems.org/blog/asynchronous-security/
[4]: https://github.com/jedisct1/libsodium
[5]: http://en.wikipedia.org/wiki/Salsa20
[6]: http://en.wikipedia.org/wiki/Curve25519
[7]: https://tools.ietf.org/html/rfc5869
[8]: https://github.com/twittner/hkdf
