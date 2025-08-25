# KittyCrypto

> Delivering a first-class cryptographic development experience.
> **API and documentation are first-class citizens** — clear, simple, and maintainable.

> [!IMPORTANT]
> ALL ALGORITHMS ARE IMPLEMENTED FOLLOWING STANDARD SPECIFICATIONS, BUT THE LIBRARY HAS NOT UNDERGONE A FORMAL SECURITY AUDIT.
>
> THE SOFTWARE IS PROVIDED AS-IS, WITHOUT ANY GUARANTEES OR WARRANTIES.
>
> THE AUTHORS ASSUME NO RESPONSIBILITY OR LIABILITY FOR ANY DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES RESULTING FROM THE USE OF THIS SOFTWARE.

Most of the code is derived from **Go**, with parts adapted from **LibTomCrypto**

## Features

* **API-first design**: clean and intuitive, minimal boilerplate
* **First-class documentation**: comprehensive guides, examples, and references to get you started quickly
* **Cross-compilation friendly**:
  * Uses `asm!()` inline assembly and runtime feature detection
  * No dependency on platform-specific toolchains (except for CUDA)
* **`no_std` support**: works in embedded and bare-metal environments. (in plan)
* **Modern cryptographic primitives**: symmetric/asymmetric encryption, hashing, AEAD

## Credits

- [Go/Crypto](https://github.com/golang/go/tree/master/src/crypto)
- [crypto](https://github.com/golang/crypto)
- [libtomlcrypto](https://github.com/libtom/libtomcrypt)
