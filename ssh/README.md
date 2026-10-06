# crown-ssh

An SSH client built on [libssh2](https://libssh2.org) whose cryptography is
provided by [crown](../) / crown-cabi via libssh2's pluggable crypto backend
interface, instead of OpenSSL, mbedTLS, libgcrypt, wolfSSL or WinCNG.

This directory is a self-contained CMake project (its own build workspace, not
part of the cargo workspace). It builds:

- **libssh2** at a pinned release tag, fetched and patched to register the
  `Crown` crypto engine,
- **the crown backend** (`backend/libssh2_crown.{h,c}`), a libssh2 crypto
  backend implemented entirely against the crown-cabi C ABI,
- **crown-ssh**, a small client that exercises the backend end to end.

## Build

```sh
cmake -S ssh -B ssh/build
cmake --build ssh/build -j
ssh/build/crown-ssh -v user@host 'uname -a'
```

The build needs cargo (it compiles crown-cabi into a static library), a C
compiler and network access for the initial libssh2 checkout.

Options:

- `-DCROWN_SSH_LIBSSH2_TAG=<tag>`: libssh2 release to build against
  (default `libssh2-1.11.1`).
- `-DENABLE_DEBUG_LOGGING=ON`: build libssh2 with tracing; `crown-ssh -v`
  then dumps the protocol trace.

## What runs on crown

Everything the backend contract covers:

| Layer | Algorithms |
| --- | --- |
| Key exchange | curve25519-sha256(+@libssh.org), ecdh-sha2-nistp256/384/521, diffie-hellman-group14-sha256, group16-sha512, group18-sha512, group-exchange-sha256 |
| Host keys | ssh-ed25519, ecdsa-sha2-nistp256/384/521, rsa-sha2-512/256 |
| Ciphers | chacha20-poly1305@openssh.com, aes128/192/256-ctr, aes128/192/256-cbc |
| MACs | hmac-sha2-256/512, hmac-sha1 |
| Authentication | password, publickey (Ed25519, ECDSA P-256/384/521, RSA) |

`chacha20-poly1305@openssh.com` is implemented inside libssh2 itself, so only
the surrounding cipher plumbing is crown's. AES-GCM and ML-KEM are not wired
yet: GCM needs the SSH packet semantics (`aes*-gcm@openssh.com`), and the
pinned libssh2 1.11.1 has no ML-KEM hooks (they arrived on master, headed for
1.12). The crown-cabi exports they would need already exist.

RSA-SHA1 is enabled (`LIBSSH2_RSA_SHA1`): libssh2 1.11.1 only accepts the
`ssh-rsa` host key blob type when it is on, and RFC 8332 keeps that type even
for rsa-sha2-* signatures. The method table lists rsa-sha2-512/256 before
ssh-rsa, so SHA-1 signatures are only negotiated with servers that offer
nothing better.

## Layout

```
ssh/
├── CMakeLists.txt              build: cargo (crown-cabi) + libssh2 + backend + CLI
├── backend/libssh2_crown.h     type/macro mapping for the libssh2 contract
├── backend/libssh2_crown.c     the backend itself
├── patches/libssh2-crown.patch libssh2 build/dispatch changes (3 files)
├── cli/ssh.c                   crown-ssh client
└── tests/e2e.sh                algorithm matrix against a real sshd
```

## Tests

`tests/e2e.sh` walks the matrix above against a running SSH server: every case
performs a full handshake, an authenticated exec and checks the output. CI
starts an OpenSSH container for it:

```sh
docker run -d --name crown-ssh-e2e -p 2222:2222 <test image>   # see CI workflow
SSH_TEST_CONTAINER=crown-ssh-e2e ssh/tests/e2e.sh
```

Environment: `SSH_TEST_HOST`, `SSH_TEST_PORT`, `SSH_TEST_USER`,
`SSH_TEST_PASSWORD`, `SSH_TEST_CONTAINER`.

## Implementation notes

- **Contract**: libssh2's `src/HACKING-CRYPTO.md` plus the declarations in
  `src/crypto.h`. The patch that registers the engine touches only
  `src/crypto.h` (dispatch), `include/libssh2.h` (engine enum) and
  `CMakeLists.txt` (backend selection).
- **Hash asymmetry**: libssh2 pre-hashes for RSA signatures but hands
  verification data unhashed; ECDSA gets unhashed data in both directions.
  The backend hashes accordingly (`crown_hash_by_digest_len`,
  `crown_ecdsa_digest`).
- **CBC padding**: SSH pads its own packets, so the backend uses crown-cabi's
  padding-free CBC (`crown_cbc_new_aes` / `crown_cbc_crypt`) rather than
  `EvpBlockCipher`, which always applies PKCS#7.
- **Key files**: OpenSSH-format private keys are parsed by libssh2 itself
  (including bcrypt-pbkdf for encrypted keys); the backend consumes the parsed
  components and builds the SSH public key blob. PKCS#1/PKCS#8 PEM files are
  not accepted yet.
- **RSA host key parsing**: requires `LIBSSH2_RSA_SHA1` (see above).
