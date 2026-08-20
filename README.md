# wallet-descriptors

A Rust crate that turns Bitcoin **output descriptors** into derived addresses, for single-sig
and multisig. Watch-only by construction — it handles public key material exclusively and
contains no signing code.

> ### ⚠️ Status: design phase. There is no code in this repository yet.
>
> The input policy and supported script set below are **settled design decisions**, not
> shipped behaviour. Nothing here has been built or tested. **Do not point this at real
> funds** — there is nothing to point.

---

## What it does

Given a descriptor and an index, it gives you an address:

```
wsh(sortedmulti(2,xpub6C…/<0;1>/*,xpub6D…/<0;1>/*,xpub6E…/<0;1>/*))
   → receive 0..20, change 0..20
```

That is the whole job. It is deliberately a small crate that does one thing carefully,
because everything above it — wallet storage, address display, coin control, change
detection — is the same operation repeated, and all of it is wrong if this is wrong.

It ships as a **library** and a **thin CLI**.

## Why descriptors, and not just xpubs

Two facts pin the design:

- **A bare xpub does not encode a script type.** `xpub…` alone cannot tell you whether to
  emit `1…`, `3…`, `bc1q…` or `bc1p…`. All four are derivable from the same key, and they
  hold different money. SLIP-132 prefixes (`ypub`/`zpub`) do encode it, but they are
  non-standard and discouraged.
- **Multisig needs more than xpubs carry** — a threshold, key ordering (`sortedmulti` versus
  `multi`, per [BIP-67](https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki)), a
  script wrapper, and a derivation path per key.

Both are exactly what [output descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
exist to express. So descriptors are the canonical input, and the convenience path for bare
keys assembles a descriptor from explicit flags and echoes it back for you to verify and
save.

## Two ways in

- **Descriptor input** — you pass a complete descriptor string. It states the script type,
  the key ordering and the derivation paths itself.
- **Assembled input** — you pass bare keys plus explicit flags, and the crate assembles a
  descriptor, echoes it back, and derives from it. The descriptor is the thing you back up,
  so you are always shown the one that was built.

## Supported forms

An **allowlist**, not "whatever parses". Every supported form owes the test suite a vector,
and that promise cannot be made for a space too large to enumerate.

| Single-sig | Multisig |
|---|---|
| `pkh(KEY)` — `1…` | `wsh(sortedmulti(k,…))` — `bc1q…` |
| `sh(wpkh(KEY))` — `3…` | `sh(wsh(sortedmulti(k,…)))` — `3…` |
| `wpkh(KEY)` — `bc1q…` | `wsh(multi(k,…))` — `bc1q…` |
| `tr(KEY)` — `bc1p…` | `sh(multi(k,…))` — `3…` |
| | `tr(INTERNAL,multi_a(k,…))` — `bc1p…`, single leaf |

Anything else is refused **by name**, not with a generic parse error — including arbitrary
miniscript (timelocks, decaying policies), `combo()`, `addr()`, `raw()`, and bare
`pk()`/`multi()`. The allowlist grows purely additively, so a form added later breaks no
existing caller.

## Deliberate refusals

Each of these is a decision with a reason, not an omission:

- **SLIP-132 (`ypub`/`zpub`) is rejected everywhere**, with an error naming both the
  converted `xpub` and the script type the prefix implies. The information is preserved as a
  suggestion you affirm rather than a guess acted on silently.
- **Network is enforced, not reported.** A `tpub` descriptor will not quietly emit mainnet
  addresses. Granularity is xpub-versus-tpub; testnet, testnet4 and signet are
  indistinguishable and the crate does not pretend otherwise.
- **Multipath ([BIP-389](https://github.com/bitcoin/bips/blob/master/bip-0389.mediawiki)) is
  exactly two paths**, receive and change, and every key must be multipath or none is.
  Mixing means the change descriptor reuses a receive key — a privacy leak that looks like
  nothing on screen.
- **Taproot multisig cannot be assembled from bare keys**, only derived from a descriptor you
  already have. A `tr()` needs an internal key, and that key is a second single-key route to
  the same coins; choosing one for you would be inventing your spending policy.
- **A duplicate key is refused when assembling** a multisig — a 2-of-3 with a duplicate is a
  1-of-2 — but **derived and reported** when it arrives inside an existing descriptor.

That last pair is the rule the whole design follows: **refuse to manufacture a footgun, never
refuse to show funds that already exist.**

## Why not BDK

[BDK](https://bitcoindevkit.org/) is excellent, and the wallet layer above this crate may
well use it. This crate sits *below* it, for three measured reasons:

1. `bdk_wallet` 3.1.0 pins `miniscript ^12.3.5`. Depending on both puts two incompatible
   `Descriptor` types in the dependency graph, and 12.x lacks the rewritten Taproot API.
2. Dependency surface is **12 packages** on bare `miniscript` versus **34** via `bdk_wallet`.
   For software guarding real money, the dependency graph *is* the attack surface.
3. BDK ships signing code, BIP-39 and `DescriptorSecretKey` handling — all of which a
   watch-only crate has promised never to use. On bare miniscript,
   `Secp256k1::verification_only()` **cannot sign at all**, which turns that promise into a
   compiler-enforced guarantee.

## Known ecosystem constraints

Research against `miniscript` 13.1.0 turned up three things that directly limit what can
ship:

- **`sortedmulti_a` is absent from every released `rust-miniscript`.** It is defined by
  [BIP-387](https://github.com/bitcoin/bips/blob/master/bip-0387.mediawiki) and deployed in
  Bitcoin Core since 24.0, so taproot-multisig descriptors exported by Core, Sparrow or
  hardware signers **will fail to parse**. Support is merged to `master`
  ([PR #910](https://github.com/rust-bitcoin/rust-miniscript/pull/910)) and queued for an
  unreleased 14.0. This crate refuses it with an error naming it as an upstream gap rather
  than a user error.
- **musig2 does not exist** in the ecosystem. BIP-390 is Draft. Not immature — absent.
- **Network validation is the caller's job.** Descriptors are network-free, and
  `xkey_network()` only *reports*. That is why this crate enforces it.

> These findings come from reading published crate sources, not from running code. They are
> well-sourced but **unverified by execution**, and re-verifying them is the first task once
> a build toolchain is in place.

## Roadmap

- [x] Scope the module and research the `rust-miniscript` capability landscape
- [x] Settle accepted input forms and supported script policy
- [ ] Settle the public API and crate boundary
- [ ] Settle correctness strategy and test vectors
- [ ] Settle dependency version and upgrade policy
- [ ] Write the spec, then implement
- [ ] Publish to crates.io

Design artifacts live outside version control and are not part of this repository.

## Relationship to the wallet

This crate is used by [logicvoid0x/wallet](https://github.com/logicvoid0x/wallet), a
watch-only terminal Bitcoin wallet that coordinates PSBTs for hardware signers. It is
developed separately and deliberately: the wallet depends on this crate, this crate knows
nothing about the wallet, and the boundary is enforced by being two projects rather than by
convention.

It is usable on its own by anyone who wants descriptor derivation without the wallet.

## Security

This crate is intended to handle real funds eventually, and it isn't there yet. It is
watch-only by construction and will never hold a private key.

Please **do not** use anything from this repository with mainnet funds until a release
explicitly says it is ready. A responsible-disclosure policy will be published alongside the
first release.

## License

[MIT](LICENSE) © 2026 logicvoid0x

The warranty disclaimer is worth reading rather than skimming. This software is provided
"as is", with no warranty of any kind and no liability accepted — which matters more than
usual for a project that will eventually touch Bitcoin, where mistakes are irreversible and
uninsured.
