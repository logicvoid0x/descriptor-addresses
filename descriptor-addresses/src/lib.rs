//! Turn a Bitcoin output descriptor into derived addresses.
//!
//! # Why a descriptor and not an xpub
//!
//! An extended public key does not carry enough information to derive an address.
//! Two gaps make this genuinely hard rather than merely inconvenient:
//!
//! - **A bare xpub does not encode a script type.** The same `xpub…` derives four
//!   different, incompatible sets of addresses — `1…`, `3…`, `bc1q…`, `bc1p…` — each
//!   holding different money.
//! - **Multisig needs more than keys**: a threshold, a key ordering, a script
//!   wrapper, and a derivation path per key.
//!
//! Guessing at any of these produces a confident list of *wrong-shaped* addresses,
//! and that failure is silent — it does not crash, it does not warn, and it looks
//! exactly like success. Output descriptors exist precisely to express what an xpub
//! cannot, so they are the canonical input here.
//!
//! # Watch-only by construction
//!
//! This crate never touches a private key, never reads stdin, and never signs. Its
//! secp256k1 context is `Secp256k1<VerifyOnly>`, whose type parameter makes a signing
//! call a **compile error** rather than a matter of discipline.
//!
//! # All fallibility at one boundary
//!
//! Every `Result` in the public API is on a constructor. Once a descriptor is
//! validated, derivation is total:
//!
//! ```
//! use descriptor_addresses::{Network, NormalIndex, ValidatedDescriptor};
//!
//! let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
//! let wallet = ValidatedDescriptor::parse(
//!     &format!("wpkh({}/<0;1>/*)", xpub),
//!     Network::Bitcoin,
//! )?;
//!
//! // No error path per index — that work was done once, above.
//! let first = wallet.external().address_at(NormalIndex::ZERO);
//! assert_eq!(first.relative_path(), "0/0");
//!
//! // Change is an `Option`, never a silent fallback to the receive chain.
//! if let Some(change) = wallet.internal() {
//!     let _ = change.address_at(NormalIndex::ZERO);
//! }
//! # Ok::<(), descriptor_addresses::DescriptorError>(())
//! ```
//!
//! # What this build accepts
//!
//! A closed set of **nine forms**, single- or two-path:
//!
//! | Single-sig | Multisig |
//! |---|---|
//! | `pkh(KEY)` | `wsh(sortedmulti(k,…))` |
//! | `sh(wpkh(KEY))` | `sh(wsh(sortedmulti(k,…)))` |
//! | `wpkh(KEY)` | `wsh(multi(k,…))` |
//! | `tr(KEY)` key-path only | `sh(multi(k,…))` |
//!
//! plus `tr(INTERNAL, multi_a(k, KEYS…))` with a single leaf.
//!
//! The set is closed **by an explicit walk**, not by "whatever the parser accepts",
//! so a form this crate has not considered is refused rather than attempted — and a
//! future version of the underlying library cannot silently widen it. A dependency
//! bump is not a policy change.
//!
//! The governing principle is the **create/read asymmetry**: refuse to *manufacture*
//! a footgun, never refuse to *show* funds that already exist. Refusing to create
//! costs one error message; refusing to read costs someone sight of their own money.

#![deny(missing_debug_implementations)]
#![warn(missing_docs)]

mod advisory;
mod assembly;
mod canonical;
mod error;
mod index;
mod origin;
mod policy;
mod record;
mod rules;
mod validated;

/// The descriptor forms this build accepts, in descriptor syntax.
///
/// Derived from the policy itself rather than written out again, so a caller listing
/// what is supported cannot drift from what is actually enforced.
pub fn supported_forms() -> impl Iterator<Item = &'static str> {
    policy::allowed_forms()
}

pub use advisory::Advisory;
pub use assembly::{
    DescriptorKey, KeyOrdering, Multisig, MultisigScript, SingleSig, SingleSigScript,
};
pub use error::{AssemblyError, DescriptorError, KeyError, NetworkClass};
pub use index::NormalIndex;
pub use origin::KeyOrigin;
pub use record::{AddressRecord, KeychainKind, ScriptType};
pub use validated::{Addresses, Keychain, ValidatedDescriptor};

// Re-exported because they appear in this crate's public API. A caller must be able
// to name our types without guessing which version of `bitcoin` we resolved to.
pub use bitcoin::{Address, Network, ScriptBuf};
