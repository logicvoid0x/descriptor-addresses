use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use bitcoin::Network;
use miniscript::descriptor::{Descriptor, DescriptorPublicKey};

use miniscript::ForEachKey;

use crate::canonical::{canonical_h_form, h_notation};
use crate::{
    policy, AddressRecord, DescriptorError, KeyOrigin, KeychainKind, NormalIndex, ScriptType,
};

/// A descriptor that has been checked, and whose checks do not need repeating.
///
/// The organising principle of this type: **all fallibility sits at one boundary.**
/// Constructing one of these can fail; nothing you do with it afterwards can. A
/// caller scanning a range of indices therefore has no error path per index, and the
/// questions this crate must ask a human are confined to one place.
#[derive(Debug)]
pub struct ValidatedDescriptor {
    canonical: String,
    network: Network,
    script_type: ScriptType,
    origins: Vec<KeyOrigin>,
    /// Present only for `tr()`. Reported as a fact; whether it is a recognised NUMS
    /// point is an advisory, and deliberately a separate question.
    internal_key: Option<String>,
    external: Descriptor<DescriptorPublicKey>,
    internal: Option<Descriptor<DescriptorPublicKey>>,
    /// A verification-only context, built once and shared by both keychains.
    ///
    /// The type parameter is the watch-only guarantee. Signing functions in
    /// `secp256k1` require `C: Signing`, and `VerifyOnly` does not implement it, so a
    /// signing call in this crate is a **compile error** — not a convention, not a
    /// review checklist item, and not something a future contributor can weaken
    /// without changing this line. It is the reason this crate sits below `bdk_wallet`
    /// rather than on it: a linked signer cannot offer the same guarantee at any price.
    secp: Secp256k1<VerifyOnly>,
}

impl ValidatedDescriptor {
    /// Validate a descriptor string against `network`.
    ///
    /// This is the only fallible call in the crate.
    pub fn parse(descriptor: &str, network: Network) -> Result<Self, DescriptorError> {
        // Caught before miniscript sees the string, because miniscript accepts it:
        // `wpkh(xpub.../0/*h)` parses, reports `desc_type = Wpkh`, passes
        // `sanity_check()`, and then panics on derivation. Observed against 13.1.0.
        // Since `address_at` is infallible, this refusal is load-bearing — it is the
        // only thing standing between pasted input and a process abort.
        if descriptor.contains("/*h") || descriptor.contains("/*'") {
            return Err(DescriptorError::HardenedWildcard);
        }

        // Two forms have to be refused before miniscript sees the string, because
        // miniscript's own error would point at the wrong thing.
        policy::check_before_parse(descriptor)?;

        let parsed = Descriptor::<DescriptorPublicKey>::from_str(descriptor)
            .map_err(DescriptorError::parse)?;

        // The allowlist, as a walk over configuration rather than a match on
        // miniscript's descriptor type. See `policy` for why that shape matters.
        let form = policy::check(&parsed)?;

        // The canonical form is computed from the multipath descriptor, before it is
        // split, so it round-trips as the single string the user must back up.
        let canonical = canonical_h_form(&parsed)?;

        // Descriptor-level facts, gathered before the split for the same reason:
        // they describe the wallet, not one of its two chains.
        let origins = origins_of(&parsed);
        let internal_key = match &parsed {
            // Through `h_notation` like everything else shown to a human: an internal
            // key can carry its own origin, and rendering it raw would print `'` next
            // to the `h` in the canonical string directly above it.
            Descriptor::Tr(tr) => Some(h_notation(&tr.internal_key().to_string())),
            _ => None,
        };

        // Multipath has to be split before anything can be derived: `at_derivation_index`
        // errors on any multipath descriptor. One path means external only.
        let mut paths = parsed
            .into_single_descriptors()
            .map_err(DescriptorError::parse)?;

        // BIP-389 defines multipath as a `<a;b;…>` element expanding to one descriptor
        // per entry, and permits any number of them. We accept one or two and no more,
        // because a keychain split has exactly two meanings — receive and change, the
        // BIP-44 change level — and there is no third chain for a third path to be.
        // Accepting it would mean silently discarding a branch the user wrote.
        //
        // The uniformity rule (all keys must carry the same paths) and the refusal of
        // mismatched lengths are ticket 04's; this is only the arity guard that keeps
        // the split unambiguous.
        if paths.is_empty() || paths.len() > 2 {
            return Err(DescriptorError::MultipathArity { paths: paths.len() });
        }

        let internal = if paths.len() == 2 {
            Some(paths.remove(1))
        } else {
            None
        };
        let external = paths.remove(0);

        Ok(ValidatedDescriptor {
            canonical,
            network,
            script_type: ScriptType::known(form),
            origins,
            internal_key,
            external,
            internal,
            secp: Secp256k1::verification_only(),
        })
    }

    /// The descriptor in BIP-380 `h` notation, checksummed.
    ///
    /// Feeding this back into [`parse`](Self::parse) yields the same string, byte for
    /// byte, checksum included.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// The network this descriptor was validated against.
    ///
    /// Bound at construction, so no call site can validate against one network and
    /// format addresses for another.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The shape of script this descriptor pays to.
    pub fn script_type(&self) -> &ScriptType {
        &self.script_type
    }

    /// Each key's origin, in the order the keys appear.
    ///
    /// A descriptor-level fact, not a per-address one: a 2-of-3 has one origin per
    /// key, so no single derivation path describes an address. Keys carrying no
    /// origin are absent from this list rather than represented by a placeholder.
    pub fn origins(&self) -> &[KeyOrigin] {
        &self.origins
    }

    /// The `tr()` internal key, or `None` for every other form.
    ///
    /// Reported, never adjudicated. Whether the key is a recognised NUMS point — and
    /// so whether the key path is meant to be unspendable — is a separate question
    /// answered by an advisory, because unspendability is not detectable in general:
    /// an arbitrary x-only key may be a NUMS point tweaked by a value only its owner
    /// knows.
    pub fn internal_key(&self) -> Option<&str> {
        self.internal_key.as_deref()
    }

    /// Lend out one chain as a borrowed view.
    ///
    /// Both accessors go through here so a keychain can only ever be built one way —
    /// there is no second place for the network or the secp context to be attached
    /// from, and so no way for the two chains to disagree about either.
    fn keychain<'a>(
        &'a self,
        kind: KeychainKind,
        descriptor: &'a Descriptor<DescriptorPublicKey>,
    ) -> Keychain<'a> {
        Keychain {
            kind,
            descriptor,
            secp: &self.secp,
            network: self.network,
            script_type: &self.script_type,
        }
    }

    /// The receive chain, which every descriptor has.
    pub fn external(&self) -> Keychain<'_> {
        self.keychain(KeychainKind::External, &self.external)
    }

    /// The change chain, or `None` for single-path input.
    ///
    /// The `Option` is deliberate. The alternative — falling back to the external
    /// chain when there is no internal one — answers "give me a change address" with
    /// a receive address, and the caller cannot tell. That is a silent wrong answer
    /// about where money is going, so it is represented as an absence instead.
    pub fn internal(&self) -> Option<Keychain<'_>> {
        self.internal
            .as_ref()
            .map(|descriptor| self.keychain(KeychainKind::Internal, descriptor))
    }
}

/// One chain of a validated descriptor: a cheap borrowed view, not an owned copy.
#[derive(Debug, Clone, Copy)]
pub struct Keychain<'a> {
    kind: KeychainKind,
    descriptor: &'a Descriptor<DescriptorPublicKey>,
    secp: &'a Secp256k1<VerifyOnly>,
    network: Network,
    script_type: &'a ScriptType,
}

impl<'a> Keychain<'a> {
    /// Which chain this is.
    pub fn kind(&self) -> KeychainKind {
        self.kind
    }

    /// Derive the address at `index`.
    ///
    /// Infallible, and every `expect` below documents which constructor check earned
    /// that. This is the payoff of doing the work at the boundary: the caller's
    /// scanning loop has no error arm.
    pub fn address_at(&self, index: NormalIndex) -> AddressRecord {
        // Cannot fail: the descriptor is single-path (split at construction) and the
        // index is not hardened (`NormalIndex` cannot hold a hardened value).
        let definite = self
            .descriptor
            .at_derivation_index(index.get())
            .expect("single-path descriptor and non-hardened index, both ensured at construction");

        // Total by construction upstream: public derivation of a normal child cannot
        // fail, so miniscript returns the descriptor rather than a `Result`.
        let derived = definite.derived_descriptor(self.secp);

        // Cannot fail: the allowlist admits only forms that have an address. Bare
        // `pk()` and `multi()` do not, which is exactly why they are refused.
        let address = derived
            .address(self.network)
            .expect("allowlisted forms always yield an address");

        AddressRecord::new(
            index,
            self.kind,
            address,
            self.script_type.clone(),
            derived.script_pubkey(),
        )
    }

    /// Derive `count` addresses starting at `start`, lazily.
    ///
    /// Stops at the top of the normal index range rather than wrapping.
    pub fn addresses(&self, start: NormalIndex, count: u32) -> Addresses<'a> {
        Addresses {
            keychain: *self,
            next: Some(start),
            remaining: count,
        }
    }
}

/// A lazy iterator over derived addresses, so a caller can scan without
/// materialising a large vector.
#[derive(Debug)]
pub struct Addresses<'a> {
    keychain: Keychain<'a>,
    next: Option<NormalIndex>,
    remaining: u32,
}

impl<'a> Iterator for Addresses<'a> {
    type Item = AddressRecord;

    fn next(&mut self) -> Option<AddressRecord> {
        if self.remaining == 0 {
            return None;
        }
        let index = self.next?;
        self.remaining -= 1;
        self.next = index.next();
        Some(self.keychain.address_at(index))
    }
}

/// Collect each key's origin, once, from the descriptor as a whole.
///
/// Keys without an origin contribute nothing rather than a placeholder: absence is
/// reported by the list being shorter than the key count, and an advisory names it.
fn origins_of(descriptor: &Descriptor<DescriptorPublicKey>) -> Vec<KeyOrigin> {
    let mut origins = Vec::new();

    descriptor.for_each_key(|key| {
        let origin = match key {
            DescriptorPublicKey::Single(single) => single.origin.as_ref(),
            DescriptorPublicKey::XPub(xpub) => xpub.origin.as_ref(),
            DescriptorPublicKey::MultiXPub(multi) => multi.origin.as_ref(),
        };

        if let Some((fingerprint, path)) = origin {
            let rendered = h_notation(&format!("{}", path));
            let rendered = if rendered.starts_with('m') {
                rendered
            } else {
                format!("m/{}", rendered.trim_start_matches('/'))
            };
            origins.push(KeyOrigin::new(*fingerprint, rendered));
        }

        true
    });

    origins
}
