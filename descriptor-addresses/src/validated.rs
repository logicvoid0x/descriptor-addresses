use std::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use bitcoin::{Network, NetworkKind};
use miniscript::descriptor::{Descriptor, DescriptorPublicKey, XKeyNetwork};

use crate::error::NetworkClass;

use miniscript::ForEachKey;

use crate::canonical::{canonical_h_form, h_notation};
use crate::{
    advisory, policy, rules, AddressRecord, Advisory, DescriptorError, KeyOrigin, KeychainKind,
    NormalIndex, ScriptType,
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
    advisories: Vec<Advisory>,
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
    /// One of the two fallible calls in the crate, and the one to reach for. See
    /// [`parse_permissive`](Self::parse_permissive) for the single relaxation
    /// available, and prefer this unless you specifically need it.
    pub fn parse(descriptor: &str, network: Network) -> Result<Self, DescriptorError> {
        Self::parse_inner(descriptor, network, false)
    }

    /// Validate a descriptor, downgrading **duplicate keys** from an error to an
    /// accepted quirk.
    ///
    /// This relaxes exactly one rule and nothing else. It exists because the
    /// create/read asymmetry cuts both ways for duplicates: a repeated key means a
    /// 2-of-3 is really a 1-of-2, which is a footgun worth refusing to *manufacture*
    /// — but if such a wallet already holds funds, refusing to *show* it costs
    /// someone sight of their own money.
    ///
    /// Every other rule still applies. A permissive parse still refuses hardened
    /// wildcards, bad checksums, SLIP-132 prefixes, mixed networks and everything
    /// else; the two constructors differ in one variant and are otherwise identical.
    pub fn parse_permissive(descriptor: &str, network: Network) -> Result<Self, DescriptorError> {
        Self::parse_inner(descriptor, network, true)
    }

    fn parse_inner(
        descriptor: &str,
        network: Network,
        allow_duplicate_keys: bool,
    ) -> Result<Self, DescriptorError> {
        // Rules that have to run before miniscript sees the string, either because
        // its error would point at the wrong thing or because accepting the input
        // leads to a panic. See `rules` for which is which.
        rules::before_parse(descriptor)?;

        // `sortedmulti_a` also has to be caught pre-parse: miniscript blames the key.
        policy::check_before_parse(descriptor)?;

        let parsed = Descriptor::<DescriptorPublicKey>::from_str(descriptor)
            .map_err(|e| rules::translate_parse_error(&e.to_string()))?;

        // The allowlist, as a walk over configuration rather than a match on
        // miniscript's descriptor type. See `policy` for why that shape matters.
        let form = policy::check(&parsed)?;

        // The canonical form is computed from the multipath descriptor, before it is
        // split, so it round-trips as the single string the user must back up.
        let canonical = canonical_h_form(&parsed)?;

        // Enforced, not merely reported. Granularity is xpub-versus-tpub only:
        // testnet, testnet4 and signet share one set of version bytes, so a key
        // cannot say which of the three was meant and this crate must not pretend
        // otherwise.
        enforce_network(&parsed, network)?;

        // Rules that need the parsed structure rather than the raw text.
        let duplicate = rules::after_parse(&parsed, allow_duplicate_keys)?;

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

        // Gathered here, while both the raw input and the parsed tree are in hand:
        // the checksum and notation findings live in the text, the origin and NUMS
        // findings live in the tree.
        let advisories = advisories_of(
            &parsed,
            descriptor,
            &origins,
            internal_key.as_deref(),
            duplicate,
        );

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
            advisories,
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

    /// Non-fatal findings, computed once at parse.
    ///
    /// Separate from the facts above because the two grow differently: the facts are a
    /// small bounded set that each get an accessor, while this list is open-ended and
    /// must be able to gain entries in a patch release. Returning it as a slice means
    /// a caller on the happy path never has to destructure anything to ignore it.
    pub fn advisories(&self) -> &[Advisory] {
        &self.advisories
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

/// Gather every non-fatal finding, once, at parse.
///
/// Stored rather than recomputed per call: a coordinator scanning ten thousand
/// indices should pay for this exactly once, and two reads must not be able to
/// disagree.
fn advisories_of(
    descriptor: &Descriptor<DescriptorPublicKey>,
    raw: &str,
    origins: &[KeyOrigin],
    internal_key: Option<&str>,
    duplicate_key: Option<String>,
) -> Vec<Advisory> {
    let mut found = Vec::new();

    if !raw.contains('#') {
        found.push(Advisory::ChecksumAbsent);
    }

    // The rewrite is detected on the *input*, not by diffing the two strings: our
    // canonical form never contains `'`, so a diff would report a rewrite for every
    // descriptor that happens to differ for any other reason.
    if raw.contains('\'') {
        found.push(Advisory::NotationRewritten);
    }

    // Reported once for the descriptor, not once per key without one. A caller
    // learns "some key here cannot route a PSBT unaided", which is a fact about the
    // descriptor; which key is missing an origin is visible from `origins()`.
    if origins.len() < origin_bearing_keys(descriptor) {
        found.push(Advisory::OriginAbsent);
    }

    if let Some(key) = duplicate_key {
        found.push(Advisory::DuplicateKey { key });
    }

    // Only for a `tr()` that actually has a script path. A key-path-only taproot is
    // *meant* to be spendable through its internal key, so remarking that the key is
    // not a NUMS point would fire on every ordinary taproot wallet and teach the
    // reader to ignore the channel.
    if let Some(key) = internal_key {
        let has_script_path = matches!(descriptor, Descriptor::Tr(tr) if tr.tap_tree().is_some());
        if has_script_path && !advisory::is_known_nums(key) {
            found.push(Advisory::NumsUnrecognised {
                key: key.to_string(),
            });
        }
    }

    found
}

/// How many keys could meaningfully carry an origin.
///
/// A raw `tr()` internal key is excluded, and the exclusion is load-bearing rather
/// than cosmetic: a NUMS point has no derivation path, so there is no origin it could
/// ever state. Counting it made the canonical script-path-only taproot multisig report
/// a missing origin **even when every signing key had one** — an advisory that fires
/// on a wallet with nothing wrong with it, which is how a reporting channel teaches
/// people to ignore it.
fn origin_bearing_keys(descriptor: &Descriptor<DescriptorPublicKey>) -> usize {
    let exempt = rules::raw_internal_key(descriptor);
    let mut count = 0;

    descriptor.for_each_key(|key| {
        if exempt.as_deref() != Some(key.to_string().as_str()) {
            count += 1;
        }
        true
    });

    count
}

/// Enforce that the keys belong to the network this descriptor is being read as.
///
/// Miniscript reports the network but enforces nothing, so a mainnet xpub read as
/// testnet yields perfectly well-formed `tb1…` addresses for money that is not there
/// — verified against the real stack. Enforcing it is ours to do.
///
/// **Granularity is xpub-versus-tpub and nothing finer.** testnet, testnet4 and signet
/// share one set of BIP-32 version bytes, so a key genuinely cannot say which of the
/// three was meant. Pretending otherwise would mean inventing a distinction the data
/// does not carry.
/// A **typed** match, not a match on `Debug` output.
///
/// An earlier draft compared `format!("{:?}", …)` against `"Mixed"` and `"Main"`. It
/// worked, and it made this crate's money rule depend on a foreign crate's `Debug`
/// formatting — which is not a stable contract. The failure mode was the wrong one
/// too: if `"Mixed"` ever stopped rendering that way, a mixed-network descriptor fell
/// through to the equality test and was **accepted**. A rule that fails open is worse
/// than no rule, because it reads as enforcement. Matching the enum makes an upstream
/// change a compile error instead.
fn enforce_network(
    descriptor: &Descriptor<DescriptorPublicKey>,
    declared: Network,
) -> Result<(), DescriptorError> {
    let keys_are_mainnet = match descriptor.xkey_network() {
        // No extended keys at all — a raw pubkey descriptor makes no network claim to
        // check, which is why the BIP-382/386 vectors can be accepted as written.
        XKeyNetwork::NoXKeys => return Ok(()),
        XKeyNetwork::Mixed => return Err(DescriptorError::MixedNetworks),
        XKeyNetwork::Single(NetworkKind::Main) => true,
        XKeyNetwork::Single(NetworkKind::Test) => false,
    };

    let declared_is_mainnet = declared == Network::Bitcoin;

    if keys_are_mainnet != declared_is_mainnet {
        return Err(DescriptorError::NetworkMismatch {
            declared: if declared_is_mainnet {
                NetworkClass::Mainnet
            } else {
                NetworkClass::Test
            },
            found: if keys_are_mainnet {
                NetworkClass::Mainnet
            } else {
                NetworkClass::Test
            },
        });
    }

    Ok(())
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
