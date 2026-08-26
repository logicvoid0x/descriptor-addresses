//! Building a descriptor from parts, for people who have keys but not a descriptor.
//!
//! # An input model, not an input mechanism
//!
//! Nothing here reads stdin, prompts, or prints. Flags, the CLI's guided prompts and a
//! future ratatui form all call the same two functions with the same structs, and the
//! library cannot tell which of them it is talking to. The CLI is free to be
//! builder-shaped internally, accumulating `Option` fields as it prompts — that is
//! where a half-built spec is legitimate, and it is deliberately not here.
//!
//! # Why two structs and two functions
//!
//! Not a builder, and not one params struct. The shape is doing work that runtime
//! checks would otherwise have to:
//!
//! - **`script_type` is a mandatory field with no `Default`**, so omitting it is
//!   `missing field script_type in initializer of SingleSig` — a compile error, where
//!   a builder could only have caught it at `build()`. "Never guess a script type" is
//!   the crate's founding rule, and this is the cheapest possible place to enforce it.
//! - **[`MultisigScript`] has no `Tr` variant**, so "taproot multisig cannot be
//!   assembled" is not a rule that can be broken — it is a sentence that cannot be
//!   written.
//! - **A single shared struct would need `Option` fields that admit nonsense**: a
//!   2-of-1, or a single-sig wallet with a key ordering.
//!
//! A future assemblable form gets a third function. Additive, exactly as the allowlist
//! grows.

use bitcoin::bip32::DerivationPath;
use bitcoin::Network;

use crate::{AssemblyError, KeyError, ValidatedDescriptor};

/// A key expression, validated at construction.
///
/// Owning a `DescriptorKey` means the string inside it is a well-formed key that this
/// crate is willing to accept — SLIP-132 prefixes and malformed origins are refused
/// here rather than several steps later, so an assembly spec cannot be built out of
/// parts that will fail at the end.
///
/// This is where [`KeyError`] earns its place as a shared type: the same failures
/// arise whether a key arrived inside a descriptor string or as a field a caller
/// filled in, and a caller prompting for a replacement wants the same information
/// either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorKey {
    /// The key as written, minus any origin.
    key: String,
    /// The origin's fingerprint, if one was given.
    fingerprint: Option<String>,
    /// The origin's path, if one was given.
    path: Option<String>,
}

impl DescriptorKey {
    /// Validate a key expression: `xpub…`, `[fingerprint]xpub…`, or
    /// `[fingerprint/path]xpub…`.
    pub fn parse(key: &str) -> Result<Self, KeyError> {
        let key = key.trim();
        if key.is_empty() {
            return Err(KeyError::Malformed {
                detail: "a key expression cannot be empty".to_string(),
            });
        }

        // The same pre-parse rules the descriptor path applies, so assembly cannot
        // become a back door around a rule `parse` enforces.
        crate::rules::reject_slip132_key(key)?;

        let (origin, bare) = match key.strip_prefix('[') {
            None => (None, key),
            Some(rest) => {
                let (inside, after) = rest.split_once(']').ok_or_else(|| KeyError::Origin {
                    detail: "the origin is missing its closing `]`".to_string(),
                })?;
                (Some(inside), after)
            }
        };

        let (fingerprint, path) = match origin {
            None => (None, None),
            Some(inside) => {
                let (fp, path) = match inside.split_once('/') {
                    Some((fp, path)) => (fp, Some(path.to_string())),
                    None => (inside, None),
                };

                // BIP-380: a master fingerprint is exactly 8 hex characters.
                if fp.len() != 8 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(KeyError::Origin {
                        detail: format!(
                            "a master fingerprint is 8 hex characters; `{}` is not",
                            fp
                        ),
                    });
                }

                // Validated here rather than left to surface much later as an opaque
                // "invalid child number format" from the descriptor parser. This type
                // promises that holding one means the key is well-formed; deferring
                // would make that promise false for exactly the field a user is most
                // likely to mistype.
                if let Some(path) = &path {
                    validate_origin_path(path)?;
                }

                (Some(fp.to_string()), path)
            }
        };

        // A wildcard or derivation suffix is assembly's job, not the caller's: the
        // whole point is that we produce `<0;1>/*` so the wallet has both chains.
        if bare.contains('/') || bare.contains('*') {
            return Err(KeyError::Malformed {
                detail: "supply the account key only; the derivation suffix is added \
                         for you so both keychains exist"
                    .to_string(),
            });
        }

        // Validated by round-tripping through the real parser rather than by our own
        // guess at what an xpub looks like — the authority on that is the library that
        // will derive from it.
        crate::rules::validate_bare_key(bare)?;

        Ok(DescriptorKey {
            key: bare.to_string(),
            fingerprint,
            path,
        })
    }

    /// Render as a descriptor key expression, with `path` filled in when the caller
    /// supplied neither an origin path nor an explicit one.
    fn render(&self, default_path: &str) -> Result<String, AssemblyError> {
        let path = match (&self.path, default_path) {
            (Some(existing), _) => existing.clone(),
            (None, default) => default.to_string(),
        };

        match &self.fingerprint {
            Some(fingerprint) => Ok(format!("[{}/{}]{}", fingerprint, path, self.key)),
            // No fingerprint, so no origin can be written at all — BIP-380 requires
            // one. The caller was told this at spec-validation time; reaching here
            // means there was no path to record either.
            None => Ok(self.key.clone()),
        }
    }

    /// The key expression without its origin.
    ///
    /// These three accessors exist for one caller: a UI showing the user what it is
    /// about to assemble. The alternative is that the caller re-splits the string it
    /// already handed to [`DescriptorKey::parse`], which is a second parser that will
    /// disagree with this one the first time either changes — and the value it would
    /// disagree about is which key a wallet is built from.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The origin's master fingerprint, if the key stated one.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// The origin's derivation path, if the key stated one.
    ///
    /// `None` does not mean "no path": it means assembly will supply the BIP default
    /// for the script type, which [`SingleSigScript::default_origin_path`] and
    /// [`MultisigScript::default_origin_path`] name.
    pub fn origin_path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Whether this key already states an origin path.
    fn has_path(&self) -> bool {
        self.path.is_some()
    }

    /// Whether this key states a fingerprint a path could hang from.
    fn has_fingerprint(&self) -> bool {
        self.fingerprint.is_some()
    }

    /// The key without its origin, for duplicate detection.
    fn bare(&self) -> &str {
        &self.key
    }
}

/// The four single-sig forms this crate can assemble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleSigScript {
    /// Legacy P2PKH, `1…` addresses. BIP-44.
    Pkh,
    /// Nested segwit, `3…` addresses. BIP-49.
    ShWpkh,
    /// Native segwit, `bc1q…` addresses. BIP-84.
    Wpkh,
    /// Taproot key-path, `bc1p…` addresses. BIP-86.
    Tr,
}

/// The multisig wrappers this crate can assemble.
///
/// **There is deliberately no `Tr` variant.** A `tr()` output needs an internal key,
/// and that key is a second, single-key spending route for the same coins:
/// `tr(A,multi_a(2,A,B,C))` reads as a 2-of-3 and is a 1-of-1. Choosing an internal
/// key is a privacy decision baked into every address the wallet will ever have, and
/// the assembled path exists precisely for users who cannot evaluate that. Anyone who
/// can is able to write the `tr(...)` themselves and hand it to `parse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigScript {
    /// Native segwit multisig, `bc1q…` addresses.
    Wsh,
    /// Nested segwit multisig, `3…` addresses.
    ShWsh,
}

/// Whether the keys are sorted before use.
///
/// The distinction is a correctness trap rather than a preference: the same keys in a
/// different order produce different addresses, and therefore different funds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrdering {
    /// `sortedmulti` — keys sorted lexicographically per BIP-67, so every cosigner
    /// derives the same addresses regardless of the order they typed them in.
    Sorted,
    /// `multi` — keys used exactly as given, so the order is part of the wallet.
    AsGiven,
}

impl SingleSigScript {
    /// The BIP-44/49/84/86 origin path assembly uses when a key states none.
    ///
    /// Public because it is the one fact a confirmation screen exists to show: which
    /// account the wallet will be derived under. A caller that hard-coded `84h/0h/0h`
    /// into its own renderer would be stating as fact something only this crate
    /// decides, and would go on stating it after this crate changed its mind.
    ///
    /// Rendered in `h` notation, the form this crate canonicalises to — not the `'`
    /// that `DerivationPath`'s own `Display` produces.
    pub fn default_origin_path(self, network: Network) -> String {
        default_single_sig_path(self, network)
    }
}

impl MultisigScript {
    /// The BIP-48 origin path assembly uses when the keys state none.
    ///
    /// See [`SingleSigScript::default_origin_path`].
    pub fn default_origin_path(self, network: Network) -> String {
        default_multisig_path(self, network)
    }
}

/// A single-signature wallet to assemble.
#[derive(Debug, Clone)]
pub struct SingleSig {
    /// The account key.
    pub key: DescriptorKey,
    /// Mandatory, with no `Default` — see the module documentation.
    pub script_type: SingleSigScript,
    /// The network the key belongs to.
    pub network: Network,
    /// `None` defaults per BIP-44/49/84/86 from the script type and network.
    pub path: Option<DerivationPath>,
}

/// A multisignature wallet to assemble.
#[derive(Debug, Clone)]
pub struct Multisig {
    /// The cosigners' account keys.
    pub keys: Vec<DescriptorKey>,
    /// How many signatures are required.
    pub threshold: u32,
    /// Mandatory, with no `Default` — see the module documentation.
    pub script_type: MultisigScript,
    /// Whether to sort the keys per BIP-67.
    pub ordering: KeyOrdering,
    /// The network the keys belong to.
    pub network: Network,
    /// `None` defaults to the BIP-48 path for this script type.
    pub path: Option<DerivationPath>,
}

/// The two keychains every assembled wallet gets.
///
/// Assembly always produces the two-path form, so an assembled wallet has somewhere to
/// send change like any other — and the echoed descriptor, the string the user must
/// back up, covers both chains rather than half of them.
const BOTH_KEYCHAINS: &str = "/<0;1>/*";

impl ValidatedDescriptor {
    /// Assemble a single-signature descriptor.
    pub fn assemble_single_sig(spec: SingleSig) -> Result<Self, AssemblyError> {
        let path = resolve_path(
            std::slice::from_ref(&spec.key),
            spec.path.as_ref(),
            &default_single_sig_path(spec.script_type, spec.network),
        )?;

        let key = spec.key.render(&path)?;

        let descriptor = match spec.script_type {
            SingleSigScript::Pkh => format!("pkh({}{})", key, BOTH_KEYCHAINS),
            SingleSigScript::ShWpkh => format!("sh(wpkh({}{}))", key, BOTH_KEYCHAINS),
            SingleSigScript::Wpkh => format!("wpkh({}{})", key, BOTH_KEYCHAINS),
            SingleSigScript::Tr => format!("tr({}{})", key, BOTH_KEYCHAINS),
        };

        finish(&descriptor, spec.network)
    }

    /// Assemble a multisignature descriptor.
    pub fn assemble_multisig(spec: Multisig) -> Result<Self, AssemblyError> {
        if spec.keys.is_empty() {
            return Err(AssemblyError::NoKeys);
        }

        if spec.threshold == 0 || spec.threshold as usize > spec.keys.len() {
            return Err(AssemblyError::ThresholdExceedsKeys {
                threshold: spec.threshold as usize,
                keys: spec.keys.len(),
            });
        }

        // Compared on the bare key, so the same xpub twice is caught even if the two
        // copies were written with different origins.
        let mut seen: Vec<&str> = Vec::new();
        for key in &spec.keys {
            if seen.contains(&key.bare()) {
                return Err(AssemblyError::DuplicateKey {
                    key: key.bare().to_string(),
                });
            }
            seen.push(key.bare());
        }

        let path = resolve_path(
            &spec.keys,
            spec.path.as_ref(),
            &default_multisig_path(spec.script_type, spec.network),
        )?;

        let keys: Result<Vec<String>, AssemblyError> = spec
            .keys
            .iter()
            .map(|key| Ok(format!("{}{}", key.render(&path)?, BOTH_KEYCHAINS)))
            .collect();
        let keys = keys?.join(",");

        let inner = match spec.ordering {
            KeyOrdering::Sorted => format!("sortedmulti({},{})", spec.threshold, keys),
            KeyOrdering::AsGiven => format!("multi({},{})", spec.threshold, keys),
        };

        let descriptor = match spec.script_type {
            MultisigScript::Wsh => format!("wsh({})", inner),
            MultisigScript::ShWsh => format!("sh(wsh({}))", inner),
        };

        finish(&descriptor, spec.network)
    }
}

/// Hand the assembled string to `parse`.
///
/// **Assembly does not have its own validation path**, and that is the point: whatever
/// it builds must survive the same allowlist, the same network enforcement and the
/// same input rules as a descriptor a user pasted. If assembly could produce something
/// `parse` refuses — `sh(wsh(multi))` is exactly such a case — the failure surfaces
/// here rather than reaching a user as a descriptor their own tool will not read back.
fn finish(descriptor: &str, network: Network) -> Result<ValidatedDescriptor, AssemblyError> {
    ValidatedDescriptor::parse(descriptor, network).map_err(|e| AssemblyError::Unbuildable {
        attempted: descriptor.to_string(),
        reason: Box::new(e),
    })
}

/// Decide which origin path the assembled keys should carry.
///
/// Three sources, and they must not silently override each other:
/// the key's own origin, an explicit `path` on the spec, and the BIP default.
fn resolve_path(
    keys: &[DescriptorKey],
    explicit: Option<&DerivationPath>,
    default: &str,
) -> Result<String, AssemblyError> {
    let with_path = keys.iter().filter(|key| key.has_path()).count();
    let without_path = keys.len() - with_path;

    // **Either every key states a path or none does.** Mixing them is refused because
    // the mixture is silently wrong rather than merely untidy: the keys without a path
    // take the BIP default account while the others keep whatever they stated, so a
    // quorum ends up spread across two different accounts and derives a wallet nobody
    // asked for — with nothing on screen to say so.
    if with_path > 0 && without_path > 0 {
        return Err(AssemblyError::MixedOrigins {
            with_path,
            without_path,
        });
    }

    match (explicit, with_path > 0) {
        // Two sources for one value is a question, not a default. Preferring either
        // silently would discard something the caller actually said.
        (Some(_), true) => Err(AssemblyError::PathAlreadyInKey {
            key: keys
                .iter()
                .find(|key| key.has_path())
                .map(|key| key.bare().to_string())
                .unwrap_or_default(),
        }),

        (Some(path), false) => {
            // A path needs a fingerprint to hang from: BIP-380 origins require one and
            // it cannot be computed from an account xpub. Dropping the path silently
            // would lose what the caller stated.
            if !keys.iter().all(|key| key.has_fingerprint()) {
                return Err(AssemblyError::PathWithoutFingerprint);
            }
            Ok(crate::canonical::h_notation(&path.to_string()))
        }

        // Every key states its own; `render` uses the key's copy and ignores this.
        (None, true) => Ok(default.to_string()),

        (None, false) => Ok(default.to_string()),
    }
}

/// Check an origin path is well-formed.
///
/// Delegated to `bitcoin`'s own parser rather than pattern-matched here, for the same
/// reason key validation is: the authority on what a derivation path may look like is
/// the crate that will walk it.
fn validate_origin_path(path: &str) -> Result<(), KeyError> {
    if path.is_empty() {
        return Err(KeyError::Origin {
            detail: "the origin has a trailing `/` with no path after it".to_string(),
        });
    }

    path.parse::<DerivationPath>()
        .map(|_| ())
        .map_err(|e| KeyError::Origin {
            detail: format!("`{}` is not a derivation path: {}", path, e),
        })
}

/// BIP-44's coin type: 0 for mainnet, 1 for every test network.
///
/// Two values because BIP-44 defines two, which matches this crate's granularity —
/// testnet, testnet4 and signet are indistinguishable from a key anyway.
fn coin_type(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

/// The purpose field each BIP assigns to its script type.
///
/// A lookup rather than a guess: both the script type and the network were stated
/// explicitly by the caller, so nothing here is inferred from the key.
fn default_single_sig_path(script_type: SingleSigScript, network: Network) -> String {
    let purpose = match script_type {
        SingleSigScript::Pkh => 44,    // BIP-44, legacy P2PKH
        SingleSigScript::ShWpkh => 49, // BIP-49, P2SH-wrapped segwit
        SingleSigScript::Wpkh => 84,   // BIP-84, native segwit
        SingleSigScript::Tr => 86,     // BIP-86, taproot key-path
    };

    format!("{}h/{}h/0h", purpose, coin_type(network))
}

/// BIP-48's path for multisig, whose final element names the script type.
fn default_multisig_path(script_type: MultisigScript, network: Network) -> String {
    let script = match script_type {
        // BIP-48 assigns 1' to P2SH-P2WSH and 2' to P2WSH.
        MultisigScript::ShWsh => 1,
        MultisigScript::Wsh => 2,
    };

    format!("48h/{}h/0h/{}h", coin_type(network), script)
}

#[cfg(test)]
mod tests {
    use super::*;

    const X: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    #[test]
    fn bip_purposes_match_their_script_types() {
        assert_eq!(
            default_single_sig_path(SingleSigScript::Pkh, Network::Bitcoin),
            "44h/0h/0h"
        );
        assert_eq!(
            default_single_sig_path(SingleSigScript::Tr, Network::Testnet),
            "86h/1h/0h"
        );
        assert_eq!(
            default_multisig_path(MultisigScript::Wsh, Network::Bitcoin),
            "48h/0h/0h/2h"
        );
        assert_eq!(
            default_multisig_path(MultisigScript::ShWsh, Network::Testnet),
            "48h/1h/0h/1h"
        );
    }

    #[test]
    fn a_key_splits_into_its_parts() {
        let bare = DescriptorKey::parse(X).unwrap();
        assert!(!bare.has_fingerprint());
        assert!(!bare.has_path());

        let with_fingerprint = DescriptorKey::parse(&format!("[aabbccdd]{}", X)).unwrap();
        assert!(with_fingerprint.has_fingerprint());
        assert!(!with_fingerprint.has_path());

        let full = DescriptorKey::parse(&format!("[aabbccdd/84h/0h/0h]{}", X)).unwrap();
        assert!(full.has_fingerprint());
        assert!(full.has_path());
    }

    /// The suffix is assembly's job. Accepting one would let a caller produce a
    /// single-chain wallet through a path that promises both.
    #[test]
    fn a_key_carrying_its_own_derivation_suffix_is_refused() {
        assert!(DescriptorKey::parse(&format!("{}/0/*", X)).is_err());
        assert!(DescriptorKey::parse(&format!("{}/<0;1>/*", X)).is_err());
    }

    #[test]
    fn a_malformed_fingerprint_is_refused() {
        assert!(DescriptorKey::parse(&format!("[zzzzzzzz]{}", X)).is_err());
        assert!(DescriptorKey::parse(&format!("[aabb]{}", X)).is_err());
        assert!(DescriptorKey::parse(&format!("[aabbccdd{}", X)).is_err());
    }
}
