//! Input rules: what is refused, and where in the pipeline it has to be caught.
//!
//! The ordering here is not arbitrary. Some rules must run **before** miniscript sees
//! the string, because miniscript's own error would point at the wrong thing or
//! because accepting the input leads to a panic. Others can only run **after**, on
//! the parsed structure. Each function below says which it is and why.

use bitcoin::base58;
use miniscript::descriptor::{checksum, Descriptor, DescriptorPublicKey};
use miniscript::ForEachKey;

use crate::{DescriptorError, KeyError};

// ------------------------------------------------------------- before parsing

/// SLIP-132 prefixes, their standard equivalent's version bytes, and the descriptor
/// form each was invented to imply.
///
/// The prefixes are non-standard and discouraged, which is why they are refused —
/// but they carry a real script type, and discarding that would make the error less
/// useful than the input.
const SLIP132: &[(&str, [u8; 4], &str)] = &[
    // Mainnet single-sig.
    ("ypub", XPUB_VERSION, "sh(wpkh)"),
    ("zpub", XPUB_VERSION, "wpkh"),
    // Testnet single-sig.
    ("upub", TPUB_VERSION, "sh(wpkh)"),
    ("vpub", TPUB_VERSION, "wpkh"),
    // Mainnet multisig.
    ("Ypub", XPUB_VERSION, "sh(wsh(sortedmulti))"),
    ("Zpub", XPUB_VERSION, "wsh(sortedmulti)"),
    // Testnet multisig.
    ("Upub", TPUB_VERSION, "sh(wsh(sortedmulti))"),
    ("Vpub", TPUB_VERSION, "wsh(sortedmulti)"),
];

/// BIP-32 mainnet public: `xpub`.
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// BIP-32 test-network public: `tpub`.
const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];

/// A BIP-32 serialised extended key is 78 bytes before its base58 check.
const XKEY_LEN: usize = 78;

/// Rules that must run before the string reaches miniscript.
pub(crate) fn before_parse(descriptor: &str) -> Result<(), DescriptorError> {
    hardened_wildcard(descriptor)?;
    checksum_shape(descriptor)?;
    checksum_matches(descriptor)?;
    slip132(descriptor)?;
    Ok(())
}

/// A hardened step in the wildcard position.
///
/// **Must** precede parsing. Observed against miniscript 13.1.0: `wpkh(xpub…/0/*h)`
/// parses, reports `desc_type = Wpkh`, passes `sanity_check()`, and then *panics*
/// when derived. Every guard the library offers says the descriptor is fine. Since
/// derivation in this crate is infallible, this refusal is the only thing standing
/// between pasted input and a process abort.
fn hardened_wildcard(descriptor: &str) -> Result<(), DescriptorError> {
    if descriptor.contains("/*h") || descriptor.contains("/*'") {
        return Err(DescriptorError::HardenedWildcard);
    }
    Ok(())
}

/// The shape of the checksum, as distinct from its correctness.
///
/// Must precede parsing because miniscript reads everything after the first `#` as
/// the checksum: given two, it reports a mismatch against a value the user never
/// typed, which describes the symptom rather than the mistake.
///
/// Correctness is [`checksum_matches`], which also runs before parsing — the expected
/// value is computed from the text itself, so neither check needs the parsed tree.
fn checksum_shape(descriptor: &str) -> Result<(), DescriptorError> {
    let separators = descriptor.matches('#').count();
    if separators > 1 {
        return Err(DescriptorError::ChecksumMalformed {
            detail: format!(
                "a descriptor carries at most one `#`, and this one has {}",
                separators
            ),
        });
    }

    if let Some((_, checksum)) = descriptor.split_once('#') {
        // BIP-380 fixes the checksum at 8 characters.
        if checksum.len() != 8 {
            return Err(DescriptorError::ChecksumMalformed {
                detail: format!(
                    "a descriptor checksum is 8 characters; this one is {}",
                    checksum.len()
                ),
            });
        }
    }

    Ok(())
}

/// SLIP-132 prefixes.
///
/// Must precede parsing: miniscript rejects these with "unknown version magic bytes",
/// which is true and tells the user nothing about what to do. The prefix implies a
/// script type, and this crate's whole reason for existing is that script types must
/// be chosen deliberately rather than inferred — so the implication is handed back as
/// a suggestion rather than acted on.
///
/// The match is **anchored to a key-expression boundary**, and that is not fussiness.
/// Every one of these prefixes is itself valid base58, so an unanchored search finds
/// `ypub` *inside* the body of a perfectly ordinary xpub roughly once in a few
/// thousand multisig descriptors. The user would then be told their standard key is a
/// non-standard one, and handed "(could not be converted)" as the suggested fix — a
/// wallet refused sight of its own funds by a false positive, which is precisely what
/// the create/read asymmetry forbids.
///
/// A key expression starts at the beginning of the string or straight after `(`, `,`
/// or the `]` closing an origin.
fn slip132(descriptor: &str) -> Result<(), DescriptorError> {
    for (start, rest) in key_expression_starts(descriptor) {
        let Some((prefix, target_version, implies)) = SLIP132
            .iter()
            .find(|(prefix, _, _)| rest.starts_with(prefix))
        else {
            continue;
        };

        // The base58 run from the prefix onward. Everything after it is descriptor
        // punctuation, which is not in the base58 alphabet.
        let candidate: String = descriptor[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();

        return Err(KeyError::Slip132 {
            prefix: (*prefix).to_string(),
            converted: reencode(&candidate, *target_version)
                .unwrap_or_else(|| "(the key could not be converted)".to_string()),
            implies: (*implies).to_string(),
        }
        .into());
    }
    Ok(())
}

/// Byte offsets in `descriptor` where a key expression may begin, in order.
///
/// Scanning left to right matters: a descriptor holding a real `zpub` beside an
/// incidental `ypub` must report the one the user actually wrote, and iterating the
/// prefix table instead would report whichever appears first in the *table*.
fn key_expression_starts(descriptor: &str) -> impl Iterator<Item = (usize, &str)> {
    descriptor.char_indices().filter_map(move |(i, c)| {
        let is_boundary = i == 0
            || matches!(
                descriptor[..i].chars().next_back(),
                Some('(') | Some(',') | Some(']')
            );
        // Only positions that begin an alphanumeric run can start a key.
        (is_boundary && c.is_ascii_alphanumeric()).then(|| (i, &descriptor[i..]))
    })
}

/// Re-encode an extended key under different version bytes.
///
/// SLIP-132 changes only the four-byte version prefix; the 74 bytes of key material
/// after it are identical, which is what makes the conversion lossless and worth
/// offering.
fn reencode(key: &str, version: [u8; 4]) -> Option<String> {
    let mut bytes = base58::decode_check(key).ok()?;
    if bytes.len() != XKEY_LEN {
        return None;
    }
    bytes[..4].copy_from_slice(&version);
    Some(base58::encode_check(&bytes))
}

/// The supplied checksum against the one the user's own text should carry.
///
/// Computed over **the literal body the user wrote**, not over our canonical form.
/// BIP-380 checksums literal characters, so one descriptor has two valid checksums —
/// the `h`-form and the `'`-form differ (measured: `7nau6n94` against `fmqjkj0g`).
/// Checking against the canonical form would reject a correctly-checksummed
/// `'`-form descriptor, which is a legitimate thing for another wallet to have
/// produced. Both notations are accepted on input; only output is fixed.
fn checksum_matches(descriptor: &str) -> Result<(), DescriptorError> {
    let Some((body, supplied)) = descriptor.split_once('#') else {
        return Ok(());
    };

    let mut engine = checksum::Engine::new();
    engine.input(body).map_err(DescriptorError::parse)?;
    let expected = engine.checksum();

    if supplied != expected {
        return Err(DescriptorError::ChecksumMismatch {
            found: supplied.to_string(),
            expected,
        });
    }

    Ok(())
}

// -------------------------------------------------------------- after parsing

/// Rules that need the parsed structure.
pub(crate) fn after_parse(
    descriptor: &Descriptor<DescriptorPublicKey>,
    allow_duplicate_keys: bool,
) -> Result<(), DescriptorError> {
    multipath_uniform(descriptor)?;

    // Before the duplicate check, and the order is load-bearing rather than
    // stylistic. `for_each_key` on a `tr()` visits the internal key *and* the leaf
    // keys, so an internal key reused in a leaf is always also a duplicate — put the
    // general rule first and the specific one becomes unreachable, reporting "the
    // quorum is smaller than it looks" for a descriptor whose real problem is that
    // the quorum can be bypassed entirely.
    internal_key_not_in_leaves(descriptor)?;

    if !allow_duplicate_keys {
        no_duplicate_keys(descriptor)?;
    }

    Ok(())
}

/// Every multipath key must carry the same tuple of derivation paths.
///
/// This is the rule that catches the observed silent truncation. `<0;1>` beside
/// `<0;1;2>` passes miniscript's `sanity_check()` and yields **two** descriptors with
/// the third branch discarded — and the behaviour is order-dependent, so a guard
/// derived from `into_single_descriptors` catches it in one order and not the other.
/// Comparing the tuples directly is order-independent and catches it before any
/// splitting happens.
///
/// **Either every key is two-path or none is.** Mixing them is refused, and the reason
/// is not truncation — nothing is discarded, and BIP-389 explicitly permits it.
/// miniscript copies the non-multipath key into both expansions, so the change
/// descriptor reuses a key from the receive descriptor. That is a privacy leak, and
/// one that looks like nothing on screen: the addresses differ, so the wallet appears
/// to be behaving normally while linking its two chains on-chain forever.
///
/// Settled by the Accepted Input and Script Policy decision (Q11). Worth stating here
/// because "BIP-389 allows it and nothing is lost" is a persuasive and wrong reason to
/// accept it, and it is the reading an implementer arrives at unaided.
fn multipath_uniform(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<(), DescriptorError> {
    let mut tuples: Vec<Vec<String>> = Vec::new();

    descriptor.for_each_key(|key| {
        let tuple: Vec<String> = match key {
            DescriptorPublicKey::MultiXPub(multi) => multi
                .derivation_paths
                .paths()
                .iter()
                .map(|path| path.to_string())
                .collect(),
            // A key with no multipath tuple is a one-element tuple, so mixing shows up
            // as a length disagreement rather than needing a rule of its own.
            DescriptorPublicKey::XPub(xpub) => vec![xpub.derivation_path.to_string()],
            DescriptorPublicKey::Single(_) => vec![String::new()],
        };
        tuples.push(tuple);
        true
    });

    // Only the *arity* is compared for single-path keys: two keys at different fixed
    // paths (`A/0/*` and `B/5/*`) are an ordinary descriptor, not a multipath
    // disagreement, so comparing their values would refuse a perfectly good wallet.
    let multipath: Vec<&Vec<String>> = tuples.iter().filter(|t| t.len() > 1).collect();

    if !multipath.is_empty() && multipath.len() != tuples.len() {
        return Err(DescriptorError::MultipathNonUniform {
            found: tuples.iter().map(|t| render_tuple(t)).collect(),
        });
    }

    let Some(first) = multipath.first().copied() else {
        // No multipath keys at all: a single-chain descriptor, which is fine.
        return Ok(());
    };

    if multipath.iter().any(|tuple| *tuple != first) {
        return Err(DescriptorError::MultipathNonUniform {
            found: multipath.iter().map(|t| render_tuple(t)).collect(),
        });
    }

    // A keychain split has exactly two meanings — receive and change, the BIP-44
    // change level — and there is no third chain for a third path to be. Accepting
    // one would mean silently discarding a branch the user wrote.
    if first.len() > 2 {
        return Err(DescriptorError::MultipathArity { paths: first.len() });
    }

    Ok(())
}

/// Render a key's derivation tuple the way it appears in a descriptor, so a refusal
/// quotes something the user can find in their own text.
fn render_tuple(tuple: &[String]) -> String {
    match tuple {
        [single] => single.clone(),
        many => format!("<{}>", many.join(";")),
    }
}

/// The same key twice means the quorum is smaller than it looks.
///
/// Compared on the **full key expression** rather than the xpub alone, so the same
/// xpub at two different derivation paths is not a duplicate — it yields different
/// public keys, and the quorum is real.
fn no_duplicate_keys(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<(), DescriptorError> {
    let mut seen: Vec<String> = Vec::new();
    let mut duplicate: Option<String> = None;

    descriptor.for_each_key(|key| {
        let rendered = key.to_string();
        if seen.contains(&rendered) {
            duplicate.get_or_insert(rendered);
        } else {
            seen.push(rendered);
        }
        true
    });

    match duplicate {
        Some(key) => Err(DescriptorError::DuplicateKey { key }),
        None => Ok(()),
    }
}

/// A `tr()` internal key must not also appear in a leaf.
///
/// If it does, the key path is a single-key spending route around the quorum:
/// `tr(A,multi_a(2,A,B))` reads as a 2-of-2 and A can spend it alone. Miniscript
/// parses this and `sanity_check()` passes, so the refusal is entirely ours.
fn internal_key_not_in_leaves(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<(), DescriptorError> {
    let Descriptor::Tr(tr) = descriptor else {
        return Ok(());
    };

    let internal = tr.internal_key().to_string();

    let Some(tree) = tr.tap_tree() else {
        return Ok(());
    };

    for leaf in tree.leaves() {
        let mut reused = false;
        leaf.miniscript().for_each_key(|key| {
            if key.to_string() == internal {
                reused = true;
            }
            true
        });

        if reused {
            return Err(DescriptorError::InternalKeyReusedInLeaf { key: internal });
        }
    }

    Ok(())
}

// ------------------------------------------------------- translating upstream

/// Turn a miniscript parse failure into one of our variants.
///
/// Translated, never wrapped: wrapping would put a `miniscript` type back in the
/// public API and undo the opaque seam. The cost is this function — miniscript states
/// these conditions in prose, so recognising them means matching on that prose, and a
/// wording change upstream degrades a precise variant into [`DescriptorError::Parse`]
/// rather than breaking the build.
///
/// The two key-count ceilings are the reason this exists at all. They are separate
/// consensus rules with separate limits, and both surface here as sentences.
pub(crate) fn translate_parse_error(message: &str) -> DescriptorError {
    // "The Miniscript corresponding Script cannot be larger than 520 bytes, but got
    // 547 bytes." — the 520-byte cap on a single stack element. A P2SH redeemScript
    // is pushed as one element, so 16 compressed keys (1 + 16*34 + 1 + 1 = 547) is
    // over the line and legacy P2SH multisig stops at 15 keys.
    if message.contains("cannot be larger than") {
        if let (Some(limit), Some(bytes)) = (
            number_before(message, " bytes, but got"),
            number_before(message, " bytes."),
        ) {
            return DescriptorError::ScriptTooLarge { bytes, limit };
        }
    }

    // "invalid threshold 1-of-21; maximum size is 20" — MAX_PUBKEYS_PER_MULTISIG,
    // which limits the CHECKMULTISIG opcode itself. The 520-byte element rule never
    // applies inside a witness, so this ceiling is 20 rather than 15.
    //
    // If either number cannot be read, fall through to `Parse` rather than guessing.
    // An earlier draft defaulted the maximum to the key count on a parse failure,
    // which would have rendered "21 keys exceeds the 21 that CHECKMULTISIG permits".
    if message.contains("maximum size is") {
        if let (Some((_, keys)), Some(max)) = (
            threshold_pair(message),
            message
                .rsplit("maximum size is ")
                .next()
                .and_then(|tail| tail.trim().parse().ok()),
        ) {
            return DescriptorError::TooManyKeys { keys, max };
        }
    }

    // "invalid threshold 3-of-2; cannot have k > n"
    if message.contains("cannot have k > n") {
        if let Some((threshold, keys)) = threshold_pair(message) {
            return DescriptorError::ThresholdExceedsKeys { threshold, keys };
        }
    }

    if message.contains("master fingerprint") || message.contains("derivation path") {
        return KeyError::Origin {
            detail: message.to_string(),
        }
        .into();
    }

    // `combo`, `addr`, `raw` and `rawtr` land here: miniscript does not know them, so
    // the refusal has to come from us to name a form rather than a parser
    // expectation.
    //
    // Matched on "unrecognized name" alone. An earlier draft also accepted any message
    // containing "expected", which is far too broad: miniscript renders
    // `expected node '{expected}', found '{actual}'`, so the first quoted run is what
    // the *parser wanted* — the refusal would have blamed the user for a form they
    // never typed, and an `'`-form origin in the message could yield `form: "/0"`.
    if message.contains("unrecognized name") {
        if let Some(form) = unrecognised_name(message) {
            return DescriptorError::UnsupportedForm { form };
        }
    }

    DescriptorError::parse(message)
}

/// The last number appearing before `marker`.
fn number_before(message: &str, marker: &str) -> Option<usize> {
    let head = if marker.is_empty() {
        message
    } else {
        message.split(marker).next()?
    };
    let digits: String = head
        .chars()
        .rev()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.chars().rev().collect::<String>().parse().ok()
}

/// Both halves of a "k-of-n" phrase.
fn threshold_pair(message: &str) -> Option<(usize, usize)> {
    let start = message.find("threshold ")? + "threshold ".len();
    let rest = &message[start..];
    let phrase: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-' || c.is_ascii_alphabetic())
        .collect();
    let (k, n) = phrase.split_once("-of-")?;
    Some((k.trim().parse().ok()?, n.trim().parse().ok()?))
}

/// The quoted name from "unrecognized name 'combo'".
///
/// Miniscript also says "unrecognized name" when a *key* confuses it — that is how
/// `sortedmulti_a` surfaces, blaming the xpub rather than the fragment. Those are not
/// form names, so anything shaped like a key is rejected here.
///
/// The test is what a descriptor fragment can actually look like — lowercase ASCII,
/// digits and `_` — rather than a length cutoff. An earlier draft used `len() > 12`,
/// which is both undocumented and wrong at the boundary: `sortedmulti_a` is 13.
fn unrecognised_name(message: &str) -> Option<String> {
    let start = message.find('\'')? + 1;
    let rest = &message[start..];
    let end = rest.find('\'')?;
    let name = &rest[..end];

    let looks_like_a_fragment = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');

    looks_like_a_fragment.then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slip132_prefixes_convert_losslessly() {
        // Only the four version bytes differ, so the round trip must return the
        // original — the conversion offered in the error has to be usable.
        let zpub = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF";
        let as_xpub = reencode(zpub, XPUB_VERSION).expect("converts");
        assert!(as_xpub.starts_with("xpub"));

        let back = reencode(&as_xpub, [0x04, 0xB2, 0x47, 0x46]).expect("converts back");
        assert_eq!(back, zpub);
    }

    #[test]
    fn a_non_key_string_does_not_convert() {
        assert!(reencode("not-a-key", XPUB_VERSION).is_none());
    }

    #[test]
    fn upstream_ceiling_messages_translate_to_distinct_variants() {
        let too_large = "The Miniscript corresponding Script cannot be larger than \
                         520 bytes, but got 547 bytes.";
        assert_eq!(
            translate_parse_error(too_large),
            DescriptorError::ScriptTooLarge {
                bytes: 547,
                limit: 520
            }
        );

        let too_many = "invalid threshold 1-of-21; maximum size is 20";
        assert_eq!(
            translate_parse_error(too_many),
            DescriptorError::TooManyKeys { keys: 21, max: 20 }
        );

        let over_threshold = "invalid threshold 3-of-2; cannot have k > n";
        assert_eq!(
            translate_parse_error(over_threshold),
            DescriptorError::ThresholdExceedsKeys {
                threshold: 3,
                keys: 2
            }
        );
    }

    /// A wording change upstream must degrade to `Parse`, not panic or mislabel.
    #[test]
    fn an_unrecognised_message_falls_back_to_parse() {
        match translate_parse_error("something entirely new") {
            DescriptorError::Parse { .. } => {}
            other => panic!("expected Parse, got {:?}", other),
        }
    }

    #[test]
    fn unknown_form_names_are_extracted_but_keys_are_not() {
        assert_eq!(
            unrecognised_name("unrecognized name 'combo'"),
            Some("combo".to_string())
        );
        assert_eq!(
            unrecognised_name("unrecognized name 'xpub661MyMwAqRbcFtXgS5sYJ'"),
            None
        );
    }
}
