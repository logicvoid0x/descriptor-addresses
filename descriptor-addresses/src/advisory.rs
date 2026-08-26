//! Non-fatal findings: true, worth saying, and not a reason to refuse.
//!
//! # Why a slice and not predicates
//!
//! The alternative shapes were both rejected on ticket 03. A bag of predicates
//! (`has_duplicate_keys()`, `origin_present()`, …) grows a method per finding and
//! makes the interface shallower with every one. Returning advisories in a tuple from
//! `parse` forces **every** call site to destructure something just to reach the happy
//! path, taxing the common case to serve the rare one.
//!
//! A slice does neither: a caller that does not care never looks, and one that does
//! gets the whole set from one accessor that never changes shape.

use core::fmt;

/// A finding that is worth reporting but is not a refusal.
///
/// `#[non_exhaustive]` for a specific, live reason rather than as a habit: the map
/// still holds open fog over **which NUMS constants this crate recognises**. That list
/// will grow, and it must be able to grow in a **patch** release — a caller who
/// matched exhaustively today would otherwise turn a widened recognition list into a
/// breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Advisory {
    /// A `tr()` internal key that is not on this crate's list of known NUMS points.
    ///
    /// Read this as a statement about **our list**, never about the key. See the
    /// `Display` text: this crate does not claim the key path is unspendable, because
    /// unspendability is not detectable in general.
    NumsUnrecognised {
        /// The internal key, as written.
        key: String,
    },

    /// At least one key that could carry a `[fingerprint/path]` origin did not.
    ///
    /// **Partial** absence counts: in a 2-of-3 where one cosigner's origin is missing,
    /// that is the key which will block a PSBT, so staying quiet until *all* origins
    /// are missing would report the easy case and hide the likely one.
    ///
    /// A raw `tr()` internal key is not counted — a NUMS point has no derivation path,
    /// so there is no origin it could ever state, and counting it made this advisory
    /// fire on every script-path-only taproot multisig with nothing wrong with it.
    OriginAbsent,

    /// The input carried no `#checksum`.
    ///
    /// Accepted, and the canonical form supplies one — but the user should know the
    /// checksum they are now looking at is ours rather than theirs.
    ChecksumAbsent,

    /// A key appeared more than once, under [`parse_permissive`].
    ///
    /// The strict constructor refuses this outright. The two carry the same fact in
    /// two places — [`DescriptorError::DuplicateKey`] and this — so the permissive
    /// path cannot drift into a different idea of what a duplicate is.
    ///
    /// [`parse_permissive`]: crate::ValidatedDescriptor::parse_permissive
    /// [`DescriptorError::DuplicateKey`]: crate::DescriptorError::DuplicateKey
    DuplicateKey {
        /// The key that appeared more than once.
        key: String,
    },

    /// The input used `'` for hardened steps and the canonical form uses `h`.
    ///
    /// The single most likely advisory to be mistaken for a problem, and the reason
    /// this channel exists at all. BIP-380 checksums literal characters, so rewriting
    /// the notation changes the checksum — measured on one key: `7nau6n94` against
    /// `fmqjkj0g`. Without an explanation, a user comparing our output against another
    /// wallet sees two different checksums and cannot tell a transcription error from
    /// a rendering choice.
    NotationRewritten,
}

impl fmt::Display for Advisory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The wording here is a decision, not a phrasing. "Not a NUMS point we
            // recognise" is a claim about our list, and a longer list makes it false
            // in the harmless direction. "The key path is unspendable" would be a
            // claim about the world that we cannot support: an arbitrary x-only key
            // may be a NUMS point tweaked by a value only its owner knows, or may be
            // someone's spending key, and telling them apart means knowing a discrete
            // log. Promising to warn on spendable key paths would be a lie in exactly
            // the case a deliberate attack would live in.
            Advisory::NumsUnrecognised { key } => write!(
                f,
                "the taproot internal key {} is not a NUMS point we recognise. It may \
                 still be unspendable — a NUMS point tweaked by a value only its owner \
                 knows looks like any other key — so this is a statement about our \
                 list, not about the key",
                key
            ),
            Advisory::OriginAbsent => write!(
                f,
                "no key origin is present. The descriptor derives correctly without \
                 one, but a coordinator needs the fingerprint to route a PSBT to the \
                 device that can sign it"
            ),
            Advisory::ChecksumAbsent => write!(
                f,
                "the input carried no checksum, so the one shown is ours rather than \
                 one you can compare against what you pasted"
            ),
            Advisory::DuplicateKey { key } => write!(
                f,
                "the key {} appears more than once, so the quorum is smaller than it \
                 looks — a 2-of-3 with a repeated key is a 1-of-2. Accepted because \
                 duplicates were explicitly allowed",
                key
            ),
            Advisory::NotationRewritten => write!(
                f,
                "hardened steps were rewritten from `'` to `h`, which is BIP-380's own \
                 notation and what Core, HWI, Coldcard and Sparrow emit. The checksum \
                 covers the literal characters, so it differs from the one on your \
                 input — the two descriptors are equivalent"
            ),
        }
    }
}

/// NUMS points this crate recognises.
///
/// One entry today: the BIP-341 constant, `H = lift_x(0x0250929b74…)`, defined as a
/// hash of the secp256k1 generator so that nobody knows its discrete log.
///
/// **The map's fog covers what else belongs here.** Wallets tweak the bare constant
/// precisely because using it unmodified makes an output identifiable on-chain as
/// key-path-disabled, so a longer list of documented conventions is plausible — and
/// [`Advisory`] is `#[non_exhaustive]` so adding one stays a patch release.
const KNOWN_NUMS: &[&str] = &["50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"];

/// Whether an internal key is one of the NUMS points we know.
///
/// Compared on the x-only hex, so an equivalent key written with a `02`/`03` prefix
/// or wrapped in an origin still matches: a taproot internal key *is* x-only, and the
/// notation it arrived in should not change the answer.
pub(crate) fn is_known_nums(key: &str) -> bool {
    let bare = key
        .rsplit(']')
        .next()
        .unwrap_or(key)
        .split('/')
        .next()
        .unwrap_or(key);

    // A SEC compressed key is 33 bytes — a parity prefix plus 32 bytes of
    // x-coordinate — so 66 hex characters. BIP-340's x-only encoding is the same 32
    // bytes without the prefix, so 64 characters. Taproot keys are x-only, so a key
    // written with its parity byte is the same point and must compare equal.
    //
    // `get` rather than `&bare[2..]`: the length is in bytes, so a 66-byte non-ASCII
    // string would panic on a char boundary. Unreachable from `parse` today, and this
    // is on the boundary the spec requires fuzzing.
    let x_only = match bare.len() {
        66 => bare.get(2..).unwrap_or(bare),
        _ => bare,
    };

    KNOWN_NUMS
        .iter()
        .any(|known| known.eq_ignore_ascii_case(x_only))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

    #[test]
    fn the_bip341_constant_is_recognised_in_every_notation() {
        assert!(is_known_nums(NUMS));
        assert!(is_known_nums(&NUMS.to_uppercase()));
        // With a parity byte, which taproot discards.
        assert!(is_known_nums(&format!("02{}", NUMS)));
        // Behind an origin.
        assert!(is_known_nums(&format!("[aabbccdd/86h/0h/0h]{}", NUMS)));
    }

    #[test]
    fn an_ordinary_key_is_not_recognised() {
        assert!(!is_known_nums(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        ));
        assert!(!is_known_nums(""));
    }

    /// The claim this crate must never make, asserted on the text itself so a future
    /// rewording cannot quietly reintroduce it.
    #[test]
    fn the_nums_advisory_never_claims_unspendability() {
        let rendered = format!(
            "{}",
            Advisory::NumsUnrecognised {
                key: NUMS.to_string()
            }
        );

        assert!(rendered.contains("not a NUMS point we recognise"));
        assert!(!rendered.to_lowercase().contains("is unspendable"));
        assert!(!rendered.to_lowercase().contains("cannot be spent"));
    }
}
