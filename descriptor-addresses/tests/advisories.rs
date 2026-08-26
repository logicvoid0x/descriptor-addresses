//! Seam 1 — advisories.
//!
//! Unit-tested rather than covered by the golden corpus, and deliberately: advisories
//! are **our own concept**. Bitcoin Core has no opinion about whether a descriptor
//! carried a checksum, so there is no second implementation to reconcile against and
//! a corpus entry would only be checking us against ourselves.

use descriptor_addresses::{Advisory, DescriptorError, Network, ValidatedDescriptor};

const X1: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const X2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const X3: &str = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";

/// The BIP-341 nothing-up-my-sleeve point, as a plain x-only key.
///
/// `H = lift_x(0x0250929b74…)`, defined in BIP-341 as the hash of the secp256k1
/// generator point. A `tr()` using it has a key path nobody can spend, which is how a
/// script-path-only taproot output is conventionally written.
const NUMS: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

fn parse(descriptor: &str) -> ValidatedDescriptor {
    ValidatedDescriptor::parse(descriptor, Network::Bitcoin)
        .unwrap_or_else(|e| panic!("{}: {}", descriptor, e))
}

fn permissive(descriptor: &str) -> ValidatedDescriptor {
    ValidatedDescriptor::parse_permissive(descriptor, Network::Bitcoin)
        .unwrap_or_else(|e| panic!("{}: {}", descriptor, e))
}

// ============================================================ the channel

/// A caller reaching the happy path must not have to destructure anything. That is
/// the whole reason advisories are a separate accessor rather than a tuple returned
/// from `parse`.
#[test]
fn a_clean_descriptor_reports_nothing() {
    let d = parse(&format!(
        "wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)#4ws9vksj",
        X1
    ));

    assert!(d.advisories().is_empty(), "got: {:?}", d.advisories());
}

/// Computed once at parse and stored, not recomputed per call — so reading them
/// twice cannot disagree, and a scanning loop pays nothing.
#[test]
fn advisories_are_stable_across_reads() {
    let d = parse(&format!("wpkh({}/<0;1>/*)", X1));

    assert_eq!(d.advisories(), d.advisories());
    assert!(!d.advisories().is_empty());
}

// ============================================================ each finding

#[test]
fn an_absent_checksum_is_reported() {
    let d = parse(&format!("wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)", X1));

    assert!(d.advisories().contains(&Advisory::ChecksumAbsent));
}

/// A coordinator needs the fingerprint to route a PSBT to the right signing device,
/// so its absence is worth saying out loud even though the descriptor is valid.
#[test]
fn an_absent_key_origin_is_reported() {
    let d = parse(&format!("wpkh({}/<0;1>/*)", X1));

    assert!(d.advisories().contains(&Advisory::OriginAbsent));
}

/// Only when it is genuinely absent — a descriptor that carries origins must not be
/// nagged about them.
#[test]
fn a_present_origin_is_not_reported() {
    let d = parse(&format!("wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)", X1));

    assert!(!d.advisories().contains(&Advisory::OriginAbsent));
}

/// Multisig: one key with an origin and one without is still an absence worth
/// reporting, because the missing one is the one that will block a PSBT.
#[test]
fn a_partially_origined_multisig_reports_the_absence() {
    let d = parse(&format!(
        "wsh(sortedmulti(2,[aabbccdd/48h/0h/0h/2h]{}/<0;1>/*,{}/<0;1>/*))",
        X1, X2
    ));

    assert!(d.advisories().contains(&Advisory::OriginAbsent));
}

/// A fully-origined script-path taproot multisig must report **no** missing origin.
///
/// The NUMS internal key has no derivation path, so there is no origin it could ever
/// carry. Counting it made this advisory fire on the canonical form with nothing
/// wrong with it — and an advisory that fires on healthy input is how a reporting
/// channel teaches people to ignore it. Found by a reviewer executing this input.
#[test]
fn a_fully_origined_taproot_multisig_reports_no_missing_origin() {
    let d = parse(&format!(
        "tr({},multi_a(2,[aabbccdd/48h/0h/0h/2h]{}/<0;1>/*,[11223344/48h/0h/0h/2h]{}/<0;1>/*))",
        NUMS, X2, X3
    ));

    assert_eq!(d.origins().len(), 2, "both signing keys carry an origin");
    assert!(
        !d.advisories().contains(&Advisory::OriginAbsent),
        "got: {:?}",
        d.advisories()
    );
}

/// The paired case: a genuinely missing origin in the same shape is still reported, so
/// the exemption above did not simply switch the advisory off for taproot.
#[test]
fn a_taproot_multisig_missing_an_origin_still_reports_it() {
    let d = parse(&format!(
        "tr({},multi_a(2,[aabbccdd/48h/0h/0h/2h]{}/<0;1>/*,{}/<0;1>/*))",
        NUMS, X2, X3
    ));

    assert!(d.advisories().contains(&Advisory::OriginAbsent));
}

/// The one that makes a differing checksum read as an explanation rather than an
/// alarm. Without it, a user who pasted `'`-notation sees a checksum that does not
/// match the one their other wallet shows and has no way to tell whether that is a
/// transcription error or a rendering choice.
#[test]
fn rewriting_apostrophes_to_h_form_is_reported() {
    let d = parse(&format!("wpkh([aabbccdd/84'/0'/0']{}/<0;1>/*)", X1));

    assert!(
        d.advisories().contains(&Advisory::NotationRewritten),
        "got: {:?}",
        d.advisories()
    );
    // And the rewrite really did happen.
    assert!(d.canonical().contains("84h/0h/0h"));
}

#[test]
fn h_form_input_is_not_reported_as_rewritten() {
    let d = parse(&format!("wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)", X1));

    assert!(!d.advisories().contains(&Advisory::NotationRewritten));
}

// ============================================================ duplicate keys

/// The permissive constructor moves the finding from `DescriptorError::DuplicateKey`
/// to `Advisory::DuplicateKey` — the same fact, relocated, so the two paths cannot
/// drift into disagreeing about what a duplicate is.
#[test]
fn a_duplicate_key_becomes_an_advisory_under_the_permissive_constructor() {
    let descriptor = format!("wsh(multi(2,{}/0/*,{}/0/*))", X1, X1);
    let d = permissive(&descriptor);

    let reported = d
        .advisories()
        .iter()
        .any(|a| matches!(a, Advisory::DuplicateKey { key } if key.contains("xpub661MyMwAqRbcF")));
    assert!(reported, "got: {:?}", d.advisories());
}

/// The strict constructor refuses it, so the advisory can never appear there. This is
/// the pairing that keeps the two constructors describing one rule.
#[test]
fn the_strict_constructor_never_produces_a_duplicate_advisory() {
    let descriptor = format!("wsh(multi(2,{}/0/*,{}/0/*))", X1, X1);

    // The specific variant, not `is_err()` — the point is that the strict path
    // reports *this* finding, so a different refusal would mean the two constructors
    // had stopped describing one rule.
    match ValidatedDescriptor::parse(&descriptor, Network::Bitcoin) {
        Err(DescriptorError::DuplicateKey { key }) => {
            assert!(key.contains("xpub661MyMwAqRbcF"))
        }
        other => panic!("expected DuplicateKey, got {:?}", other.map(|_| ())),
    }

    // And on input it *does* accept, no duplicate advisory is invented.
    let clean = parse(&format!("wsh(multi(2,{}/0/*,{}/0/*))", X1, X2));
    assert!(!clean
        .advisories()
        .iter()
        .any(|a| matches!(a, Advisory::DuplicateKey { .. })));
}

// ============================================================ NUMS

/// The wording constraint, and the reason this crate reports rather than adjudicates.
///
/// An unrecognised internal key means **we did not recognise it** — not that the key
/// path is unspendable. Unspendability is not detectable in general: an arbitrary
/// x-only key may be a NUMS point tweaked by a value only its owner knows, or may
/// simply be someone's spending key, and telling them apart means knowing a discrete
/// log. A feature promising to warn on spendable key paths would be lying in exactly
/// the case a deliberate attack would live in.
#[test]
fn an_unrecognised_internal_key_is_reported_without_claiming_unspendability() {
    let d = parse(&format!(
        "tr({}/<0;1>/*,multi_a(2,{}/<0;1>/*,{}/<0;1>/*))",
        X1, X2, X3
    ));

    let advisory = d
        .advisories()
        .iter()
        .find(|a| matches!(a, Advisory::NumsUnrecognised { .. }))
        .unwrap_or_else(|| panic!("expected NumsUnrecognised, got {:?}", d.advisories()));

    let rendered = format!("{}", advisory);
    assert!(
        rendered.contains("not a NUMS point we recognise"),
        "got: {}",
        rendered
    );

    // The claims we must never make. Note the text *does* contain the word
    // "unspendable" — in "it may still be unspendable", which is the honest
    // statement: we are declining to rule it out, which is the opposite of asserting
    // it. Banning the word outright would have forced out the sentence that makes
    // the advisory truthful, so the assertion targets the claim rather than a token.
    let lower = rendered.to_lowercase();
    assert!(!lower.contains("is unspendable"), "got: {}", rendered);
    assert!(!lower.contains("cannot be spent"), "got: {}", rendered);
    assert!(!lower.contains("key path is disabled"), "got: {}", rendered);
}

/// The paired case: the BIP-341 constant *is* recognised, so it produces no advisory.
/// Without this, "we did not recognise it" could be true of everything and the
/// advisory would carry no information.
#[test]
fn the_bip341_nums_point_is_recognised() {
    let d = parse(&format!(
        "tr({},multi_a(2,{}/<0;1>/*,{}/<0;1>/*))",
        NUMS, X2, X3
    ));

    assert!(
        !d.advisories()
            .iter()
            .any(|a| matches!(a, Advisory::NumsUnrecognised { .. })),
        "the BIP-341 constant should be recognised, got: {:?}",
        d.advisories()
    );
}

/// A key-path-only `tr()` has no script path, so its internal key is meant to be
/// spendable and saying "that is not a NUMS point" would be noise on every ordinary
/// taproot wallet.
#[test]
fn a_key_path_only_taproot_gets_no_nums_advisory() {
    let d = parse(&format!("tr([aabbccdd/86h/0h/0h]{}/<0;1>/*)", X1));

    assert!(
        !d.advisories()
            .iter()
            .any(|a| matches!(a, Advisory::NumsUnrecognised { .. })),
        "got: {:?}",
        d.advisories()
    );
}

/// Non-taproot forms have no internal key at all.
#[test]
fn non_taproot_forms_get_no_nums_advisory() {
    let d = parse(&format!("wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)", X1));

    assert!(!d
        .advisories()
        .iter()
        .any(|a| matches!(a, Advisory::NumsUnrecognised { .. })));
}

// ============================================================ combinations

/// Several findings at once, each reported once. A descriptor can be imperfect in
/// more than one way and the caller should see all of it.
#[test]
fn independent_findings_are_all_reported() {
    // No checksum, no origin, apostrophe notation in the key path.
    let d = parse(&format!(
        "wsh(sortedmulti(2,{}/<0;1>/*,{}/<0;1>/*))",
        X1, X2
    ));

    assert!(d.advisories().contains(&Advisory::ChecksumAbsent));
    assert!(d.advisories().contains(&Advisory::OriginAbsent));

    // Each finding appears once, not once per key.
    let origin_count = d
        .advisories()
        .iter()
        .filter(|a| **a == Advisory::OriginAbsent)
        .count();
    assert_eq!(origin_count, 1);
}
