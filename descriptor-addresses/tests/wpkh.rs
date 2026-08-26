//! Seam 1 — the library's public API.
//!
//! The key is BIP-32 test vector 1's master public key (seed `000102…0f`), so the
//! descriptor itself is anchored to a published document. The *addresses* here are
//! not: BIP-32 publishes keys, not addresses, so these values were produced by this
//! stack and are pinned as a regression baseline. Agreement with an independent
//! implementation is ticket 10's job (the golden corpus against Bitcoin Core), and
//! nothing in this file should be read as establishing it.
//!
//! The canonical checksum asserted below (`7nau6n94`) is the one exception: it was
//! measured and recorded on the Derivation Output and CLI Surface decision ticket
//! before this crate existed, so it is a genuine external check on the h-form rule.

use descriptor_addresses::{DescriptorError, Network, NormalIndex, ValidatedDescriptor};

const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

fn h_form() -> String {
    format!("wpkh([d34db33f/84h/0h/0h]{}/<0;1>/*)", XPUB)
}

fn tick_form() -> String {
    format!("wpkh([d34db33f/84'/0'/0']{}/<0;1>/*)", XPUB)
}

fn idx(i: u32) -> NormalIndex {
    NormalIndex::new(i).expect("index is below the hardened boundary")
}

#[test]
fn derives_the_external_keychain() {
    let d = ValidatedDescriptor::parse(&h_form(), Network::Bitcoin).expect("valid wpkh");

    let expected = [
        "bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz",
        "bc1qrfxr69jqnhwufxgkqgcdep9prq4j4vuw2wyg0v",
        "bc1qhvd6suvqzjcu9pxjhrwhtrlj85ny3n2mqql5w4",
        "bc1qjzgwzugce3mqfvn2cdq8wt8drz50mf6je9utcl",
        "bc1q4lrflkd0sddm4ktujw8e5syxmlwcdprdtzvamp",
    ];

    for (i, want) in expected.iter().enumerate() {
        let rec = d.external().address_at(idx(i as u32));
        assert_eq!(rec.address().to_string(), *want, "external index {}", i);
        assert_eq!(rec.relative_path(), format!("0/{}", i));
    }
}

#[test]
fn derives_the_internal_keychain() {
    let d = ValidatedDescriptor::parse(&h_form(), Network::Bitcoin).expect("valid wpkh");
    let internal = d
        .internal()
        .expect("two-path descriptor has a change keychain");

    let expected = [
        "bc1q7zwtzcqsm3k43ha0ac7nl8cz0hqrhckywf6sew",
        "bc1qf7x2v0de6hvgv6tke54pyzmkc9022wh5j3f6y5",
        "bc1qa3ht4xx9evh8dp8p66tzftu45zccugw4lnc6nn",
    ];

    for (i, want) in expected.iter().enumerate() {
        let rec = internal.address_at(idx(i as u32));
        assert_eq!(rec.address().to_string(), *want, "internal index {}", i);
        assert_eq!(rec.relative_path(), format!("1/{}", i));
    }
}

/// A single-path descriptor has no change keychain, and that absence is an `Option`
/// rather than a silent fallback to the external chain — the failure mode being
/// refused is asking for change and quietly receiving receive addresses.
#[test]
fn single_path_input_has_no_internal_keychain() {
    let single = format!("wpkh({}/0/*)", XPUB);
    let d = ValidatedDescriptor::parse(&single, Network::Bitcoin).expect("valid wpkh");

    assert!(d.internal().is_none());
    assert_eq!(
        d.external().address_at(idx(0)).address().to_string(),
        "bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz"
    );
}

/// BIP-380 checksums the literal characters, so the h-form and the `'`-form of one
/// descriptor carry *different* valid checksums. Emitting `'` would hand the user a
/// checksum disagreeing with the one their own wallet shows.
#[test]
fn canonical_form_is_h_notation_and_round_trips_byte_identically() {
    let input = h_form();
    let d = ValidatedDescriptor::parse(&input, Network::Bitcoin).expect("valid wpkh");

    assert_eq!(d.canonical(), format!("{}#7nau6n94", input));
    assert!(!d.canonical().contains('\''));

    // Feeding our own output back in must produce that same output, checksum included.
    let again = ValidatedDescriptor::parse(d.canonical(), Network::Bitcoin).expect("round trip");
    assert_eq!(again.canonical(), d.canonical());
}

#[test]
fn apostrophe_input_is_accepted_and_normalised_to_h_form() {
    let d = ValidatedDescriptor::parse(&tick_form(), Network::Bitcoin).expect("valid wpkh");

    assert_eq!(d.canonical(), format!("{}#7nau6n94", h_form()));
}

#[test]
fn a_record_carries_the_script_pubkey_and_script_type() {
    let d = ValidatedDescriptor::parse(&h_form(), Network::Bitcoin).expect("valid wpkh");
    let rec = d.external().address_at(idx(0));

    assert_eq!(rec.script_type().form(), "wpkh");
    assert!(rec.script_type().recognised());
    // P2WPKH: OP_0 (0x00) then a 20-byte push (0x14).
    assert_eq!(&rec.script_pubkey().to_bytes()[..2], &[0x00, 0x14]);
}

#[test]
fn network_is_bound_at_construction() {
    let d = ValidatedDescriptor::parse(&h_form(), Network::Bitcoin).expect("valid wpkh");
    assert_eq!(d.network(), Network::Bitcoin);
}

// A test asserting `pkh` was refused lived here while `wpkh` was the only supported
// form. Ticket 03 admitted `pkh` to the allowlist, which made that assertion false —
// correctly, and the test failing was the signal. Allowlist coverage, acceptances and
// refusals alike, now lives in forms.rs, which is the file that owns the policy.

/// Observed against miniscript 13.1.0: a hardened wildcard parses, reports its
/// descriptor type, passes miniscript's own `sanity_check()`, and then PANICS on
/// derivation. `address_at` is infallible, so this input cannot be allowed to reach
/// it. Ticket 04 owns the full rule; this asserts the guard.
///
/// The variant matters more here than anywhere else in this file. `is_err()` would
/// pass just as happily if this were refused as an unsupported form — which is to
/// say, it would keep passing after the panic guard stopped working.
#[test]
fn hardened_wildcard_is_refused_before_it_can_panic() {
    for descriptor in [
        format!("wpkh({}/0/*h)", XPUB),
        format!("wpkh({}/0/*')", XPUB),
        format!("wpkh({}/<0;1>/*h)", XPUB),
    ] {
        let err = ValidatedDescriptor::parse(&descriptor, Network::Bitcoin).unwrap_err();
        assert_eq!(
            err,
            DescriptorError::HardenedWildcard,
            "input: {}",
            descriptor
        );
    }
}

/// The keychain split needs exactly one or two paths to be unambiguous, so the
/// boundary is asserted from both sides: three paths refused with the variant that
/// says so, and one and two paths accepted. The acceptance is what proves the guard
/// is not drawn one path early — refusing a legitimate two-path wallet would be a
/// silent failure for every user who has one.
///
/// BIP-389's uniformity rules, and the mismatched-length refusal, are ticket 04's.
#[test]
fn the_path_arity_boundary_is_enforced_from_both_sides() {
    let three = format!("wpkh({}/<0;1;2>/*)", XPUB);
    let err = ValidatedDescriptor::parse(&three, Network::Bitcoin).unwrap_err();
    assert_eq!(err, DescriptorError::MultipathArity { paths: 3 });

    let two = ValidatedDescriptor::parse(&h_form(), Network::Bitcoin).expect("two paths accepted");
    assert!(two.internal().is_some());

    let one = ValidatedDescriptor::parse(&format!("wpkh({}/0/*)", XPUB), Network::Bitcoin)
        .expect("one path accepted");
    assert!(one.internal().is_none());
}

/// Mirrors the example in the crate-level documentation.
///
/// Doctests are the natural home for this, but `rustdoc.exe` is blocked by an
/// Application Control policy on the development machine, so the documented example
/// would otherwise ship unverified. Ticket 02's CI matrix runs doctests on Linux;
/// until then this is what actually exercises it.
#[test]
fn the_documented_example_works() {
    let wallet =
        ValidatedDescriptor::parse(&format!("wpkh({}/<0;1>/*)", XPUB), Network::Bitcoin).unwrap();

    let first = wallet.external().address_at(NormalIndex::ZERO);
    assert_eq!(first.relative_path(), "0/0");

    let change = wallet.internal().expect("two-path descriptor");
    assert_eq!(change.address_at(NormalIndex::ZERO).relative_path(), "1/0");
}

/// The lazy iterator is the scanning path a coordinator uses, so it must agree with
/// the at-index call rather than being a second implementation of it.
#[test]
fn the_iterator_agrees_with_address_at() {
    let d = ValidatedDescriptor::parse(&h_form(), Network::Bitcoin).expect("valid wpkh");
    let external = d.external();

    let scanned: Vec<String> = external
        .addresses(idx(0), 5)
        .map(|r| r.address().to_string())
        .collect();

    let direct: Vec<String> = (0..5)
        .map(|i| external.address_at(idx(i)).address().to_string())
        .collect();

    assert_eq!(scanned, direct);
    assert_eq!(scanned.len(), 5);
}

/// Deriving from the last normal index must stop rather than wrap into the hardened
/// half, where derivation would need a private key this crate never holds.
#[test]
fn the_iterator_stops_at_the_top_of_the_normal_range() {
    let d = ValidatedDescriptor::parse(&h_form(), Network::Bitcoin).expect("valid wpkh");
    let last = NormalIndex::new(2_147_483_647).unwrap();

    let produced: Vec<_> = d.external().addresses(last, 5).collect();
    assert_eq!(produced.len(), 1, "only the final normal index exists");
    assert_eq!(produced[0].relative_path(), "0/2147483647");
}

#[test]
fn normal_index_cannot_hold_a_hardened_value() {
    assert!(NormalIndex::new(0).is_some());
    assert!(NormalIndex::new(2_147_483_647).is_some()); // 2^31 - 1, the last normal index
    assert!(NormalIndex::new(2_147_483_648).is_none()); // 2^31, the first hardened index
    assert!(NormalIndex::new(u32::MAX).is_none());
}
