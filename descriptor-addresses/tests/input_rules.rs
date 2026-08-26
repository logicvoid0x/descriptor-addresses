//! Seam 1 — the negative roster, and the acceptances that bound it.
//!
//! Two rules govern this file, both from the spec's Testing Decisions:
//!
//! 1. **Assert the specific variant, never `is_err()`.** A test that passes because
//!    the *wrong* error fired is worse than no test, and this crate has several
//!    errors that could plausibly substitute for each other — `UnsupportedForm` and
//!    `TooManyKeys` would both "fail" on a 21-key `wsh(multi)`.
//! 2. **Pair every boundary rejection with an acceptance.** The rejection proves a
//!    limit is enforced; the acceptance proves it is not enforced one step early. An
//!    off-by-one that refuses a legitimate 15-of-15 wallet is a real failure and is
//!    otherwise silent.

use descriptor_addresses::{DescriptorError, KeyError, Network, NetworkClass, ValidatedDescriptor};

const X1: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const X2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const X3: &str = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
const TPUB: &str = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
const ZPUB: &str = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF";
const YPUB: &str = "ypub6QqdH2c5z7967aF6HwpNZVNJ3K9AN5Gn29rt2H9zC1TCRSF9pd2zEUKrPFsAWZxeqPZAJXFwmXvmpBcRkX9GjNdSPfnPPXAeUpMuJnbGaVR";

fn refuse(descriptor: &str) -> DescriptorError {
    ValidatedDescriptor::parse(descriptor, Network::Bitcoin)
        .err()
        .unwrap_or_else(|| panic!("expected a refusal: {}", descriptor))
}

fn refuse_on(descriptor: &str, network: Network) -> DescriptorError {
    ValidatedDescriptor::parse(descriptor, network)
        .err()
        .unwrap_or_else(|| panic!("expected a refusal: {}", descriptor))
}

fn accept(descriptor: &str) -> ValidatedDescriptor {
    ValidatedDescriptor::parse(descriptor, Network::Bitcoin)
        .unwrap_or_else(|e| panic!("expected acceptance of {}: {}", descriptor, e))
}

/// `n` keys under one wrapper, for walking up to a key-count ceiling.
fn with_keys(template: &str, n: usize) -> String {
    let keys: Vec<String> = (0..n).map(|i| format!("{}/{}/*", X1, i)).collect();
    template.replace("KEYS", &keys.join(","))
}

// =========================================================== checksums

#[test]
fn a_wrong_checksum_is_fatal_and_reports_the_one_expected() {
    let descriptor = format!("wpkh({}/0/*)#00000000", X1);

    match refuse(&descriptor) {
        DescriptorError::ChecksumMismatch { found, expected } => {
            assert_eq!(found, "00000000");
            // Reporting the expected checksum is the whole point: a transcription
            // slip is fixed by comparing two short strings, and the user cannot do
            // that if we withhold ours.
            assert_eq!(expected, "wvk84d79");
        }
        other => panic!("expected ChecksumMismatch, got {:?}", other),
    }
}

#[test]
fn more_than_one_checksum_separator_is_refused() {
    let descriptor = format!("wpkh({}/0/*)#wvk84d79#wvk84d79", X1);

    match refuse(&descriptor) {
        DescriptorError::ChecksumMalformed { detail } => {
            assert!(detail.contains('#'), "should name the problem: {}", detail)
        }
        other => panic!("expected ChecksumMalformed, got {:?}", other),
    }
}

/// The paired acceptance: absent is fine, and the canonical form supplies one.
#[test]
fn an_absent_checksum_is_accepted_and_the_canonical_form_carries_one() {
    let d = accept(&format!("wpkh({}/0/*)", X1));

    assert!(d.canonical().ends_with("#wvk84d79"));
}

#[test]
fn a_correct_checksum_round_trips() {
    let d = accept(&format!("wpkh({}/0/*)#wvk84d79", X1));

    assert_eq!(d.canonical(), format!("wpkh({}/0/*)#wvk84d79", X1));
}

// =========================================================== SLIP-132

/// The error carries both halves of what the user needs: the equivalent xpub, and
/// the script type the prefix was implying. We refuse to act on that implication —
/// choosing a script type is exactly the decision this crate exists to stop tools
/// making silently — but we do not withhold it either.
#[test]
fn a_zpub_is_refused_with_its_conversion_and_implied_script_type() {
    let descriptor = format!("wpkh({}/0/*)", ZPUB);

    match refuse(&descriptor) {
        DescriptorError::Key(KeyError::Slip132 {
            prefix,
            converted,
            implies,
        }) => {
            assert_eq!(prefix, "zpub");
            assert_eq!(implies, "wpkh");
            assert!(converted.starts_with("xpub"), "got: {}", converted);
            // Converting must actually work, not merely be attempted.
            assert_eq!(
                converted,
                "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8"
            );
        }
        other => panic!("expected Slip132, got {:?}", other),
    }
}

#[test]
fn a_ypub_names_the_nested_segwit_script_type_it_implies() {
    let descriptor = format!("sh(wpkh({}/0/*))", YPUB);

    match refuse(&descriptor) {
        DescriptorError::Key(KeyError::Slip132 {
            prefix, implies, ..
        }) => {
            assert_eq!(prefix, "ypub");
            assert_eq!(implies, "sh(wpkh)");
        }
        other => panic!("expected Slip132, got {:?}", other),
    }
}

// =========================================================== network

/// Granularity is xpub-versus-tpub and nothing finer. testnet, testnet4 and signet
/// share one set of version bytes, so a tpub cannot tell us which of the three a user
/// meant — and the crate must not pretend it can.
#[test]
fn a_testnet_key_declared_as_mainnet_is_refused() {
    let descriptor = format!("wpkh({}/0/*)", TPUB);

    match refuse_on(&descriptor, Network::Bitcoin) {
        DescriptorError::NetworkMismatch { declared, found } => {
            // Typed, so a caller can branch on it rather than scraping a sentence.
            assert_eq!(declared, NetworkClass::Mainnet);
            assert_eq!(found, NetworkClass::Test);
        }
        other => panic!("expected NetworkMismatch, got {:?}", other),
    }
}

#[test]
fn a_mainnet_key_declared_as_testnet_is_refused() {
    let descriptor = format!("wpkh({}/0/*)", X1);

    match refuse_on(&descriptor, Network::Testnet) {
        DescriptorError::NetworkMismatch { .. } => {}
        other => panic!("expected NetworkMismatch, got {:?}", other),
    }
}

#[test]
fn a_descriptor_mixing_networks_is_refused() {
    let descriptor = format!("wsh(sortedmulti(2,{}/0/*,{}/0/*))", X1, TPUB);

    match refuse(&descriptor) {
        DescriptorError::MixedNetworks => {}
        other => panic!("expected MixedNetworks, got {:?}", other),
    }
}

/// The paired acceptance: a tpub on any of the three test networks is fine, and all
/// three are accepted from the same key because they are genuinely indistinguishable.
#[test]
fn a_testnet_key_is_accepted_on_each_indistinguishable_test_network() {
    for network in [Network::Testnet, Network::Signet, Network::Regtest] {
        let d = ValidatedDescriptor::parse(&format!("wpkh({}/0/*)", TPUB), network)
            .unwrap_or_else(|e| panic!("{:?}: {}", network, e));
        assert_eq!(d.network(), network);
    }
}

// =========================================================== multipath

#[test]
fn three_derivation_paths_are_refused() {
    match refuse(&format!("wpkh({}/<0;1;2>/*)", X1)) {
        DescriptorError::MultipathArity { paths } => assert_eq!(paths, 3),
        other => panic!("expected MultipathArity, got {:?}", other),
    }
}

/// The observed hazard, and the reason this check exists at all.
///
/// `<0;1>` beside `<0;1;2>` passes miniscript's `sanity_check()` and yields **two**
/// descriptors with the third branch silently discarded — so an arity check alone
/// sees two paths and waves it through. Worse, the behaviour is order-dependent:
/// with the longer tuple first, `into_single_descriptors` errors; with it second, it
/// truncates. Both orders are asserted, because a guard that only catches one is a
/// guard that catches the safe case.
#[test]
fn mismatched_multipath_lengths_are_refused_rather_than_truncated() {
    for descriptor in [
        format!("wsh(sortedmulti(2,{}/<0;1>/*,{}/<0;1;2>/*))", X1, X2),
        format!("wsh(sortedmulti(2,{}/<0;1;2>/*,{}/<0;1>/*))", X1, X2),
    ] {
        match refuse(&descriptor) {
            DescriptorError::MultipathNonUniform { found } => {
                assert_eq!(found.len(), 2, "both key tuples should be reported");
                assert_ne!(found[0], found[1]);
            }
            other => panic!(
                "expected MultipathNonUniform for {}, got {:?}",
                descriptor, other
            ),
        }
    }
}

/// Same length, different values: `<0;1>` beside `<2;3>`. Nothing is truncated, but
/// the two keys disagree about which chain is which, so the change chain of one key
/// is paired with the receive chain of another.
#[test]
fn multipath_tuples_that_differ_in_value_are_refused() {
    let descriptor = format!("wsh(sortedmulti(2,{}/<0;1>/*,{}/<2;3>/*))", X1, X2);

    match refuse(&descriptor) {
        DescriptorError::MultipathNonUniform { .. } => {}
        other => panic!("expected MultipathNonUniform, got {:?}", other),
    }
}

/// The paired acceptance for the whole multipath family.
#[test]
fn uniform_two_path_multipath_is_accepted_on_every_key() {
    let d = accept(&format!(
        "wsh(sortedmulti(2,[aabbccdd/48h/0h/0h/2h]{}/<0;1>/*,[11223344/48h/0h/0h/2h]{}/<0;1>/*))",
        X1, X2
    ));

    assert!(d.internal().is_some());
}

/// Either every key is two-path or none is.
///
/// BIP-389 permits the mix and discards nothing, which makes "accept it" a persuasive
/// and **wrong** conclusion — the one this implementation first reached. The harm is
/// not truncation: miniscript copies the non-multipath key into both expansions, so
/// the change descriptor reuses a key from the receive descriptor. That links the two
/// chains on-chain permanently, and it looks like nothing on screen because the
/// addresses still differ. Settled by Accepted Input and Script Policy, Q11.
#[test]
fn mixing_multipath_and_single_path_keys_is_refused() {
    let descriptor = format!("wsh(sortedmulti(2,{}/<0;1>/*,{}/0/*))", X1, X2);

    match refuse(&descriptor) {
        DescriptorError::MultipathNonUniform { found } => {
            assert_eq!(found, vec!["<0;1>".to_string(), "0".to_string()]);
        }
        other => panic!("expected MultipathNonUniform, got {:?}", other),
    }
}

/// Ordinary fixed paths differing between keys is not a multipath question at all —
/// it is just two keys at different positions, and it must not be caught by the
/// uniformity rule.
#[test]
fn keys_at_different_fixed_paths_are_accepted() {
    accept(&format!("wsh(sortedmulti(2,{}/0/*,{}/5/*))", X1, X2));
}

// =========================================================== hardened wildcard

/// Observed against miniscript 13.1.0: this parses, reports its descriptor type,
/// passes `sanity_check()`, and then **panics** on derivation. Since `address_at` is
/// infallible, this refusal is the only thing standing between pasted input and a
/// process abort.
#[test]
fn a_hardened_wildcard_is_refused_in_every_notation() {
    for descriptor in [
        format!("wpkh({}/0/*h)", X1),
        format!("wpkh({}/0/*')", X1),
        format!("wpkh({}/<0;1>/*h)", X1),
        format!("wsh(sortedmulti(2,{}/0/*h,{}/0/*))", X1, X2),
    ] {
        assert_eq!(
            refuse(&descriptor),
            DescriptorError::HardenedWildcard,
            "input: {}",
            descriptor
        );
    }
}

/// The paired acceptance: hardened steps are perfectly legal *before* the wildcard,
/// and a BIP-84 account path is nothing but hardened steps.
#[test]
fn hardened_steps_before_the_wildcard_are_accepted() {
    accept(&format!("wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)", X1));
    accept(&format!("wpkh([aabbccdd/84'/0'/0']{}/<0;1>/*)", X1));
}

// =========================================================== duplicate keys

/// A duplicate key in a 2-of-3 means the quorum is not what it appears: two of the
/// three "signers" are one key, so a 2-of-3 is really a 1-of-2. That is a footgun
/// worth refusing to manufacture.
#[test]
fn a_duplicate_key_is_an_error_by_default() {
    let descriptor = format!("wsh(multi(2,{}/0/*,{}/0/*))", X1, X1);

    match refuse(&descriptor) {
        DescriptorError::DuplicateKey { key } => {
            assert!(
                key.contains("xpub661MyMwAqRbcF"),
                "should name the key: {}",
                key
            )
        }
        other => panic!("expected DuplicateKey, got {:?}", other),
    }
}

/// The narrow opt-in. It downgrades duplicates and **relaxes nothing else** — the
/// property test in a later ticket asserts the two constructors differ in exactly one
/// variant; here it is enough that a permissive parse still refuses other things.
#[test]
fn the_permissive_constructor_accepts_duplicates_and_nothing_else() {
    let duplicate = format!("wsh(multi(2,{}/0/*,{}/0/*))", X1, X1);
    let permissive = ValidatedDescriptor::parse_permissive(&duplicate, Network::Bitcoin)
        .expect("permissive accepts a duplicate key");
    assert_eq!(permissive.script_type().form(), "wsh(multi)");

    // Everything else it refuses exactly as the strict constructor does — and with
    // the *same variant*, not merely with some error. `is_err()` here would stay
    // green if the permissive path regressed to reporting `DuplicateKey` for all
    // four, which is precisely the test the spec's first testing rule forbids.
    let cases = [
        (format!("wpkh({}/0/*h)", X1), "HardenedWildcard"),
        (format!("wpkh({}/0/*)#00000000", X1), "ChecksumMismatch"),
        (format!("wpkh({}/0/*)", ZPUB), "Key"),
        (format!("wpkh({}/<0;1;2>/*)", X1), "MultipathArity"),
    ];

    for (descriptor, expected) in cases {
        let strict = ValidatedDescriptor::parse(&descriptor, Network::Bitcoin)
            .expect_err("strict refuses this");
        let permissive = ValidatedDescriptor::parse_permissive(&descriptor, Network::Bitcoin)
            .expect_err("permissive must refuse it too");

        assert_eq!(
            strict, permissive,
            "the two constructors must agree on {}",
            descriptor
        );
        assert!(
            format!("{:?}", permissive).starts_with(expected),
            "expected {} for {}, got {:?}",
            expected,
            descriptor,
            permissive
        );
    }
}

/// The same key at *different* derivation paths is not a duplicate: it produces
/// different public keys, so the quorum is real.
#[test]
fn the_same_xpub_at_different_paths_is_not_a_duplicate() {
    accept(&format!("wsh(multi(2,{}/0/*,{}/1/*))", X1, X1));
}

// =========================================================== key counts

/// `sh(multi)` caps at 15 keys, and the rule is the 520-byte limit on a single stack
/// element: a P2SH redeemScript is pushed as one element, and 16 compressed keys make
/// `1 + 16*34 + 1 + 1 = 547` bytes. The error must report the byte figures, because
/// the ceiling is a consequence rather than a stated maximum.
#[test]
fn sh_multi_refuses_the_sixteenth_key_on_the_script_size_rule() {
    match refuse(&with_keys("sh(multi(1,KEYS))", 16)) {
        DescriptorError::ScriptTooLarge { bytes, limit } => {
            assert_eq!(bytes, 547);
            assert_eq!(limit, 520);
        }
        other => panic!("expected ScriptTooLarge, got {:?}", other),
    }
}

/// `wsh(multi)` caps at 20, and the rule is a different one: `MAX_PUBKEYS_PER_MULTISIG`
/// limits the CHECKMULTISIG opcode itself, and the 520-byte element rule never applies
/// inside the witness.
///
/// The two must stay distinct variants. Collapsing them would tell a user who hit the
/// P2SH limit at 16 keys that the maximum is 20 — which is true of the other rule and
/// useless for theirs.
#[test]
fn wsh_multi_refuses_the_twenty_first_key_on_the_opcode_rule() {
    match refuse(&with_keys("wsh(multi(1,KEYS))", 21)) {
        DescriptorError::TooManyKeys { keys, max } => {
            assert_eq!(keys, 21);
            assert_eq!(max, 20);
        }
        other => panic!("expected TooManyKeys, got {:?}", other),
    }
}

/// Both paired acceptances. An off-by-one here refuses a legitimate wallet, and the
/// refusal would look exactly like the limit working.
#[test]
fn the_key_count_ceilings_are_not_enforced_one_key_early() {
    accept(&with_keys("sh(multi(1,KEYS))", 15));
    accept(&with_keys("wsh(multi(1,KEYS))", 20));
}

#[test]
fn a_threshold_larger_than_the_key_count_is_refused() {
    let descriptor = format!("wsh(multi(3,{}/0/*,{}/0/*))", X1, X2);

    match refuse(&descriptor) {
        DescriptorError::ThresholdExceedsKeys { threshold, keys } => {
            assert_eq!(threshold, 3);
            assert_eq!(keys, 2);
        }
        other => panic!("expected ThresholdExceedsKeys, got {:?}", other),
    }
}

// =========================================================== forms

/// `combo`, `addr`, `raw` and `rawtr` are outside the target set. Miniscript does not
/// know three of them at all, so the refusal has to come from us to be legible.
#[test]
fn forms_outside_the_target_set_are_refused() {
    for descriptor in [
        format!("combo({}/0/*)", X1),
        "addr(bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz)".to_string(),
        "raw(00140d1c9c02a7be9ba8b8842804feb961481ce6561b)".to_string(),
        format!("rawtr({}/0/*)", X1),
    ] {
        match refuse(&descriptor) {
            DescriptorError::UnsupportedForm { .. } => {}
            other => panic!(
                "expected UnsupportedForm for {}, got {:?}",
                descriptor, other
            ),
        }
    }
}

/// A `tr()` whose internal key also appears in a leaf. The key path is then a
/// single-key spending route around the quorum: `tr(A,multi_a(2,A,B))` looks like a
/// 2-of-2 and A can spend it alone. Miniscript parses this and `sanity_check()`
/// passes, so the refusal is entirely ours.
#[test]
fn a_taproot_internal_key_reused_in_a_leaf_is_refused() {
    let descriptor = format!("tr({}/0/*,multi_a(2,{}/0/*,{}/0/*))", X1, X1, X2);

    match refuse(&descriptor) {
        DescriptorError::InternalKeyReusedInLeaf { key } => {
            assert!(
                key.contains("xpub661MyMwAqRbcF"),
                "should name the key: {}",
                key
            )
        }
        other => panic!("expected InternalKeyReusedInLeaf, got {:?}", other),
    }
}

/// The paired acceptance: a distinct internal key is the ordinary case.
#[test]
fn a_taproot_internal_key_absent_from_the_leaves_is_accepted() {
    accept(&format!(
        "tr({}/<0;1>/*,multi_a(2,{}/<0;1>/*,{}/<0;1>/*))",
        X1, X2, X3
    ));
}

// =========================================================== key origins

#[test]
fn a_malformed_key_origin_is_refused() {
    let descriptor = format!("wpkh([zzzzzzzz/84h/0h/0h]{}/0/*)", X1);

    match refuse(&descriptor) {
        DescriptorError::Key(KeyError::Origin { .. }) => {}
        other => panic!("expected KeyError::Origin, got {:?}", other),
    }
}

/// Origins are optional, and a well-formed one is preserved rather than normalised
/// away — a coordinator needs the fingerprint to route a PSBT to the right device.
#[test]
fn a_well_formed_origin_is_accepted_and_preserved() {
    let d = accept(&format!("wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)", X1));

    assert_eq!(d.origins().len(), 1);
    assert_eq!(d.origins()[0].fingerprint().to_string(), "aabbccdd");
    assert!(d.canonical().contains("[aabbccdd/84h/0h/0h]"));
}

#[test]
fn an_absent_origin_is_accepted() {
    let d = accept(&format!("wpkh({}/<0;1>/*)", X1));
    assert!(d.origins().is_empty());
}
