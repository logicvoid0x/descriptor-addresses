//! Seam 1 — assembled input.
//!
//! Assembly is an input **model**, not an input mechanism. Everything here calls the
//! same two functions the CLI's prompts and a future ratatui form will call, with the
//! same structs — the library cannot tell how its arguments were obtained.

use descriptor_addresses::{
    AssemblyError, DescriptorKey, KeyOrdering, Multisig, MultisigScript, Network, SingleSig,
    SingleSigScript, ValidatedDescriptor,
};

const X1: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const X2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const X3: &str = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
const TPUB: &str = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";

fn key(s: &str) -> DescriptorKey {
    DescriptorKey::parse(s).unwrap_or_else(|e| panic!("{}: {}", s, e))
}

fn single(script_type: SingleSigScript, k: &str) -> SingleSig {
    SingleSig {
        key: key(k),
        script_type,
        network: Network::Bitcoin,
        path: None,
    }
}

fn multi(script_type: MultisigScript, ordering: KeyOrdering, keys: &[&str]) -> Multisig {
    Multisig {
        keys: keys.iter().map(|k| key(k)).collect(),
        threshold: 2,
        script_type,
        ordering,
        network: Network::Bitcoin,
        path: None,
    }
}

// ==================================================== the shape of the output

/// Assembly and parsing produce the same type, so everything downstream — derivation,
/// advisories, the canonical string — is identical for both entry points. That is the
/// map's "one derivation path in the code", honoured literally.
#[test]
fn an_assembled_descriptor_is_indistinguishable_from_a_parsed_one() {
    let assembled =
        ValidatedDescriptor::assemble_single_sig(single(SingleSigScript::Wpkh, X1)).unwrap();

    let parsed = ValidatedDescriptor::parse(assembled.canonical(), Network::Bitcoin).unwrap();

    assert_eq!(assembled.canonical(), parsed.canonical());
    assert_eq!(
        assembled
            .external()
            .address_at(descriptor_addresses::NormalIndex::ZERO)
            .address()
            .to_string(),
        parsed
            .external()
            .address_at(descriptor_addresses::NormalIndex::ZERO)
            .address()
            .to_string()
    );
}

/// Two paths, always. An assembled wallet has somewhere to send change like any other,
/// and the echoed descriptor — the string the user must back up — covers both chains
/// rather than half of them.
#[test]
fn assembly_always_produces_both_keychains() {
    for script_type in [
        SingleSigScript::Pkh,
        SingleSigScript::ShWpkh,
        SingleSigScript::Wpkh,
        SingleSigScript::Tr,
    ] {
        let d = ValidatedDescriptor::assemble_single_sig(single(script_type, X1)).unwrap();

        assert!(d.canonical().contains("<0;1>/*"), "got: {}", d.canonical());
        assert!(
            d.internal().is_some(),
            "{:?} has no change keychain",
            script_type
        );
    }
}

/// Checksummed and in h-form, because the echo is the whole point: the user compares
/// it against what their other wallet shows.
#[test]
fn the_assembled_descriptor_is_checksummed_and_in_h_form() {
    let d = ValidatedDescriptor::assemble_single_sig(single(SingleSigScript::Wpkh, X1)).unwrap();

    assert!(d.canonical().contains('#'));
    assert!(!d.canonical().contains('\''));
    assert_eq!(d.canonical().rsplit('#').next().unwrap().len(), 8);
}

// ==================================================== the four single-sig forms

#[test]
fn each_single_sig_script_type_produces_its_form() {
    let cases = [
        (SingleSigScript::Pkh, "pkh"),
        (SingleSigScript::ShWpkh, "sh(wpkh)"),
        (SingleSigScript::Wpkh, "wpkh"),
        (SingleSigScript::Tr, "tr"),
    ];

    for (script_type, expected) in cases {
        let d = ValidatedDescriptor::assemble_single_sig(single(script_type, X1)).unwrap();
        assert_eq!(d.script_type().form(), expected);
    }
}

// ==================================================== the four multisig forms

/// `{Wsh, ShWsh}` times `{Sorted, AsGiven}` is exactly the four multisig forms, with
/// no invalid combination anywhere in the product. That is why it is two enums rather
/// than one flat enum of four: a flat enum would admit a fifth entry nobody checked.
#[test]
fn the_product_of_the_two_multisig_enums_is_exactly_the_four_forms() {
    let cases = [
        (MultisigScript::Wsh, KeyOrdering::Sorted, "wsh(sortedmulti)"),
        (MultisigScript::Wsh, KeyOrdering::AsGiven, "wsh(multi)"),
        (
            MultisigScript::ShWsh,
            KeyOrdering::Sorted,
            "sh(wsh(sortedmulti))",
        ),
        // The one combination that is NOT an allowlisted form. Assembly must refuse to
        // manufacture it rather than emit something `parse` would then reject.
        (MultisigScript::ShWsh, KeyOrdering::AsGiven, "REFUSED"),
    ];

    for (script_type, ordering, expected) in cases {
        let spec = multi(script_type, ordering, &[X1, X2, X3]);
        match ValidatedDescriptor::assemble_multisig(spec) {
            Ok(d) => assert_eq!(d.script_type().form(), expected),
            // Named, not merely "an error": the refusal must be the allowlist
            // declining this form, not some unrelated rule tripping first.
            Err(AssemblyError::Unbuildable { reason, .. }) => {
                assert_eq!(expected, "REFUSED", "{:?} {:?}", script_type, ordering);
                assert!(matches!(
                    reason.as_ref(),
                    descriptor_addresses::DescriptorError::UnsupportedForm { .. }
                ));
            }
            Err(other) => panic!("unexpected refusal: {:?}", other),
        }
    }
}

/// BIP-67 ordering is the correctness trap this crate exists around: the same keys in
/// a different order give different addresses, and therefore different funds.
///
/// **The invariant is over addresses, not over the descriptor string.** BIP-67 sorts
/// the *derived public keys at each index*, not the xpubs as written — so two
/// permutations of a `sortedmulti` produce two different descriptor strings that
/// derive the same addresses. Asserting on the canonical string would be asserting the
/// wrong thing, and would pass only if we silently rewrote what the user typed.
#[test]
fn sorted_ordering_is_invariant_under_permutation_of_the_keys() {
    let forward = ValidatedDescriptor::assemble_multisig(multi(
        MultisigScript::Wsh,
        KeyOrdering::Sorted,
        &[X1, X2, X3],
    ))
    .unwrap();
    let reversed = ValidatedDescriptor::assemble_multisig(multi(
        MultisigScript::Wsh,
        KeyOrdering::Sorted,
        &[X3, X2, X1],
    ))
    .unwrap();

    // The strings differ, because we echo back the order the user gave us.
    assert_ne!(forward.canonical(), reversed.canonical());

    // The money does not.
    for i in [0u32, 1, 5] {
        let index = descriptor_addresses::NormalIndex::new(i).unwrap();
        assert_eq!(
            forward.external().address_at(index).address().to_string(),
            reversed.external().address_at(index).address().to_string(),
            "sortedmulti must derive the same address at index {}",
            i
        );
    }
}

/// The paired negative, and the reason the two orderings are separate variants at all:
/// with `multi`, permuting the keys is a different wallet holding different coins.
#[test]
fn as_given_ordering_is_not_invariant_under_permutation() {
    let forward = ValidatedDescriptor::assemble_multisig(multi(
        MultisigScript::Wsh,
        KeyOrdering::AsGiven,
        &[X1, X2, X3],
    ))
    .unwrap();
    let reversed = ValidatedDescriptor::assemble_multisig(multi(
        MultisigScript::Wsh,
        KeyOrdering::AsGiven,
        &[X3, X2, X1],
    ))
    .unwrap();

    let index = descriptor_addresses::NormalIndex::ZERO;
    assert_ne!(
        forward.external().address_at(index).address().to_string(),
        reversed.external().address_at(index).address().to_string(),
        "multi must not sort: a different order is a different wallet"
    );
}

// ==================================================== defaulted paths

/// A lookup, not a guess: both the script type and the network were stated
/// explicitly, so the BIP path follows from them with nothing inferred.
///
/// The fingerprint comes from the user's key — it cannot be computed from an account
/// xpub — so the default fills in only the path half of an origin.
#[test]
fn the_derivation_path_defaults_per_bip_from_script_type_and_network() {
    let cases = [
        (SingleSigScript::Pkh, "[aabbccdd/44h/0h/0h]"), // BIP-44
        (SingleSigScript::ShWpkh, "[aabbccdd/49h/0h/0h]"), // BIP-49
        (SingleSigScript::Wpkh, "[aabbccdd/84h/0h/0h]"), // BIP-84
        (SingleSigScript::Tr, "[aabbccdd/86h/0h/0h]"),  // BIP-86
    ];

    for (script_type, expected) in cases {
        let d = ValidatedDescriptor::assemble_single_sig(single(
            script_type,
            &format!("[aabbccdd]{}", X1),
        ))
        .unwrap();

        assert!(
            d.canonical().contains(expected),
            "{:?}: expected {} in {}",
            script_type,
            expected,
            d.canonical()
        );
    }
}

/// Coin type 1 for every test network, because BIP-44 defines exactly two — and the
/// three test networks are indistinguishable from a key anyway.
#[test]
fn the_default_path_uses_coin_type_one_on_test_networks() {
    for network in [Network::Testnet, Network::Signet, Network::Regtest] {
        let d = ValidatedDescriptor::assemble_single_sig(SingleSig {
            key: key(&format!("[aabbccdd]{}", TPUB)),
            script_type: SingleSigScript::Wpkh,
            network,
            path: None,
        })
        .unwrap();

        assert!(
            d.canonical().contains("[aabbccdd/84h/1h/0h]"),
            "got: {}",
            d.canonical()
        );
    }
}

/// BIP-48 for multisig, whose last element names the script type: `2h` for P2WSH and
/// `1h` for P2SH-P2WSH.
#[test]
fn multisig_defaults_to_the_bip48_path_for_its_script_type() {
    let wsh = ValidatedDescriptor::assemble_multisig(multi(
        MultisigScript::Wsh,
        KeyOrdering::Sorted,
        &[&format!("[aabbccdd]{}", X1), &format!("[11223344]{}", X2)],
    ))
    .unwrap();
    assert!(
        wsh.canonical().contains("/48h/0h/0h/2h]"),
        "got: {}",
        wsh.canonical()
    );

    let sh_wsh = ValidatedDescriptor::assemble_multisig(multi(
        MultisigScript::ShWsh,
        KeyOrdering::Sorted,
        &[&format!("[aabbccdd]{}", X1), &format!("[11223344]{}", X2)],
    ))
    .unwrap();
    assert!(
        sh_wsh.canonical().contains("/48h/0h/0h/1h]"),
        "got: {}",
        sh_wsh.canonical()
    );
}

/// An explicit path overrides the default — the default exists to spare the user a
/// decision, not to take one away.
#[test]
fn an_explicit_path_is_used_instead_of_the_default() {
    let d = ValidatedDescriptor::assemble_single_sig(SingleSig {
        key: key(&format!("[aabbccdd]{}", X1)),
        script_type: SingleSigScript::Wpkh,
        network: Network::Bitcoin,
        path: Some("84h/0h/7h".parse().unwrap()),
    })
    .unwrap();

    assert!(
        d.canonical().contains("[aabbccdd/84h/0h/7h]"),
        "got: {}",
        d.canonical()
    );
}

/// A key that already states its full origin keeps it. Nothing is defaulted over the
/// top of what the user actually said.
#[test]
fn a_key_with_a_complete_origin_keeps_it() {
    let d = ValidatedDescriptor::assemble_single_sig(single(
        SingleSigScript::Wpkh,
        &format!("[aabbccdd/84h/0h/5h]{}", X1),
    ))
    .unwrap();

    assert!(
        d.canonical().contains("[aabbccdd/84h/0h/5h]"),
        "got: {}",
        d.canonical()
    );
}

/// Two sources for one value is a question, not a default. Silently preferring either
/// would discard something the user stated.
#[test]
fn a_path_given_twice_is_refused_rather_than_silently_resolved() {
    let result = ValidatedDescriptor::assemble_single_sig(SingleSig {
        key: key(&format!("[aabbccdd/84h/0h/0h]{}", X1)),
        script_type: SingleSigScript::Wpkh,
        network: Network::Bitcoin,
        path: Some("84h/0h/7h".parse().unwrap()),
    });

    match result {
        Err(AssemblyError::PathAlreadyInKey { .. }) => {}
        other => panic!("expected PathAlreadyInKey, got {:?}", other.map(|_| ())),
    }
}

/// A path needs a fingerprint to hang from — BIP-380 origins require one, and it
/// cannot be computed from an account xpub. Dropping the path silently would lose
/// what the user said.
#[test]
fn a_path_without_a_fingerprint_is_refused() {
    let result = ValidatedDescriptor::assemble_single_sig(SingleSig {
        key: key(X1),
        script_type: SingleSigScript::Wpkh,
        network: Network::Bitcoin,
        path: Some("84h/0h/0h".parse().unwrap()),
    });

    match result {
        Err(AssemblyError::PathWithoutFingerprint) => {}
        other => panic!(
            "expected PathWithoutFingerprint, got {:?}",
            other.map(|_| ())
        ),
    }
}

/// A bare key with no path at all is fine — the descriptor simply carries no origin,
/// and an advisory says so.
#[test]
fn a_bare_key_assembles_without_an_origin() {
    let d = ValidatedDescriptor::assemble_single_sig(single(SingleSigScript::Wpkh, X1)).unwrap();

    assert!(!d.canonical().contains('['));
    assert!(d
        .advisories()
        .contains(&descriptor_addresses::Advisory::OriginAbsent));
}

// ==================================================== refusals

#[test]
fn a_threshold_larger_than_the_key_count_is_refused() {
    let spec = Multisig {
        keys: vec![key(X1), key(X2)],
        threshold: 3,
        script_type: MultisigScript::Wsh,
        ordering: KeyOrdering::Sorted,
        network: Network::Bitcoin,
        path: None,
    };

    match ValidatedDescriptor::assemble_multisig(spec) {
        Err(AssemblyError::ThresholdExceedsKeys { threshold, keys }) => {
            assert_eq!(threshold, 3);
            assert_eq!(keys, 2);
        }
        other => panic!("expected ThresholdExceedsKeys, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn a_zero_threshold_is_refused() {
    let spec = Multisig {
        keys: vec![key(X1), key(X2)],
        threshold: 0,
        script_type: MultisigScript::Wsh,
        ordering: KeyOrdering::Sorted,
        network: Network::Bitcoin,
        path: None,
    };

    match ValidatedDescriptor::assemble_multisig(spec) {
        Err(AssemblyError::ThresholdExceedsKeys { threshold, keys }) => {
            assert_eq!(threshold, 0);
            assert_eq!(keys, 2);
        }
        other => panic!("expected ThresholdExceedsKeys, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn a_duplicate_key_is_refused() {
    let spec = multi(MultisigScript::Wsh, KeyOrdering::Sorted, &[X1, X1]);

    match ValidatedDescriptor::assemble_multisig(spec) {
        Err(AssemblyError::DuplicateKey { key }) => {
            assert!(key.contains("xpub661MyMwAqRbcF"))
        }
        other => panic!("expected DuplicateKey, got {:?}", other.map(|_| ())),
    }
}

/// The network is stated, so a key from a different one is a contradiction the caller
/// can fix — and exactly the mistake this crate exists to catch.
#[test]
fn a_key_from_the_wrong_network_is_refused() {
    let result = ValidatedDescriptor::assemble_single_sig(SingleSig {
        key: key(TPUB),
        script_type: SingleSigScript::Wpkh,
        network: Network::Bitcoin,
        path: None,
    });

    match result {
        Err(AssemblyError::Unbuildable { reason, .. }) => assert!(matches!(
            reason.as_ref(),
            descriptor_addresses::DescriptorError::NetworkMismatch { .. }
        )),
        other => panic!("expected a network refusal, got {:?}", other.map(|_| ())),
    }
}

/// SLIP-132 is refused on the way in, so assembly cannot be a back door around a rule
/// `parse` enforces. This is `KeyError` doing the job it was factored out for.
#[test]
fn a_slip132_key_is_refused_at_construction() {
    const ZPUB: &str = "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF";

    match DescriptorKey::parse(ZPUB) {
        Err(descriptor_addresses::KeyError::Slip132 { implies, .. }) => {
            assert_eq!(implies, "wpkh")
        }
        other => panic!("expected Slip132, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn a_malformed_key_is_refused_at_construction() {
    for bad in ["not-a-key", "", "   "] {
        match DescriptorKey::parse(bad) {
            Err(descriptor_addresses::KeyError::Malformed { .. }) => {}
            other => panic!(
                "expected Malformed for {:?}, got {:?}",
                bad,
                other.map(|_| ())
            ),
        }
    }
}

/// An empty key list has no quorum to express.
#[test]
fn multisig_with_no_keys_is_refused() {
    let spec = Multisig {
        keys: vec![],
        threshold: 1,
        script_type: MultisigScript::Wsh,
        ordering: KeyOrdering::Sorted,
        network: Network::Bitcoin,
        path: None,
    };

    match ValidatedDescriptor::assemble_multisig(spec) {
        Err(AssemblyError::NoKeys) => {}
        other => panic!("expected NoKeys, got {:?}", other.map(|_| ())),
    }
}

/// Assembly must not be able to manufacture a descriptor `parse` would refuse — and
/// when it tries, the refusal arrives **with its structure intact**.
///
/// `sh(wsh(multi))` is the case: it is a well-formed descriptor that the allowlist
/// does not contain, so it is the one corner of the `{Wsh,ShWsh} x {Sorted,AsGiven}`
/// product with nowhere to land.
///
/// This test replaced one that built a 21-key quorum from 21 copies of a single xpub
/// and asserted `is_err()`. It passed — on `DuplicateKey`, because duplicate detection
/// runs first. The key-count ceiling was never reached, and `is_err()` could not tell
/// the difference. The ceiling itself is tested against `parse` in `input_rules.rs`,
/// where distinct keys are available; what assembly needs to prove is the delegation,
/// which is what this asserts.
#[test]
fn a_descriptor_parse_would_refuse_surfaces_with_its_structure_intact() {
    let spec = multi(MultisigScript::ShWsh, KeyOrdering::AsGiven, &[X1, X2, X3]);

    match ValidatedDescriptor::assemble_multisig(spec) {
        Err(AssemblyError::Unbuildable { attempted, reason }) => {
            assert!(attempted.starts_with("sh(wsh(multi("), "got: {}", attempted);
            // The inner error is matchable, not a sentence.
            match reason.as_ref() {
                descriptor_addresses::DescriptorError::UnsupportedForm { form } => {
                    assert_eq!(form, "sh(wsh(multi))")
                }
                other => panic!("expected UnsupportedForm, got {:?}", other),
            }
        }
        other => panic!("expected Unbuildable, got {:?}", other.map(|_| ())),
    }
}

/// A quorum built from copies of one key is a duplicate, and must say so rather than
/// reporting whichever other rule happens to trip.
#[test]
fn a_quorum_of_repeated_keys_reports_the_duplicate() {
    let keys: Vec<DescriptorKey> = (0..21).map(|_| key(X1)).collect();
    let spec = Multisig {
        keys,
        threshold: 1,
        script_type: MultisigScript::Wsh,
        ordering: KeyOrdering::AsGiven,
        network: Network::Bitcoin,
        path: None,
    };

    match ValidatedDescriptor::assemble_multisig(spec) {
        Err(AssemblyError::DuplicateKey { key }) => assert_eq!(key, X1),
        other => panic!("expected DuplicateKey, got {:?}", other.map(|_| ())),
    }
}

/// Mixing keys that state an origin path with keys that do not is refused.
///
/// Not tidiness: the ones without take the BIP default account while the others keep
/// their own, so the quorum spreads across two accounts and derives a wallet nobody
/// asked for — silently. Found by a reviewer probing the mixture directly.
#[test]
fn mixing_keys_with_and_without_an_origin_path_is_refused() {
    let spec = Multisig {
        keys: vec![
            key(&format!("[aabbccdd/48h/0h/9h/2h]{}", X1)),
            key(&format!("[11223344]{}", X2)),
        ],
        threshold: 2,
        script_type: MultisigScript::Wsh,
        ordering: KeyOrdering::Sorted,
        network: Network::Bitcoin,
        path: None,
    };

    match ValidatedDescriptor::assemble_multisig(spec) {
        Err(AssemblyError::MixedOrigins {
            with_path,
            without_path,
        }) => {
            assert_eq!(with_path, 1);
            assert_eq!(without_path, 1);
        }
        other => panic!("expected MixedOrigins, got {:?}", other.map(|_| ())),
    }
}

/// The paired acceptance: every key stating the same account is exactly what a real
/// multisig export looks like, and must assemble.
#[test]
fn keys_that_all_state_their_origin_assemble() {
    let spec = Multisig {
        keys: vec![
            key(&format!("[aabbccdd/48h/0h/9h/2h]{}", X1)),
            key(&format!("[11223344/48h/0h/9h/2h]{}", X2)),
        ],
        threshold: 2,
        script_type: MultisigScript::Wsh,
        ordering: KeyOrdering::Sorted,
        network: Network::Bitcoin,
        path: None,
    };

    let d = ValidatedDescriptor::assemble_multisig(spec).unwrap();
    assert_eq!(d.origins().len(), 2);
    assert!(
        d.canonical().contains("/48h/0h/9h/2h]"),
        "got: {}",
        d.canonical()
    );
}

/// A malformed origin path is refused at construction, where the type promises it is.
#[test]
fn a_malformed_origin_path_is_refused_at_construction() {
    for bad in [
        format!("[aabbccdd/]{}", X1),
        format!("[aabbccdd/not a path]{}", X1),
        format!("[aabbccdd/84h/zz]{}", X1),
    ] {
        match DescriptorKey::parse(&bad) {
            Err(descriptor_addresses::KeyError::Origin { .. }) => {}
            other => panic!(
                "expected KeyError::Origin for {}, got {:?}",
                bad,
                other.map(|_| ())
            ),
        }
    }
}
