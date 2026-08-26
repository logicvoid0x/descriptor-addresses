//! Seam 1 — the nine-form allowlist.
//!
//! **Every address and `scriptPubKey` asserted here was produced by the research
//! probe on 2026-08-22, before this crate existed** (`research/probes/probe-output.txt`,
//! the `[form ...]` blocks). They are evidence independent of the code under test,
//! not values captured from a first run and blessed.
//!
//! They are still *same-stack* evidence: the probe used miniscript 13.1.0 too, so a
//! shared bug would be invisible to both. Agreement with an independent
//! implementation is ticket 10's golden corpus against Bitcoin Core, and nothing in
//! this file should be read as establishing it.
//!
//! Descriptors here use `<0;1>` so both keychains exist. The external branch of
//! `<0;1>/*` is `/0/*`, which is exactly what the probe derived, so the probe's
//! values apply unchanged at external index 0.

use descriptor_addresses::{DescriptorError, Network, NormalIndex, ValidatedDescriptor};

const X1: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const X2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const X3: &str = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";

fn parse(d: &str) -> ValidatedDescriptor {
    ValidatedDescriptor::parse(d, Network::Bitcoin).unwrap_or_else(|e| panic!("{}: {}", d, e))
}

fn refuse(d: &str) -> DescriptorError {
    ValidatedDescriptor::parse(d, Network::Bitcoin)
        .err()
        .unwrap_or_else(|| panic!("expected refusal: {}", d))
}

fn idx(i: u32) -> NormalIndex {
    NormalIndex::new(i).unwrap()
}

/// One row per allowlisted form: the multipath descriptor, the name this crate
/// reports, and the probe's address and `scriptPubKey` at external index 0.
struct Form {
    descriptor: String,
    name: &'static str,
    address: &'static str,
    script_pubkey: &'static str,
}

fn nine_forms() -> Vec<Form> {
    let row = |descriptor: String, name, address, script_pubkey| Form {
        descriptor,
        name,
        address,
        script_pubkey,
    };

    vec![
        row(
            format!("pkh({}/<0;1>/*)", X1),
            "pkh",
            "12CL4K2eVqj7hQTix7dM7CVHCkpP17Pry3",
            "76a9140d1c9c02a7be9ba8b8842804feb961481ce6561b88ac",
        ),
        row(
            format!("wpkh({}/<0;1>/*)", X1),
            "wpkh",
            "bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz",
            "00140d1c9c02a7be9ba8b8842804feb961481ce6561b",
        ),
        row(
            format!("sh(wpkh({}/<0;1>/*))", X1),
            "sh(wpkh)",
            "3AfyxhpBVVLmBR4ZYX2onGzRqjv5QZ7FqD",
            "a914628713e27a36da16174e9d02c1772cd9e406039b87",
        ),
        row(
            format!("tr({}/<0;1>/*)", X1),
            "tr",
            "bc1pgfhzycz8pckwsdspf04hn6rps5tpapgrchtzx5f3k8wlvqhmxu6qrdt83a",
            "5120426e2260470e2ce836014beb79e86185161e8503c5d6235131b1ddf602fb3734",
        ),
        row(
            format!("wsh(multi(2,{}/<0;1>/*,{}/<0;1>/*))", X1, X2),
            "wsh(multi)",
            "bc1q008ztx6a24axhk6srvfg2f48nzczjhl6u5xr3nwl9a2kcd3q6xtq632a7g",
            "00207bce259b5d557a6bdb501b128526a798b0295ffae50c38cddf2f556c3620d196",
        ),
        row(
            format!("wsh(sortedmulti(2,{}/<0;1>/*,{}/<0;1>/*))", X1, X2),
            "wsh(sortedmulti)",
            "bc1qpsnmhwhv2cvnyp25efl8xvpyyenc8qr7zt0fj47dklj0txpc4e0q7vlzgy",
            "00200c27bbbaec5619320554ca7e733024266783807e12de9957cdb7e4f59838ae5e",
        ),
        row(
            format!("sh(multi(2,{}/<0;1>/*,{}/<0;1>/*))", X1, X2),
            "sh(multi)",
            "32yeps9S1xxVVaYjgcHY7AsJrDFXsp9p6f",
            "a9140e1d95e2cb6f8e97d432367a34aab000866c6dd387",
        ),
        row(
            format!("sh(wsh(sortedmulti(2,{}/<0;1>/*,{}/<0;1>/*)))", X1, X2),
            "sh(wsh(sortedmulti))",
            "35MLEwGPsDu4gssZeuQjyah7GkBWccsB9o",
            "a91428277968e7784fac15bf2475a9e7fc2c2e9850d287",
        ),
        row(
            format!(
                "tr({}/<0;1>/*,multi_a(2,{}/<0;1>/*,{}/<0;1>/*))",
                X1, X2, X3
            ),
            "tr(multi_a)",
            "bc1ph7kwa2m3nfzx4pwd7dra6zy6x6gqmkgxfkt6cc99npkrppfpkjdsewr950",
            "5120bfaceeab719a446a85cdf347dd089a36900dd9064d97ac60a5986c308521b49b",
        ),
    ]
}

/// The address AND the `scriptPubKey`, for every form.
///
/// Both, because they can disagree: a caller building a PSBT spends from the
/// `scriptPubKey`, so a correct address beside a wrong script would be a silent
/// failure for exactly the consumer this crate exists to serve.
#[test]
fn all_nine_forms_match_the_probe_at_external_index_zero() {
    for form in nine_forms() {
        let record = parse(&form.descriptor).external().address_at(idx(0));

        assert_eq!(record.address().to_string(), form.address, "{}", form.name);
        assert_eq!(
            record.script_pubkey().to_hex_string(),
            form.script_pubkey,
            "{} scriptPubKey",
            form.name
        );
        assert_eq!(record.script_type().form(), form.name);
        assert!(record.script_type().recognised(), "{}", form.name);
    }
}

/// Every allowlisted form must have a change keychain, and it must derive from the
/// **second** path.
///
/// The probe never derived change addresses, so there is no independent value to pin.
/// Rather than bless a self-produced string, this asserts a structural identity: the
/// internal keychain of `<0;1>/*` must equal the external keychain of a standalone
/// `/1/*` descriptor. That is what would actually break — a multipath split wired to
/// the wrong branch would hand out receive addresses when asked for change, and
/// against a pinned string that failure looks identical to a deliberate change.
#[test]
fn the_change_keychain_derives_from_the_second_path() {
    for form in nine_forms() {
        let multipath = parse(&form.descriptor);
        let internal = multipath
            .internal()
            .unwrap_or_else(|| panic!("{} has no change keychain", form.name));

        let standalone = parse(&form.descriptor.replace("<0;1>", "1"));

        for i in [0u32, 1, 7] {
            let change = internal.address_at(idx(i));
            let expected = standalone.external().address_at(idx(i));

            assert_eq!(
                change.address().to_string(),
                expected.address().to_string(),
                "{} change index {}",
                form.name,
                i
            );
            assert_eq!(
                change.script_pubkey(),
                expected.script_pubkey(),
                "{} change scriptPubKey at {}",
                form.name,
                i
            );
            assert_eq!(change.relative_path(), format!("1/{}", i));
        }

        // And it must not be the receive chain wearing a different label.
        assert_ne!(
            internal.address_at(idx(0)).address().to_string(),
            form.address,
            "{}: change equals receive",
            form.name
        );
    }
}

// ---------------------------------------------------------------- refusals

/// The point of an explicit walk rather than "whatever miniscript parses":
/// miniscript accepts every one of these. Each is refused by *our* policy, so a
/// future miniscript version cannot silently widen what this crate accepts.
///
/// The refusal names the shape actually seen — asserted here, because "refused by
/// name" is the requirement and a refusal that says only "unsupported" leaves the
/// reader to guess which part of their descriptor was the problem.
#[test]
fn forms_miniscript_accepts_but_policy_does_not() {
    let cases = [
        // Parse and derive upstream; excluded from the allowlist by decision.
        (
            format!("sh(sortedmulti(2,{}/<0;1>/*,{}/<0;1>/*))", X1, X2),
            "sh(sortedmulti)",
        ),
        (
            format!("sh(wsh(multi(2,{}/<0;1>/*,{}/<0;1>/*)))", X1, X2),
            "sh(wsh(multi))",
        ),
        // Arbitrary miniscript — a timelock branch.
        (
            format!("wsh(and_v(v:pk({}/<0;1>/*),older(144)))", X1),
            "wsh(miniscript)",
        ),
        // Bare forms: they parse, but a bare script has no address at all.
        (format!("pk({}/<0;1>/*)", X1), "pk"),
        (format!("multi(2,{}/<0;1>/*,{}/<0;1>/*)", X1, X2), "multi"),
    ];

    for (descriptor, expected_form) in cases {
        match refuse(&descriptor) {
            DescriptorError::UnsupportedForm { form } => {
                assert_eq!(form, expected_form, "for {}", descriptor)
            }
            other => panic!(
                "expected UnsupportedForm for {}, got {:?}",
                descriptor, other
            ),
        }
    }
}

/// A nested tap tree is refused on **depth**, not on leaf kind — the two leaves here
/// are `pk`, which is inside the leaf policy. This is the case that proves the depth
/// bound does something: an earlier draft also tested the leaf count, which made the
/// depth constant inert because a branch always has two children.
#[test]
fn a_nested_tap_tree_is_refused_on_depth() {
    let descriptor = format!(
        "tr({}/<0;1>/*,{{pk({}/<0;1>/*),pk({}/<0;1>/*)}})",
        X1, X2, X3
    );

    match refuse(&descriptor) {
        DescriptorError::UnsupportedForm { form } => {
            assert!(form.contains("levels deep"), "got: {}", form);
            assert!(
                form.contains('2'),
                "should report the depth it found: {}",
                form
            );
        }
        other => panic!("expected UnsupportedForm, got {:?}", other),
    }
}

/// The paired acceptance for the depth bound: one leaf is admitted, so the refusal
/// above is a boundary and not a blanket ban on script paths.
#[test]
fn a_single_leaf_tap_tree_is_accepted() {
    let descriptor = format!(
        "tr({}/<0;1>/*,multi_a(2,{}/<0;1>/*,{}/<0;1>/*))",
        X1, X2, X3
    );
    assert_eq!(parse(&descriptor).script_type().form(), "tr(multi_a)");
}

/// `sortedmulti_a` is an upstream gap, not a user error, and the message has to say
/// so — otherwise someone spends an evening hunting a mistake they did not make.
/// Miniscript's own error blames the *key* (`unrecognized name 'xpub…'`), which is
/// why this is intercepted before the string reaches the parser.
#[test]
fn sortedmulti_a_names_the_upstream_gap() {
    let descriptor = format!(
        "tr({}/<0;1>/*,sortedmulti_a(2,{}/<0;1>/*,{}/<0;1>/*))",
        X1, X2, X3
    );

    match refuse(&descriptor) {
        DescriptorError::UnsupportedUpstream { form, detail } => {
            assert_eq!(form, "sortedmulti_a");
            // The reader has to learn this is not theirs to fix.
            assert!(detail.contains("unreleased"), "got: {}", detail);
        }
        other => panic!("expected UnsupportedUpstream, got {:?}", other),
    }
}

// ------------------------------------------------- descriptor-level facts

/// A 2-of-3 has one origin per key, so there is no single derivation path for an
/// address. Origins are reported once, against the descriptor.
#[test]
fn origins_are_a_descriptor_level_fact_not_a_per_address_one() {
    let descriptor = format!(
        "wsh(sortedmulti(2,[aabbccdd/48h/0h/0h/2h]{}/<0;1>/*,[11223344/48h/0h/0h/2h]{}/<0;1>/*))",
        X1, X2
    );
    let d = parse(&descriptor);

    let origins = d.origins();
    assert_eq!(origins.len(), 2, "one origin per key");
    assert_eq!(origins[0].fingerprint().to_string(), "aabbccdd");
    assert_eq!(origins[1].fingerprint().to_string(), "11223344");

    // h-form here too: a screen that says 48h on one line and 48' on the next is
    // worse than either notation alone.
    assert_eq!(origins[0].path(), "m/48h/0h/0h/2h");
    assert!(!origins[0].path().contains('\''));

    // The record still carries only the suffix, which is the same for every key.
    assert_eq!(d.external().address_at(idx(4)).relative_path(), "0/4");
}

/// Apostrophe input must reach the same one notation — this is the path that was
/// rendering `'` while the canonical string beside it rendered `h`.
#[test]
fn origins_are_normalised_even_when_the_input_used_apostrophes() {
    let descriptor = format!("wpkh([aabbccdd/84'/0'/0']{}/<0;1>/*)", X1);
    let d = parse(&descriptor);

    assert_eq!(d.origins()[0].path(), "m/84h/0h/0h");
    assert!(!d.canonical().contains('\''));
}

#[test]
fn a_descriptor_without_origins_reports_none() {
    let d = parse(&format!("wpkh({}/<0;1>/*)", X1));
    assert!(d.origins().is_empty());
}

/// The `tr()` internal key is a descriptor-level fact. Whether it is a recognised
/// NUMS point is an advisory, and belongs to ticket 05.
#[test]
fn the_taproot_internal_key_is_reported() {
    let keypath = parse(&format!("tr({}/<0;1>/*)", X1));
    assert!(keypath
        .internal_key()
        .expect("tr has an internal key")
        .starts_with("xpub661MyMwAqRbcF"));

    let script_path = parse(&format!(
        "tr({}/<0;1>/*,multi_a(2,{}/<0;1>/*,{}/<0;1>/*))",
        X1, X2, X3
    ));
    assert!(script_path.internal_key().is_some());

    // Non-taproot forms have no internal key, and that is an absence rather than an
    // empty string standing in for one.
    assert!(parse(&format!("wpkh({}/<0;1>/*)", X1))
        .internal_key()
        .is_none());
}

/// An internal key can carry its own origin, and that origin must be in the same
/// notation as everything else on screen. This is the case that caught the internal
/// key bypassing the h-form rewrite entirely.
#[test]
fn the_internal_key_is_rendered_in_h_notation() {
    let descriptor = format!("tr([aabbccdd/86'/0'/0']{}/<0;1>/*)", X1);
    let d = parse(&descriptor);

    let internal = d.internal_key().expect("tr has an internal key");
    assert!(internal.contains("86h/0h/0h"), "got: {}", internal);
    assert!(!internal.contains('\''), "got: {}", internal);
}

/// The published list of supported forms is derived from the policy, so it cannot
/// drift from what is actually enforced.
#[test]
fn the_supported_form_list_matches_what_parses() {
    let published: Vec<&str> = descriptor_addresses::supported_forms().collect();
    assert_eq!(published.len(), 9);

    let derived: Vec<&str> = nine_forms().iter().map(|f| f.name).collect();
    assert_eq!(published, derived);
}
