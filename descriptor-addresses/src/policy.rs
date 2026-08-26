//! What this crate accepts, expressed as a walk over configuration.
//!
//! # Why a walk and not a match on `desc_type()`
//!
//! Arbitrary custom scripts are the stated destination for this crate, so the
//! validator is written from day one as a recursive descent that *describes* what it
//! found and then consults configuration, rather than as a flat match over named
//! forms. Widening later edits the three values below; it does not rewrite the
//! algorithm.
//!
//! It also buys a safety property that is easy to miss: because acceptance is an
//! explicit walk and not "whatever miniscript parses", **taking a future miniscript
//! version can never silently widen what we accept**. A dependency bump is not a
//! policy change. `sh(sortedmulti(…))`, `sh(wsh(multi(…)))`, arbitrary miniscript and
//! nested tap trees all parse and derive perfectly well upstream today — they are
//! refused here because they are not on the list.

use miniscript::descriptor::{Descriptor, DescriptorPublicKey, ShInner, Tr, Wsh, WshInner};
use miniscript::Terminal;

use crate::DescriptorError;

/// A script wrapper, in the order it appears from the outside in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wrapper {
    Pkh,
    Wpkh,
    Sh,
    Wsh,
    Tr,
}

impl Wrapper {
    fn name(self) -> &'static str {
        match self {
            Wrapper::Pkh => "pkh",
            Wrapper::Wpkh => "wpkh",
            Wrapper::Sh => "sh",
            Wrapper::Wsh => "wsh",
            Wrapper::Tr => "tr",
        }
    }
}

/// The spending condition at the bottom of the wrapper chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Leaf {
    /// A single key held directly by the wrapper, as in `wpkh(KEY)`.
    ///
    /// Not a member of [`LEAF_POLICY`]: it is not a script leaf at all, it is the
    /// wrapper's own key, and there is no policy question to ask about it.
    Key,
    Pk,
    Multi,
    SortedMulti,
    MultiA,
    /// Miniscript this crate has no name for — a timelock, a threshold, a decaying
    /// policy. Never in [`LEAF_POLICY`] in v1, and rendered verbatim in the refusal
    /// so the user learns what was actually seen.
    Script,
}

impl Leaf {
    fn name(self) -> &'static str {
        match self {
            Leaf::Key => "",
            Leaf::Pk => "pk",
            Leaf::Multi => "multi",
            Leaf::SortedMulti => "sortedmulti",
            Leaf::MultiA => "multi_a",
            Leaf::Script => "miniscript",
        }
    }
}

// ------------------------------------------------------------- configuration
//
// The three values below are the whole policy. Everything around them is mechanism.

/// Which script leaves this crate will consider at all.
///
/// The **leaf** dimension of the policy, and the first gate: a fragment outside this
/// set is refused before its position is even examined, so the refusal can say what
/// the fragment was rather than which combination failed.
const LEAF_POLICY: &[Leaf] = &[Leaf::Pk, Leaf::Multi, Leaf::SortedMulti, Leaf::MultiA];

/// Which (wrapper chain, leaf) combinations are accepted: the nine forms.
///
/// The **position** dimension, and necessarily separate from [`LEAF_POLICY`]. A leaf
/// set alone cannot express this allowlist: crossing the five wrappers with the four
/// leaves yields *eleven* forms, not nine, because it also admits `sh(sortedmulti)`
/// and `sh(wsh(multi))` — which the Accepted Input and Script Policy decision (Q7)
/// enumerates around rather than including. Widening the allowlist is a decision that
/// carries its own test vectors, so the shape that can only widen deliberately is the
/// right one. Recorded as amendment A4 on that ticket, together with the open
/// question of whether `sh(sortedmulti)` belongs in the nine.
const ALLOWED: &[(&[Wrapper], Leaf, &str)] = &[
    // Single-sig.
    (&[Wrapper::Pkh], Leaf::Key, "pkh"),
    (&[Wrapper::Wpkh], Leaf::Key, "wpkh"),
    (&[Wrapper::Sh, Wrapper::Wpkh], Leaf::Key, "sh(wpkh)"),
    (&[Wrapper::Tr], Leaf::Key, "tr"),
    // Multisig. The legacy pair earns its place because someone's 2017 coins are in
    // there; unsorted `multi` earns its because the descriptor names the variant, so
    // the parser cannot confuse it with `sortedmulti`.
    (&[Wrapper::Wsh], Leaf::Multi, "wsh(multi)"),
    (&[Wrapper::Wsh], Leaf::SortedMulti, "wsh(sortedmulti)"),
    (&[Wrapper::Sh], Leaf::Multi, "sh(multi)"),
    (
        &[Wrapper::Sh, Wrapper::Wsh],
        Leaf::SortedMulti,
        "sh(wsh(sortedmulti))",
    ),
    // Taproot multisig, single leaf only.
    (&[Wrapper::Tr], Leaf::MultiA, "tr(multi_a)"),
];

/// How deep a taproot script tree may be.
///
/// **One-based: a single leaf is depth 1**, so v1's value of 1 means "one leaf, no
/// branches". Miniscript counts that same leaf as depth 0, and the conversion happens
/// in exactly one place below. The off-by-one is stated rather than absorbed because
/// a depth bound that is wrong by one is a depth bound that does nothing.
///
/// This value is load-bearing on its own: raising it to 2 genuinely admits a two-leaf
/// tree, and the walk validates *every* leaf rather than the first one. An earlier
/// draft also tested `leaves.len() > 1`, which silently made this constant inert — a
/// branch always has two children, so the leaf count decided every case and raising
/// the depth would have widened nothing. Two reviewers caught it independently.
const MAX_TAPTREE_DEPTH: usize = 1;

// ------------------------------------------------------------------- mechanism

/// What the walk found: enough to decide, and enough to explain a refusal.
pub(crate) struct Shape {
    chain: Vec<Wrapper>,
    leaf: Leaf,
}

impl Shape {
    /// Render in descriptor syntax, e.g. `sh(wsh(sortedmulti))`.
    ///
    /// Built inside out, so a wrapper holding a key directly prints as `wpkh` rather
    /// than `wpkh()`. Used for the refusal message, so a reader sees the shape this
    /// crate recognised in their input rather than a parser's internal name.
    fn describe(&self) -> String {
        let mut rendered = self.leaf.name().to_string();
        for wrapper in self.chain.iter().rev() {
            rendered = if rendered.is_empty() {
                wrapper.name().to_string()
            } else {
                format!("{}({})", wrapper.name(), rendered)
            };
        }
        rendered
    }
}

/// The forms this build accepts, for anything that needs to list them to a human.
///
/// Derived from [`ALLOWED`] rather than written out a second time: a list of
/// supported forms that can disagree with the policy is worse than no list.
pub(crate) fn allowed_forms() -> impl Iterator<Item = &'static str> {
    ALLOWED.iter().map(|(_, _, name)| *name)
}

/// Validate a descriptor against the policy, returning the form's name.
pub(crate) fn check(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<&'static str, DescriptorError> {
    let shape = walk(descriptor)?;

    // Gate one: the leaf itself. A `Key` is the wrapper's own key rather than a
    // script leaf, so it is not subject to the leaf policy.
    if shape.leaf != Leaf::Key && !LEAF_POLICY.contains(&shape.leaf) {
        return Err(DescriptorError::UnsupportedForm {
            form: shape.describe(),
        });
    }

    // Gate two: the position it appears in.
    for (chain, leaf, name) in ALLOWED {
        if *chain == shape.chain.as_slice() && *leaf == shape.leaf {
            return Ok(name);
        }
    }

    Err(DescriptorError::UnsupportedForm {
        form: shape.describe(),
    })
}

/// Walk the descriptor from the outside in, accumulating wrappers until a leaf.
fn walk(descriptor: &Descriptor<DescriptorPublicKey>) -> Result<Shape, DescriptorError> {
    let (chain, leaf) = match descriptor {
        // `pk(KEY)` and `multi(k,…)` at top level. They parse, but a bare script has
        // no address, so there is nothing this crate could show even in principle.
        Descriptor::Bare(bare) => (vec![], leaf_of(&bare.as_inner().node)),
        Descriptor::Pkh(_) => (vec![Wrapper::Pkh], Leaf::Key),
        Descriptor::Wpkh(_) => (vec![Wrapper::Wpkh], Leaf::Key),
        Descriptor::Sh(sh) => {
            let (mut chain, leaf) = walk_sh(sh.as_inner());
            chain.insert(0, Wrapper::Sh);
            (chain, leaf)
        }
        Descriptor::Wsh(wsh) => {
            let (mut chain, leaf) = walk_wsh(wsh);
            chain.insert(0, Wrapper::Wsh);
            (chain, leaf)
        }
        Descriptor::Tr(tr) => (vec![Wrapper::Tr], walk_tr(tr)?),
    };

    Ok(Shape { chain, leaf })
}

/// Recurse through an `sh()` wrapper. `sh(wsh(…))` descends again.
fn walk_sh(inner: &ShInner<DescriptorPublicKey>) -> (Vec<Wrapper>, Leaf) {
    match inner {
        ShInner::Wpkh(_) => (vec![Wrapper::Wpkh], Leaf::Key),
        ShInner::Wsh(wsh) => {
            let (mut chain, leaf) = walk_wsh(wsh);
            chain.insert(0, Wrapper::Wsh);
            (chain, leaf)
        }
        ShInner::SortedMulti(_) => (vec![], Leaf::SortedMulti),
        ShInner::Ms(ms) => (vec![], leaf_of(&ms.node)),
    }
}

fn walk_wsh(wsh: &Wsh<DescriptorPublicKey>) -> (Vec<Wrapper>, Leaf) {
    match wsh.as_inner() {
        WshInner::SortedMulti(_) => (vec![], Leaf::SortedMulti),
        WshInner::Ms(ms) => (vec![], leaf_of(&ms.node)),
    }
}

/// Walk a `tr()`: bound the tree's depth, then classify **every** leaf.
///
/// Checking only the first leaf would mean that the moment [`MAX_TAPTREE_DEPTH`] is
/// raised, a two-leaf tree would be admitted on the strength of its first leaf with
/// the second never examined.
fn walk_tr(tr: &Tr<DescriptorPublicKey>) -> Result<Leaf, DescriptorError> {
    let tree = match tr.tap_tree() {
        // Key-path only: the internal key is the whole spending condition.
        None => return Ok(Leaf::Key),
        Some(tree) => tree,
    };

    let mut depth = 0;
    let mut kinds: Vec<Leaf> = Vec::new();

    for item in tree.leaves() {
        // The one place miniscript's 0-based depth becomes our 1-based depth.
        depth = depth.max(usize::from(item.depth()) + 1);
        kinds.push(leaf_of(&item.miniscript().node));
    }

    if depth > MAX_TAPTREE_DEPTH {
        return Err(DescriptorError::UnsupportedForm {
            form: format!(
                "tr with a script tree {} levels deep ({} leaves)",
                depth,
                kinds.len()
            ),
        });
    }

    kinds.dedup();
    match kinds.as_slice() {
        [only] => Ok(*only),
        // Unreachable while the depth bound is 1, and written anyway: it is what
        // makes raising that bound a configuration change rather than a rewrite.
        other => Err(DescriptorError::UnsupportedForm {
            form: format!("tr with a script tree of {} differing leaves", other.len()),
        }),
    }
}

/// Classify one miniscript fragment.
///
/// Anything not named here is [`Leaf::Script`], which is not in [`LEAF_POLICY`] — so
/// an unknown fragment is refused by default rather than by omission.
fn leaf_of<Ctx: miniscript::ScriptContext>(node: &Terminal<DescriptorPublicKey, Ctx>) -> Leaf {
    match node {
        Terminal::Multi(_) => Leaf::Multi,
        Terminal::MultiA(_) => Leaf::MultiA,
        Terminal::PkK(_) | Terminal::PkH(_) => Leaf::Pk,
        // `pk(KEY)` desugars to `c:pk_k(KEY)`, so the check wrapper sits above the key.
        Terminal::Check(inner) => match &inner.node {
            Terminal::PkK(_) | Terminal::PkH(_) => Leaf::Pk,
            _ => Leaf::Script,
        },
        _ => Leaf::Script,
    }
}

/// Forms that must be caught before miniscript sees the string.
///
/// `sortedmulti_a` is absent from every released miniscript (merged to master
/// 2026-04-03, still unreleased). Left to the parser, the error blames the *key* —
/// `unrecognized name 'xpub66…'` — which sends the user hunting a transcription
/// mistake they did not make. It is an upstream gap, and the message has to say so.
pub(crate) fn check_before_parse(descriptor: &str) -> Result<(), DescriptorError> {
    if descriptor.contains("sortedmulti_a") {
        return Err(DescriptorError::UnsupportedUpstream {
            form: "sortedmulti_a".to_string(),
            detail: "absent from every released rust-miniscript (merged upstream but \
                     unreleased). Taproot multisig from Bitcoin Core, Sparrow or a hardware \
                     signer cannot be loaded by this build."
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two configuration values have to agree, or a row in `ALLOWED` names a leaf
    /// the first gate would already have rejected — an allowlist entry that can never
    /// match, which is the kind of dead policy nobody notices.
    #[test]
    fn every_allowed_leaf_is_permitted_by_the_leaf_policy() {
        for (chain, leaf, name) in ALLOWED {
            assert!(
                *leaf == Leaf::Key || LEAF_POLICY.contains(leaf),
                "{} ({:?}) names a leaf outside LEAF_POLICY",
                name,
                chain
            );
        }
    }

    #[test]
    fn shapes_render_as_descriptor_syntax() {
        let cases = [
            (vec![Wrapper::Pkh], Leaf::Key, "pkh"),
            (vec![Wrapper::Sh, Wrapper::Wpkh], Leaf::Key, "sh(wpkh)"),
            (vec![Wrapper::Wsh], Leaf::Multi, "wsh(multi)"),
            (
                vec![Wrapper::Sh, Wrapper::Wsh],
                Leaf::SortedMulti,
                "sh(wsh(sortedmulti))",
            ),
            (vec![Wrapper::Wsh], Leaf::Script, "wsh(miniscript)"),
            (vec![], Leaf::Multi, "multi"),
        ];

        for (chain, leaf, want) in cases {
            assert_eq!(Shape { chain, leaf }.describe(), want);
        }
    }

    /// Every name in `ALLOWED` must be one `describe()` could produce, or an
    /// acceptance and a refusal would call the same form by different names.
    #[test]
    fn allowed_names_match_what_describe_renders() {
        for (chain, leaf, name) in ALLOWED {
            let shape = Shape {
                chain: chain.to_vec(),
                leaf: *leaf,
            };
            assert_eq!(&shape.describe(), name);
        }
    }
}
