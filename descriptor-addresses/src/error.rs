use core::fmt;

/// What can be wrong with a single key expression.
///
/// Shared by [`DescriptorError`] and [`AssemblyError`], because a key is a key
/// whether it arrived inside a descriptor string or as a field a caller filled in.
/// Both entry points can hit every one of these, and a caller prompting for a
/// replacement wants the same information either way.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyError {
    /// A SLIP-132 prefix (`ypub`, `zpub`, and their testnet and multisig kin).
    ///
    /// Refused everywhere. The prefix encodes a script type, which is real
    /// information — but acting on it would mean this crate choosing a script type
    /// from a non-standard, discouraged convention, and choosing script types
    /// silently is the failure this crate exists to prevent. So the implication is
    /// preserved and handed back as a suggestion the user must affirm.
    Slip132 {
        /// The prefix as it appeared, e.g. `zpub`.
        prefix: String,
        /// The same key re-encoded with standard `xpub`/`tpub` version bytes.
        converted: String,
        /// The descriptor form the prefix was implying, e.g. `wpkh`.
        implies: String,
    },

    /// The `[fingerprint/path]` origin is not well-formed.
    ///
    /// Validation of an origin can only ever mean "well-formed": whether the path is
    /// the one the signing device actually used is not knowable from the descriptor.
    Origin {
        /// What was wrong, in terms of the text that was given.
        detail: String,
    },

    /// The key itself could not be read.
    Malformed {
        /// What was wrong, in terms of the text that was given.
        detail: String,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Slip132 {
                prefix,
                converted,
                implies,
            } => write!(
                f,
                "`{}` keys are not accepted: the prefix is a non-standard convention \
                 for encoding a script type. It implies `{}`. The same key as a \
                 standard xpub is {} — supply that inside the descriptor form you \
                 want, so the script type is your decision rather than a guess.",
                prefix, implies, converted
            ),
            KeyError::Origin { detail } => write!(f, "malformed key origin: {}", detail),
            KeyError::Malformed { detail } => write!(f, "malformed key: {}", detail),
        }
    }
}

impl std::error::Error for KeyError {}

/// How coarse this crate's view of "which network" actually is.
///
/// Two variants and no more, because that is the real granularity of a BIP-32 key:
/// testnet, testnet4 and signet share one set of version bytes, so a `tpub` cannot say
/// which of the three was meant. A four-variant type here would let a caller ask a
/// question the data cannot answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkClass {
    /// An `xpub`: mainnet, unambiguously.
    Mainnet,
    /// A `tpub`: testnet, testnet4 or signet, and no way to tell which.
    Test,
}

impl fmt::Display for NetworkClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            NetworkClass::Mainnet => "mainnet (an xpub)",
            NetworkClass::Test => "a test network (a tpub: testnet, testnet4 or signet)",
        })
    }
}

/// Everything that can go wrong turning a string into a [`ValidatedDescriptor`].
///
/// Hand-written rather than derived. A derive macro here would pull the proc-macro
/// chain into the library's dependency graph, and "twelve packages, zero proc-macro
/// crates" is the crate's central security claim — a hundred lines of `impl Display`
/// is a cheap price for keeping that claim literally true.
///
/// `#[non_exhaustive]` because the allowlist is designed to widen, so the set of ways
/// input can be refused must be able to grow in a patch release.
///
/// Every variant is **structured, not stringly**, because that is what makes prompting
/// mechanical: a caller that wants to ask for one corrected value needs to know which
/// value was wrong, not to scrape a sentence.
///
/// [`ValidatedDescriptor`]: crate::ValidatedDescriptor
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DescriptorError {
    /// The string is not a well-formed descriptor.
    ///
    /// Miniscript's own error is translated into `detail` rather than wrapped:
    /// wrapping would put a `miniscript` type in our public API and undo the opaque
    /// seam that keeps a miniscript major bump a patch release for our callers.
    Parse {
        /// Miniscript's own message, translated to a string so that no `miniscript`
        /// type appears in our public API.
        detail: String,
    },

    /// Something was wrong with one of the keys.
    Key(KeyError),

    /// The descriptor is well-formed but its form is not on the allowlist.
    UnsupportedForm {
        /// The form as written in descriptor syntax, e.g. `wsh(miniscript)`.
        form: String,
    },

    /// The form is one this crate would accept, but the library beneath it cannot
    /// parse it at all.
    ///
    /// Separate from [`DescriptorError::UnsupportedForm`] because the two are
    /// different news for the reader. "Not on our list" invites them to check what
    /// they pasted; "absent upstream" tells them nothing they type will help, and
    /// saves an evening spent hunting a mistake they did not make.
    UnsupportedUpstream {
        /// The form as written in descriptor syntax, e.g. `sortedmulti_a`.
        form: String,
        /// What is missing upstream, and what it costs the user.
        detail: String,
    },

    /// The checksum given does not match the descriptor it is attached to.
    ChecksumMismatch {
        /// The checksum as supplied.
        found: String,
        /// The checksum the descriptor actually has. Reported because comparing two
        /// short strings is how a transcription slip gets found.
        expected: String,
    },

    /// The checksum is not shaped like a checksum — more than one `#`, or the wrong
    /// length after it.
    ChecksumMalformed {
        /// What was wrong with it.
        detail: String,
    },

    /// A hardened step appeared in the wildcard position (`/*h` or `/*'`).
    ///
    /// Observed against miniscript 13.1.0: such a descriptor parses, reports its
    /// descriptor type, passes miniscript's own `sanity_check()`, and then panics
    /// when derived. Refusing it here is what makes derivation infallible.
    HardenedWildcard,

    /// A multipath descriptor carried more than the two paths a keychain split has
    /// meaning for.
    MultipathArity {
        /// How many paths the descriptor actually carried.
        paths: usize,
    },

    /// Two keys disagree about their multipath tuples.
    ///
    /// Either in length — which upstream may silently truncate — or in value, which
    /// pairs one key's change chain with another's receive chain.
    MultipathNonUniform {
        /// The differing tuples, one per multipath key, in the order the keys appear.
        found: Vec<String>,
    },

    /// The keys are for a different network than the one declared.
    ///
    /// Both fields are [`NetworkClass`] rather than strings, so a caller can branch on
    /// them — prompting "did you mean testnet?" should not require scraping a
    /// sentence.
    NetworkMismatch {
        /// The network this descriptor was being validated against.
        declared: NetworkClass,
        /// What the keys' version bytes say instead.
        found: NetworkClass,
    },

    /// One descriptor contains both mainnet and test-network keys.
    ///
    /// Its own variant rather than a [`DescriptorError::NetworkMismatch`], because
    /// there is no network the user could have declared that would make it valid.
    MixedNetworks,

    /// The same key appears twice, so the quorum is smaller than it looks.
    ///
    /// A 2-of-3 with a repeated key is a 1-of-2. Available as an advisory instead via
    /// [`ValidatedDescriptor::parse_permissive`].
    ///
    /// [`ValidatedDescriptor::parse_permissive`]: crate::ValidatedDescriptor::parse_permissive
    DuplicateKey {
        /// The key that appeared more than once.
        key: String,
    },

    /// A `k`-of-`n` where `k` exceeds `n`, which can never be satisfied.
    ThresholdExceedsKeys {
        /// The threshold asked for.
        threshold: usize,
        /// How many keys there are.
        keys: usize,
    },

    /// A P2SH redeemScript exceeded the 520-byte limit on a single stack element.
    ///
    /// Distinct from [`DescriptorError::TooManyKeys`] on purpose — see that variant.
    ScriptTooLarge {
        /// How large the script would be.
        bytes: usize,
        /// The consensus limit it exceeded.
        limit: usize,
    },

    /// More keys than `CHECKMULTISIG` itself permits.
    ///
    /// Deliberately **not** merged with [`DescriptorError::ScriptTooLarge`], though
    /// both present to a user as "too many keys". They are two independent consensus
    /// rules with two different ceilings, and one message cannot serve both: telling
    /// someone who hit the P2SH limit at 16 keys that the maximum is 20 is true of
    /// the other rule and useless for theirs.
    TooManyKeys {
        /// How many keys were given.
        keys: usize,
        /// The maximum this rule permits.
        max: usize,
    },

    /// A `tr()` internal key also appears in one of the leaves.
    ///
    /// The key path is then a single-key spending route around the quorum:
    /// `tr(A,multi_a(2,A,B))` looks like a 2-of-2 that A can spend alone.
    InternalKeyReusedInLeaf {
        /// The key that appears in both positions.
        key: String,
    },
}

impl DescriptorError {
    /// Translate a foreign error into [`DescriptorError::Parse`].
    ///
    /// Every call site that touches miniscript funnels through here, which is what
    /// keeps "translated, never wrapped" a single decision rather than a habit
    /// repeated at each `map_err`.
    pub(crate) fn parse<E: fmt::Display>(source: E) -> Self {
        DescriptorError::Parse {
            detail: source.to_string(),
        }
    }
}

impl From<KeyError> for DescriptorError {
    fn from(e: KeyError) -> Self {
        DescriptorError::Key(e)
    }
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::Parse { detail } => {
                write!(f, "not a valid output descriptor: {}", detail)
            }
            DescriptorError::Key(e) => write!(f, "{}", e),
            DescriptorError::UnsupportedForm { form } => write!(
                f,
                "descriptor form `{}` is not on this crate's allowlist",
                form
            ),
            DescriptorError::UnsupportedUpstream { form, detail } => {
                write!(f, "`{}` is not a mistake on your part: {}", form, detail)
            }
            DescriptorError::ChecksumMismatch { found, expected } => write!(
                f,
                "checksum `{}` does not match this descriptor; it should be `{}`. \
                 One of the two was mistyped",
                found, expected
            ),
            DescriptorError::ChecksumMalformed { detail } => {
                write!(f, "malformed checksum: {}", detail)
            }
            DescriptorError::HardenedWildcard => write!(
                f,
                "a hardened step cannot be a wildcard: use `/*` for the derivable \
                 position, and put hardened steps in the key origin"
            ),
            DescriptorError::MultipathArity { paths } => write!(
                f,
                "expected one or two derivation paths, found {}: a wallet has a \
                 receive chain and a change chain, and no third chain for the extra \
                 path to be",
                paths
            ),
            DescriptorError::MultipathNonUniform { found } => write!(
                f,
                "the keys disagree about their derivation paths ({}). Every key must \
                 carry the same tuple, or the chains cannot be paired up",
                found.join(" vs ")
            ),
            DescriptorError::NetworkMismatch { declared, found } => write!(
                f,
                "this descriptor was read as {}, but its keys are {}",
                declared, found
            ),
            DescriptorError::MixedNetworks => write!(
                f,
                "this descriptor mixes mainnet and test-network keys, so no network \
                 is the right one to read it as"
            ),
            DescriptorError::DuplicateKey { key } => write!(
                f,
                "the key {} appears more than once, so the quorum is smaller than it \
                 looks — a 2-of-3 with a repeated key is a 1-of-2",
                key
            ),
            DescriptorError::ThresholdExceedsKeys { threshold, keys } => write!(
                f,
                "a {}-of-{} can never be satisfied: the threshold is larger than the \
                 number of keys",
                threshold, keys
            ),
            // The arithmetic is spelled out because a bare 520 is unreviewable: the
            // next reader cannot tell a real consensus limit from a guess. It is
            // stated as the boundary case rather than recomputed for the input,
            // because 15-versus-16 is the fact the reader needs — an earlier draft
            // printed the 16-key arithmetic beside a 17-key input's byte count.
            DescriptorError::ScriptTooLarge { bytes, limit } => write!(
                f,
                "this redeemScript would be {} bytes, and a P2SH redeemScript is pushed \
                 as one stack element, which consensus caps at {}. Legacy P2SH multisig \
                 therefore stops at 15 keys: the 16-key case is already 547 bytes \
                 (1 + 16*34 + 1 + 1)",
                bytes, limit
            ),
            DescriptorError::TooManyKeys { keys, max } => write!(
                f,
                "{} keys exceeds the {} that CHECKMULTISIG itself permits \
                 (MAX_PUBKEYS_PER_MULTISIG). This is a different rule from the P2SH \
                 script-size limit, and a different ceiling",
                keys, max
            ),
            DescriptorError::InternalKeyReusedInLeaf { key } => write!(
                f,
                "the taproot internal key {} also appears in a leaf, so it can spend \
                 alone through the key path and the quorum in the leaf is not the \
                 only way to spend",
                key
            ),
        }
    }
}

impl std::error::Error for DescriptorError {}

/// What can go wrong assembling a descriptor from parts a caller supplied.
///
/// Two enums rather than one, so the CLI's match has no impossible arms: parsing
/// cannot fail with a threshold that exceeds the key count when the caller never
/// supplied a threshold, and assembly cannot fail with a bad checksum when there was
/// no string to checksum.
///
/// The assembly entry points themselves belong to a later ticket; this enum exists
/// now because [`KeyError`] is shared, and the shape of that sharing is a decision
/// better made once than twice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssemblyError {
    /// Something was wrong with one of the keys.
    Key(KeyError),

    /// A `k`-of-`n` where `k` exceeds `n`, which can never be satisfied.
    ThresholdExceedsKeys {
        /// The threshold asked for.
        threshold: usize,
        /// How many keys were supplied.
        keys: usize,
    },

    /// The same key was supplied twice.
    DuplicateKey {
        /// The key that appeared more than once.
        key: String,
    },
}

impl From<KeyError> for AssemblyError {
    fn from(e: KeyError) -> Self {
        AssemblyError::Key(e)
    }
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssemblyError::Key(e) => write!(f, "{}", e),
            AssemblyError::ThresholdExceedsKeys { threshold, keys } => write!(
                f,
                "a {}-of-{} can never be satisfied: the threshold is larger than the \
                 number of keys",
                threshold, keys
            ),
            AssemblyError::DuplicateKey { key } => {
                write!(f, "the key {} was supplied more than once", key)
            }
        }
    }
}

impl std::error::Error for AssemblyError {}
