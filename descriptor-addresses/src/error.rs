use core::fmt;

/// Everything that can go wrong turning a string into a [`ValidatedDescriptor`].
///
/// Hand-written rather than derived. A derive macro here would pull the proc-macro
/// chain into the library's dependency graph, and "twelve packages, zero proc-macro
/// crates" is the crate's central security claim — sixty lines of `impl Display` is a
/// cheap price for keeping that claim literally true.
///
/// `#[non_exhaustive]` because the allowlist is designed to widen, so the set of ways
/// input can be refused must be able to grow in a patch release.
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

    /// The descriptor is well-formed but its form is not on the allowlist.
    UnsupportedForm {
        /// The form as written in descriptor syntax, e.g. `pkh`.
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

    /// A hardened step appeared in the wildcard position (`/*h` or `/*'`).
    ///
    /// Observed against miniscript 13.1.0: such a descriptor parses, reports its
    /// descriptor type, passes miniscript's own `sanity_check()`, and then panics
    /// when derived. Refusing it here is what makes derivation infallible.
    HardenedWildcard,

    /// A multipath descriptor did not carry exactly one or two paths.
    MultipathArity {
        /// How many paths the descriptor actually carried.
        paths: usize,
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

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::Parse { detail } => {
                write!(f, "not a valid output descriptor: {}", detail)
            }
            DescriptorError::UnsupportedForm { form } => write!(
                f,
                "descriptor form `{}` is not on this crate's allowlist",
                form
            ),
            DescriptorError::UnsupportedUpstream { form, detail } => {
                write!(f, "`{}` is not a mistake on your part: {}", form, detail)
            }
            DescriptorError::HardenedWildcard => write!(
                f,
                "a hardened step cannot be a wildcard: use `/*` for the derivable \
                 position, and put hardened steps in the key origin"
            ),
            DescriptorError::MultipathArity { paths } => {
                write!(f, "expected one or two derivation paths, found {}", paths)
            }
        }
    }
}

impl std::error::Error for DescriptorError {}
