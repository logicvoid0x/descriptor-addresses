use core::fmt;

/// The first hardened index, per BIP-32: indices `0 .. 2^31` are normal, and
/// `2^31 .. 2^32` are hardened. Hardened derivation needs the private key, which this
/// crate never holds, so only the lower half is representable here.
const HARDENED_THRESHOLD: u32 = 1 << 31;

/// A BIP-32 index that is guaranteed not to be hardened.
///
/// This newtype is load-bearing rather than decorative. Derivation is total — see
/// [`Keychain::address_at`] — and it can only be total because the one remaining way
/// it could fail has been made unrepresentable. A `u32` parameter would put the error
/// path back, in the hottest loop the API has.
///
/// [`Keychain::address_at`]: crate::Keychain::address_at
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalIndex(u32);

impl NormalIndex {
    /// The first index of a keychain.
    pub const ZERO: NormalIndex = NormalIndex(0);

    /// Returns `None` if `index` is hardened (`>= 2^31`).
    pub fn new(index: u32) -> Option<Self> {
        if index < HARDENED_THRESHOLD {
            Some(NormalIndex(index))
        } else {
            None
        }
    }

    /// The underlying index.
    pub fn get(self) -> u32 {
        self.0
    }

    /// The next index, or `None` at the top of the normal range.
    pub fn next(self) -> Option<Self> {
        NormalIndex::new(self.0.checked_add(1)?)
    }
}

impl fmt::Display for NormalIndex {
    /// Delegates to the inner `u32` rather than `write!(f, "{}", self.0)`.
    ///
    /// The difference matters: `write!` with a fresh `{}` **discards the formatter's
    /// flags**, so a caller asking for `{:>4}` would silently get no padding. The
    /// table, JSON and CSV renderers all align this column.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_boundary_is_two_to_the_thirty_first() {
        assert!(NormalIndex::new(HARDENED_THRESHOLD - 1).is_some());
        assert!(NormalIndex::new(HARDENED_THRESHOLD).is_none());
    }

    /// Regression: `Display` written as `write!(f, "{}", self.0)` drops the caller's
    /// formatting flags, so an aligned column silently collapses.
    #[test]
    fn display_honours_the_callers_width() {
        assert_eq!(format!("{:>4}", NormalIndex::new(7).unwrap()), "   7");
        assert_eq!(format!("{:<4}|", NormalIndex::new(7).unwrap()), "7   |");
        assert_eq!(format!("{}", NormalIndex::new(7).unwrap()), "7");
    }

    #[test]
    fn next_stops_at_the_top_of_the_normal_range() {
        let last = NormalIndex::new(HARDENED_THRESHOLD - 1).unwrap();
        assert!(last.next().is_none());
        assert_eq!(NormalIndex::ZERO.next().unwrap().get(), 1);
    }
}
