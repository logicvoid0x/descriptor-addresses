use bitcoin::bip32::Fingerprint;
use core::fmt;

/// Where one of a descriptor's keys came from: a master fingerprint and the path
/// walked from it.
///
/// # Why this is a descriptor-level fact
///
/// A 2-of-3 multisig has **one origin per key**, so there is no single "derivation
/// path" that describes an address — asking for one is asking the wrong question.
/// Origins are therefore reported once, against the descriptor, while
/// [`AddressRecord::relative_path`] carries only the suffix (`0/4`), which is the
/// part that varies per address and is the same for every key.
///
/// This was discovered by prototyping against real multisig data rather than
/// reasoned about; a single-sig-shaped record with one path per address looks
/// perfectly sensible right up until a quorum arrives.
///
/// [`AddressRecord::relative_path`]: crate::AddressRecord::relative_path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyOrigin {
    fingerprint: Fingerprint,
    path: String,
}

impl KeyOrigin {
    pub(crate) fn new(fingerprint: Fingerprint, path: String) -> Self {
        KeyOrigin { fingerprint, path }
    }

    /// The master key's fingerprint, as a signing device reports it.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The derivation path, in BIP-380 `h` notation, e.g. `m/48h/0h/0h/2h`.
    ///
    /// Pre-rendered rather than returned as a typed path, and deliberately: this
    /// crate shows exactly one hardened notation everywhere it shows a string to a
    /// human. A typed `DerivationPath` formats itself with `'`, so handing one out
    /// would put the second notation back on screen next to the first — which is the
    /// bug the canonical form exists to prevent.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.fingerprint, self.path)
    }
}
