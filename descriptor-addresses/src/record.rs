use bitcoin::{Address, ScriptBuf};
use core::fmt;

use crate::NormalIndex;

/// Which chain of a wallet an address belongs to.
///
/// These are the library's names. The CLI renders them as *receive* and *change* —
/// that translation happens once, at the presentation edge, and never in here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeychainKind {
    /// The receive chain, path element `0`.
    External,
    /// The change chain, path element `1`.
    Internal,
}

impl KeychainKind {
    /// The path element this keychain occupies.
    ///
    /// `0` for external and `1` for internal, per BIP-44's change level, which every
    /// later standard (BIP-49/84/86) inherits unchanged. These are not arbitrary
    /// labels: a wallet that swapped them would show its change addresses as
    /// receiving addresses and hand one out to a payer.
    pub fn number(self) -> u32 {
        match self {
            KeychainKind::External => 0,
            KeychainKind::Internal => 1,
        }
    }
}

impl fmt::Display for KeychainKind {
    /// `f.pad` rather than `f.write_str`, so callers can align this in a column.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            KeychainKind::External => "external",
            KeychainKind::Internal => "internal",
        })
    }
}

/// The shape of script an address pays to.
///
/// Deliberately **not** a closed enum. Arbitrary custom scripts are the stated
/// destination for this crate, so an unenumerated form has to be able to print the
/// shape it actually saw rather than being forced into a variant that does not fit.
/// Miniscript's own descriptor-type accessor cannot make the distinction for us
/// either — it reports `Tr` for both a key-path `tr()` and a nested tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptType {
    form: String,
    recognised: bool,
}

impl ScriptType {
    pub(crate) fn known(form: &str) -> Self {
        ScriptType {
            form: form.to_string(),
            recognised: true,
        }
    }

    /// The form as written in descriptor syntax, e.g. `wpkh` or `sh(wsh(sortedmulti))`.
    pub fn form(&self) -> &str {
        &self.form
    }

    /// Whether this form is one the crate enumerates, as opposed to one it is
    /// reporting verbatim because it has no name for it.
    pub fn recognised(&self) -> bool {
        self.recognised
    }
}

impl fmt::Display for ScriptType {
    /// `f.pad` rather than `f.write_str`, so callers can align this in a column.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.form)
    }
}

/// One derived address, with everything a caller needs to use it without deriving
/// anything a second time.
#[derive(Debug, Clone)]
pub struct AddressRecord {
    index: NormalIndex,
    keychain: KeychainKind,
    relative_path: String,
    address: Address,
    script_type: ScriptType,
    script_pubkey: ScriptBuf,
}

impl AddressRecord {
    pub(crate) fn new(
        index: NormalIndex,
        keychain: KeychainKind,
        address: Address,
        script_type: ScriptType,
        script_pubkey: ScriptBuf,
    ) -> Self {
        AddressRecord {
            relative_path: format!("{}/{}", keychain.number(), index.get()),
            index,
            keychain,
            address,
            script_type,
            script_pubkey,
        }
    }

    /// The index this address was derived at.
    pub fn index(&self) -> NormalIndex {
        self.index
    }

    /// Which chain this address belongs to.
    pub fn keychain(&self) -> KeychainKind {
        self.keychain
    }

    /// The path **suffix** only, e.g. `0/4`.
    ///
    /// Not the full derivation path, and this is a decision rather than an omission.
    /// A 2-of-3 multisig has one key origin per key, so there is no single derivation
    /// path that describes an address. Origins are a descriptor-level fact, reported
    /// once against the descriptor; the suffix is the only part that varies per
    /// address, and it is the same suffix for every key.
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// The derived address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The shape of script this address pays to.
    pub fn script_type(&self) -> &ScriptType {
        &self.script_type
    }

    /// The `scriptPubKey` this address encodes, so a caller building a PSBT does not
    /// have to derive it a second time.
    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }
}
