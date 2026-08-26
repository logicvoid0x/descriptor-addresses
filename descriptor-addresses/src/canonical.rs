use miniscript::descriptor::{checksum, Descriptor, DescriptorPublicKey};

use crate::DescriptorError;

/// Render a descriptor the way this crate shows it to a human: BIP-380's `h`
/// notation, always checksummed.
///
/// **This is the only function in the crate that produces a descriptor string**, and
/// that is the point. The prototype that settled this decision rendered `48h` on one
/// line and `48'` on the next until every path was routed through one function, and a
/// screen that contradicts itself about notation is worse than either notation alone.
///
/// Why `h` rather than miniscript's `'`: BIP-380 is written in `h` and calls `'` the
/// alternative, and Core, HWI, Coldcard and Sparrow all emit `h`. This is not
/// cosmetic. BIP-380 checksums the **literal characters**, so one descriptor has two
/// different valid checksums — measured on this key: h-form `7nau6n94`, `'`-form
/// `fmqjkj0g`. Emitting `'` would hand the user a checksum that disagrees with the one
/// their own wallet displays, turning a short string designed for eyeball comparison
/// into a false alarm.
///
/// The rewrite therefore has to happen **before** the checksum is computed. Computing
/// it over the string we actually show is the whole mechanism.
///
/// The blanket replace is safe because `'` appears in no other role: it is not in the
/// base58, bech32 or hex alphabets, so within a descriptor a `'` can only ever be a
/// hardened marker.
/// Rewrite hardened markers from `'` to `h`.
///
/// **Every string this crate shows a human goes through here** — the canonical
/// descriptor, key origins, and the `tr()` internal key alike. That is the whole
/// point: an earlier version rewrote the descriptor but let origins and the internal
/// key render themselves, which put `48h` on one line and `48'` on the next. A screen
/// that contradicts itself about notation is worse than either notation alone.
///
/// The blanket replace is safe because `'` appears in no other role: it is not in the
/// base58, bech32 or hex alphabets, so within a descriptor a `'` can only ever be a
/// hardened marker.
pub(crate) fn h_notation(rendered: &str) -> String {
    rendered.replace('\'', "h")
}

pub(crate) fn canonical_h_form(
    descriptor: &Descriptor<DescriptorPublicKey>,
) -> Result<String, DescriptorError> {
    // `{:#}` renders without a checksum; `{}` would append miniscript's own, computed
    // over the `'`-form we are about to rewrite.
    let body = h_notation(&format!("{:#}", descriptor));

    let mut engine = checksum::Engine::new();
    engine.input(&body).map_err(DescriptorError::parse)?;

    Ok(format!("{}#{}", body, engine.checksum()))
}
