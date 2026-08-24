//! `descaddr` — derive addresses from a Bitcoin output descriptor at a terminal.
//!
//! # A negative constraint that matters more than any flag
//!
//! **The listing path never enables raw mode or the alternate screen.**
//!
//! It is tempting to reach for them the moment a table needs formatting, and both
//! break the tool in ways that are easy to miss when you are the one who wrote it:
//! raw mode captures mouse events, which kills the click-drag selection that makes an
//! address copyable for free, and the alternate screen wipes the output the moment the
//! process exits, so the addresses the user asked for are gone before they can use
//! them. This binary therefore writes plain lines to stdout and nothing else.

use std::process::ExitCode;

use descriptor_addresses::{
    AddressRecord, DescriptorError, KeychainKind, Network, NormalIndex, ValidatedDescriptor,
};

const USAGE: &str = "\
descaddr — derive addresses from a Bitcoin output descriptor

USAGE:
    descaddr list <DESCRIPTOR> [--start N] [--count N]

OPTIONS:
    --start N   first index to derive (default 0)
    --count N   how many indices to derive (default 20)
    -h, --help  print this message

This build accepts mainnet wpkh descriptors only.";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(output) => {
            print!("{}", output);
            ExitCode::SUCCESS
        }
        Err(Failure::Usage(message)) => {
            eprintln!("{}\n\n{}", message, USAGE);
            // Exit codes are formalised by the ticket that owns the process boundary;
            // 2-for-usage is the convention that ticket will inherit.
            ExitCode::from(2)
        }
        Err(Failure::Descriptor(e)) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    Usage(String),
    Descriptor(DescriptorError),
}

impl From<DescriptorError> for Failure {
    fn from(e: DescriptorError) -> Self {
        Failure::Descriptor(e)
    }
}

fn run(args: Vec<String>) -> Result<String, Failure> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        return Err(Failure::Usage("nothing to do".to_string()));
    }
    if args[0] != "list" {
        return Err(Failure::Usage(format!("unknown command `{}`", args[0])));
    }

    let mut descriptor: Option<String> = None;
    let mut start: u32 = 0;
    let mut count: u32 = 20;

    // Mainnet is hard-coded, and that is deliberate rather than unfinished. A
    // `--network` flag without the enforcement that goes with it is a footgun: it
    // will happily render testnet-shaped addresses from mainnet keys, or the reverse,
    // and the whole reason this crate exists is that wrong-shaped addresses fail
    // silently and look exactly like success. The flag arrives with the ticket that
    // makes network enforced rather than merely reported.
    let network = Network::Bitcoin;

    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--start" => start = number("--start", rest.next())?,
            "--count" => count = number("--count", rest.next())?,
            other if other.starts_with('-') => {
                return Err(Failure::Usage(format!("unknown option `{}`", other)))
            }
            other => {
                if descriptor.replace(other.to_string()).is_some() {
                    return Err(Failure::Usage("more than one descriptor given".to_string()));
                }
            }
        }
    }

    let descriptor =
        descriptor.ok_or_else(|| Failure::Usage("no descriptor given".to_string()))?;
    let start = NormalIndex::new(start).ok_or_else(|| {
        Failure::Usage("--start must be below 2147483648, the first hardened index".to_string())
    })?;

    let wallet = ValidatedDescriptor::parse(&descriptor, network)?;

    let mut records: Vec<AddressRecord> = wallet.external().addresses(start, count).collect();
    if let Some(change) = wallet.internal() {
        records.extend(change.addresses(start, count));
    }

    Ok(render(&wallet, &records))
}

fn number(flag: &str, value: Option<&String>) -> Result<u32, Failure> {
    let value = value.ok_or_else(|| Failure::Usage(format!("{} needs a value", flag)))?;
    value
        .parse()
        .map_err(|_| Failure::Usage(format!("{} must be a whole number, got `{}`", flag, value)))
}

/// Rendering is a pure function of the records, not a series of `println!` calls.
///
/// The ticket that owns output formats tests this seam directly — `records -> String`
/// needs no process to exercise — so the shape is established here rather than
/// retrofitted.
fn render(wallet: &ValidatedDescriptor, records: &[AddressRecord]) -> String {
    let mut out = String::new();

    out.push_str(&format!("descriptor  {}\n", elide(wallet.canonical(), 66)));
    out.push_str(&format!(
        "network     {}  -  {}  -  {} addresses\n\n",
        wallet.network(),
        wallet.script_type(),
        records.len()
    ));

    out.push_str("CHAIN     IDX  PATH   ADDRESS\n");
    for record in records {
        out.push_str(&format!(
            "{:<8} {:>4}  {:<5}  {}\n",
            chain_label(record.keychain()),
            record.index(),
            record.relative_path(),
            record.address()
        ));
    }

    out
}

/// The presentation edge, and the only place this translation happens.
///
/// The library says `External`/`Internal`, because those are the names the descriptor
/// world uses. A person reading their own wallet says *receive* and *change*.
fn chain_label(kind: KeychainKind) -> &'static str {
    match kind {
        KeychainKind::External => "receive",
        KeychainKind::Internal => "change",
    }
}

/// Shorten a long descriptor for the header line. The full form stays available —
/// the `echo` subcommand that prints it arrives with the advisories ticket.
fn elide(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let keep = width.saturating_sub(3);
    let head: String = s.chars().take(keep * 2 / 3).collect();
    let tail: String = s
        .chars()
        .skip(s.chars().count() - (keep - keep * 2 / 3))
        .collect();
    format!("{}...{}", head, tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn lists_both_keychains_by_default() {
        let descriptor = format!("wpkh({}/<0;1>/*)", XPUB);
        let out = run(args(&["list", &descriptor, "--count", "2"])).ok().unwrap();

        assert!(out.contains("bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz"));
        assert_eq!(out.matches("receive").count(), 2);
        assert_eq!(out.matches("change").count(), 2);
    }

    #[test]
    fn start_offsets_the_range() {
        let descriptor = format!("wpkh({}/0/*)", XPUB);
        let out = run(args(&["list", &descriptor, "--start", "2", "--count", "1"]))
            .ok()
            .unwrap();

        assert!(out.contains("0/2"));
        assert!(!out.contains("0/0"));
    }

    #[test]
    fn a_single_path_descriptor_lists_only_receive() {
        let descriptor = format!("wpkh({}/0/*)", XPUB);
        let out = run(args(&["list", &descriptor, "--count", "3"])).ok().unwrap();

        assert_eq!(out.matches("receive").count(), 3);
        assert!(!out.contains("change"));
    }

    #[test]
    fn a_hardened_start_is_a_usage_error_not_a_panic() {
        let descriptor = format!("wpkh({}/0/*)", XPUB);
        match run(args(&["list", &descriptor, "--start", "2147483648"])) {
            Err(Failure::Usage(message)) => assert!(message.contains("2147483648")),
            _ => panic!("expected a usage error, not a descriptor error or success"),
        }
    }

    /// `--network` is not a flag this build has, and its absence is deliberate:
    /// rendering addresses for a network the keys are not for is the exact silent
    /// failure this crate exists to prevent, and the enforcement lands with ticket 04.
    #[test]
    fn there_is_no_unguarded_network_flag() {
        let descriptor = format!("wpkh({}/0/*)", XPUB);
        match run(args(&["list", &descriptor, "--network", "testnet"])) {
            Err(Failure::Usage(message)) => assert!(message.contains("--network")),
            _ => panic!("--network must be rejected while network is unenforced"),
        }
    }

    #[test]
    fn an_unsupported_form_reports_the_descriptor_error() {
        let descriptor = format!("pkh({}/0/*)", XPUB);
        match run(args(&["list", &descriptor])) {
            Err(Failure::Descriptor(e)) => assert!(format!("{}", e).contains("pkh")),
            _ => panic!("expected a descriptor error naming the form"),
        }
    }
}
