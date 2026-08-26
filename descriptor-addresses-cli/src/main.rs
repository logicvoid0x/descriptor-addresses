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

use std::io::IsTerminal;
use std::process::ExitCode;

mod interactive;

use descriptor_addresses::{
    AddressRecord, Advisory, DescriptorError, DescriptorKey, KeyOrdering, KeychainKind, Multisig,
    MultisigScript, Network, NormalIndex, SingleSig, SingleSigScript, ValidatedDescriptor,
};

const USAGE: &str = "\
descaddr — derive addresses from a Bitcoin output descriptor

USAGE:
    descaddr list <DESCRIPTOR> [--start N] [--count N] [--allow-duplicate-keys]
    descaddr echo <DESCRIPTOR>
    descaddr assemble --key K [--key K ...] --script TYPE [--threshold N] [--as-given]
    descaddr assemble [--interactive]

COMMANDS:
    list   derive and print addresses
    echo   print the full canonical descriptor, unelided
    assemble  build a descriptor from keys and flags, and echo it back

OPTIONS:
    --start N   first index to derive (default 0)
    --count N   how many indices to derive (default 20)
    -h, --help  print this message

    --interactive
                prompt for keys, script type, threshold and ordering instead of
                taking them as flags. Assumed when `assemble` is run with no
                flags at a terminal; required when stdin is a pipe, so a script
                that forgot an argument gets an error rather than a prompt it
                cannot answer. Prompts are written to stderr, so the assembled
                descriptor can still be redirected on its own.

    --allow-duplicate-keys
                accept a descriptor in which a key appears twice. Such a wallet
                has a smaller quorum than it looks — a 2-of-3 with a repeated
                key is a 1-of-2 — so it is refused unless you say otherwise.
                Relaxes this one rule and nothing else.
";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(Output { stdout, advisories }) => {
            print!("{}", stdout);

            // Advisories go to **stderr**, so `descaddr list … | jq` still receives
            // clean output while a human at a terminal sees both. They are findings
            // about input that was accepted, so they must not contaminate the data.
            if !advisories.is_empty() {
                eprint!("{}", advisories);
            }

            // Zero. An advisory is a remark about input this crate accepted, and a
            // script that treats one as failure would refuse a wallet whose only
            // fault is having no checksum.
            ExitCode::SUCCESS
        }
        Err(Failure::Usage(message)) => {
            eprintln!("{}\n\n{}{}", message, USAGE, supported_forms());
            // Exit codes are formalised by the ticket that owns the process boundary;
            // 2-for-usage is the convention that ticket will inherit.
            ExitCode::from(2)
        }
        Err(Failure::Descriptor(e)) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
        Err(Failure::Key(e)) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
        Err(Failure::Assembly(e)) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
        Err(Failure::Aborted(message)) => {
            eprintln!("{}", message);
            // Non-zero: a caller that asked for a wallet did not get one, and a
            // script that stopped checking here would go on to derive from nothing.
            ExitCode::FAILURE
        }
    }
}

/// The supported-forms block of the help text.
///
/// Built from the library's own list rather than typed out here. A CLI that
/// advertises a form the library refuses — or omits one it accepts — sends the reader
/// looking for a mistake in their descriptor that is really a mistake in this string.
fn supported_forms() -> String {
    let mut out = String::from("\nAccepts these mainnet descriptor forms:\n");
    for form in descriptor_addresses::supported_forms() {
        out.push_str("    ");
        out.push_str(form);
        out.push('\n');
    }
    out
}

/// What a successful run produces: data for stdout, remarks for stderr.
///
/// Two fields rather than one string because they have different destinations and
/// different meanings — one is the answer, the other is commentary about the question.
#[derive(Debug)]
struct Output {
    stdout: String,
    advisories: String,
}

/// Render advisories for a human.
///
/// Prefixed `note:` rather than `warning:`, deliberately. Every one of these describes
/// input the crate **accepted**, and "warning" trains a reader to expect something is
/// wrong — which, for the notation-rewritten advisory, is the exact misreading it
/// exists to prevent.
fn render_advisories(advisories: &[Advisory]) -> String {
    let mut out = String::new();
    for advisory in advisories {
        out.push_str(&format!("note: {}\n", advisory));
    }
    out
}

#[derive(Debug)]
enum Failure {
    /// The command line itself was wrong: exit 2, print usage.
    Usage(String),
    /// The descriptor was refused. Exit 1 with the reason -- printing usage here
    /// would bury a specific, actionable error under a wall of flags.
    Descriptor(DescriptorError),
    /// A key was refused before assembly could start.
    Key(descriptor_addresses::KeyError),
    /// The parts did not assemble into something this crate accepts.
    Assembly(descriptor_addresses::AssemblyError),
    /// The interactive flow did not finish: the input ended, or the user said no.
    /// Its message is already a sentence addressed to the person who typed it, so it
    /// is printed as-is rather than prefixed `error:`.
    Aborted(String),
}

impl From<DescriptorError> for Failure {
    fn from(e: DescriptorError) -> Self {
        Failure::Descriptor(e)
    }
}

fn run(args: Vec<String>) -> Result<Output, Failure> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        return Err(Failure::Usage("nothing to do".to_string()));
    }

    match args[0].as_str() {
        "list" => list(&args[1..]),
        "echo" => echo(&args[1..]),
        "assemble" => assemble(&args[1..]),
        other => Err(Failure::Usage(format!("unknown command `{}`", other))),
    }
}

/// Build a descriptor from keys and flags, and echo it back.
///
/// The echo is a safety feature rather than a courtesy: the descriptor is the single
/// string that recovers this wallet, and a user who assembled one from parts has never
/// seen it before. It is printed first, and on its own line, so it can be redirected
/// to a file without the address table coming with it.
///
/// Values arrive either as flags or through prompts, and the two meet here: both
/// build a [`SingleSig`] or a [`Multisig`] and hand it to the library, which cannot
/// tell them apart. There is no second input path and no rule reachable from one route
/// and not the other.
fn assemble(args: &[String]) -> Result<Output, Failure> {
    let mut keys: Vec<String> = Vec::new();
    let mut script: Option<String> = None;
    let mut threshold: Option<u32> = None;
    let mut ordering = KeyOrdering::Sorted;
    let mut ordering_given = false;
    let mut interactive = false;
    let mut count: u32 = 20;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--key" => keys.push(value("--key", rest.next())?),
            "--script" => script = Some(value("--script", rest.next())?),
            "--threshold" => threshold = Some(number("--threshold", rest.next())?),
            "--count" => count = number("--count", rest.next())?,
            // `sortedmulti` is the default because it is the safe one: every cosigner
            // derives the same addresses regardless of the order they typed keys in.
            // Choosing `multi` makes the order part of the wallet, so it is opt-in.
            "--as-given" => {
                ordering = KeyOrdering::AsGiven;
                ordering_given = true;
            }
            "--interactive" => interactive = true,
            other => return Err(Failure::Usage(format!("unknown option `{}`", other))),
        }
    }

    // `--count` is not in this set. It says how much of the wallet to print, not what
    // the wallet is, so it composes with either route.
    let flags_given = !keys.is_empty() || script.is_some() || threshold.is_some() || ordering_given;

    // Exhaustive rather than `if let`, so a third route cannot be added without
    // deciding here what it does.
    match route(flags_given, interactive, std::io::stdin().is_terminal())? {
        Route::Prompt => {
            let wallet = interactive::Session::on_stdio().assemble(Network::Bitcoin)?;
            return Ok(render_output(&wallet, count));
        }
        Route::Flags => {}
    }

    if keys.is_empty() {
        return Err(Failure::Usage(
            "no keys given: pass --key for each cosigner".to_string(),
        ));
    }

    let script = script.ok_or_else(|| {
        // The one prompt this command will never guess its way out of. Four script
        // types derive four incompatible sets of addresses from the same key, and
        // picking one for the user is the exact failure this crate exists to prevent.
        Failure::Usage(
            "--script is required: pkh, sh-wpkh, wpkh, tr for a single key; \
             wsh or sh-wsh for a quorum"
                .to_string(),
        )
    })?;

    let parsed: Result<Vec<DescriptorKey>, _> =
        keys.iter().map(|k| DescriptorKey::parse(k)).collect();
    // A rejected key is a descriptor problem, not a command-line one: exit 1 with the
    // reason rather than exit 2 with a wall of flags the user got right.
    let parsed = parsed.map_err(Failure::Key)?;

    let wallet = match threshold {
        None => {
            if parsed.len() > 1 {
                return Err(Failure::Usage(
                    "--threshold is required when more than one --key is given".to_string(),
                ));
            }
            ValidatedDescriptor::assemble_single_sig(SingleSig {
                key: parsed.into_iter().next().expect("checked non-empty"),
                script_type: single_sig_script(&script)?,
                network: Network::Bitcoin,
                path: None,
            })
        }
        Some(threshold) => ValidatedDescriptor::assemble_multisig(Multisig {
            keys: parsed,
            threshold,
            script_type: multisig_script(&script)?,
            ordering,
            network: Network::Bitcoin,
            path: None,
        }),
    }
    .map_err(Failure::Assembly)?;

    Ok(render_output(&wallet, count))
}

/// Where `assemble` gets its values from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// Read them from the flags already parsed.
    Flags,
    /// Ask for them.
    Prompt,
}

/// Choose between reading flags and asking questions.
///
/// A free function of three booleans rather than a branch inside `assemble`, because
/// one of the three is "stdin is a terminal" — and a test cannot be a terminal. The
/// decision this ticket is really about is therefore the one part of it no
/// process-boundary test could otherwise reach.
///
/// The three cases, and why the middle one is not a hang:
///
/// - **A terminal with no flags** is someone who ran `descaddr assemble` to be walked
///   through it. Prompting is the answer; erroring at them is the behaviour this
///   ticket exists to remove.
/// - **A pipe with no flags** is a script that forgot an argument. Prompting at it
///   would hang a build until something times out, so it gets an error that names the
///   cause instead.
/// - **`--interactive`** says "prompt anyway", which is how the flow is driven by an
///   answer file, a heredoc or a test. It is required rather than inferred precisely
///   so that the middle case can stay an error.
fn route(flags_given: bool, interactive: bool, stdin_is_terminal: bool) -> Result<Route, Failure> {
    match (flags_given, interactive) {
        // Two answers to the same question, and no rule for which wins. Asking is
        // better than picking, and better than merging them into a wallet that is
        // half typed and half answered.
        (true, true) => Err(Failure::Usage(
            "--interactive prompts for the same values --key, --script, --threshold \
             and --as-given supply: pass one or the other"
                .to_string(),
        )),
        (true, false) => Ok(Route::Flags),
        (false, true) => Ok(Route::Prompt),
        (false, false) if stdin_is_terminal => Ok(Route::Prompt),
        (false, false) => Err(Failure::Usage(
            "nothing to assemble, and stdin is not a terminal so there is nobody to \
             ask: pass --key for each cosigner along with --script, or --interactive \
             to be prompted through the pipe"
                .to_string(),
        )),
    }
}

/// What an assembled wallet prints, whichever route built it.
///
/// Shared by the flag path and the prompted one deliberately: if the two rendered
/// separately, the descriptor a user confirmed on screen and the descriptor they
/// backed up could drift apart, and nothing would say which was the wallet.
fn render_output(wallet: &ValidatedDescriptor, count: u32) -> Output {
    let start = NormalIndex::ZERO;
    let mut records: Vec<AddressRecord> = wallet.external().addresses(start, count).collect();
    if let Some(change) = wallet.internal() {
        records.extend(change.addresses(start, count));
    }

    Output {
        stdout: format!("{}\n\n{}", wallet.canonical(), render(wallet, &records)),
        advisories: render_advisories(wallet.advisories()),
    }
}

fn single_sig_script(name: &str) -> Result<SingleSigScript, Failure> {
    match name {
        "pkh" => Ok(SingleSigScript::Pkh),
        "sh-wpkh" => Ok(SingleSigScript::ShWpkh),
        "wpkh" => Ok(SingleSigScript::Wpkh),
        "tr" => Ok(SingleSigScript::Tr),
        // Named explicitly rather than falling through to "unknown", because a user
        // asking for `wsh` with one key has misunderstood something specific.
        "wsh" | "sh-wsh" => Err(Failure::Usage(format!(
            "`{}` is a multisig script type; pass --threshold and more than one --key",
            name
        ))),
        other => Err(Failure::Usage(format!(
            "unknown script type `{}`: expected pkh, sh-wpkh, wpkh or tr",
            other
        ))),
    }
}

fn multisig_script(name: &str) -> Result<MultisigScript, Failure> {
    match name {
        "wsh" => Ok(MultisigScript::Wsh),
        "sh-wsh" => Ok(MultisigScript::ShWsh),
        // The refusal ticket 02 decided, surfaced where a user meets it. `tr` is not
        // assemblable at all: a taproot output needs an internal key, which is a
        // second single-key route around the quorum.
        "tr" => Err(Failure::Usage(
            "taproot multisig cannot be assembled: a tr() output needs an internal \
             key, which is a second single-key way to spend the same coins. Write the \
             tr(...) descriptor yourself and pass it to `list` if that is what you want"
                .to_string(),
        )),
        "pkh" | "sh-wpkh" | "wpkh" => Err(Failure::Usage(format!(
            "`{}` is a single-key script type; drop --threshold or pass one --key",
            name
        ))),
        other => Err(Failure::Usage(format!(
            "unknown script type `{}`: expected wsh or sh-wsh",
            other
        ))),
    }
}

fn value(flag: &str, next: Option<&String>) -> Result<String, Failure> {
    next.cloned()
        .ok_or_else(|| Failure::Usage(format!("{} needs a value", flag)))
}

/// Print the full canonical descriptor and nothing else.
///
/// It exists because `list` elides the descriptor to one line to keep the table
/// readable — and the descriptor is the single string a user must back up, so there
/// has to be a way to see all of it. One string on stdout, so it can be redirected
/// straight into a file.
fn echo(args: &[String]) -> Result<Output, Failure> {
    let descriptor = single_descriptor(args)?;
    let wallet = ValidatedDescriptor::parse(&descriptor, Network::Bitcoin)?;

    Ok(Output {
        stdout: format!("{}\n", wallet.canonical()),
        advisories: render_advisories(wallet.advisories()),
    })
}

/// The one positional argument shared by both commands.
fn single_descriptor(args: &[String]) -> Result<String, Failure> {
    let mut descriptor: Option<String> = None;

    for arg in args {
        if arg.starts_with('-') {
            return Err(Failure::Usage(format!("unknown option `{}`", arg)));
        }
        if descriptor.replace(arg.to_string()).is_some() {
            return Err(Failure::Usage("more than one descriptor given".to_string()));
        }
    }

    descriptor.ok_or_else(|| Failure::Usage("no descriptor given".to_string()))
}

fn list(args: &[String]) -> Result<Output, Failure> {
    let mut descriptor: Option<String> = None;
    let mut start: u32 = 0;
    let mut count: u32 = 20;
    // Ticket 03: the CLI maps `parse_permissive` to an explicit flag, so relaxing a
    // safety rule is something a user types rather than something a tool decides.
    let mut permissive = false;

    // Mainnet is hard-coded, and that is deliberate rather than unfinished. A
    // `--network` flag without the enforcement that goes with it is a footgun: it
    // will happily render testnet-shaped addresses from mainnet keys, or the reverse,
    // and the whole reason this crate exists is that wrong-shaped addresses fail
    // silently and look exactly like success. The flag arrives with the ticket that
    // makes network enforced rather than merely reported.
    let network = Network::Bitcoin;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--allow-duplicate-keys" => permissive = true,
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

    let descriptor = descriptor.ok_or_else(|| Failure::Usage("no descriptor given".to_string()))?;
    let start = NormalIndex::new(start).ok_or_else(|| {
        Failure::Usage("--start must be below 2147483648, the first hardened index".to_string())
    })?;

    let wallet = if permissive {
        ValidatedDescriptor::parse_permissive(&descriptor, network)?
    } else {
        ValidatedDescriptor::parse(&descriptor, network)?
    };

    let mut records: Vec<AddressRecord> = wallet.external().addresses(start, count).collect();
    if let Some(change) = wallet.internal() {
        records.extend(change.addresses(start, count));
    }

    Ok(Output {
        stdout: render(&wallet, &records),
        advisories: render_advisories(wallet.advisories()),
    })
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
        let out = run(args(&["list", &descriptor, "--count", "2"]))
            .ok()
            .unwrap()
            .stdout;

        assert!(out.contains("bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz"));
        assert_eq!(out.matches("receive").count(), 2);
        assert_eq!(out.matches("change").count(), 2);
    }

    #[test]
    fn start_offsets_the_range() {
        let descriptor = format!("wpkh({}/0/*)", XPUB);
        let out = run(args(&["list", &descriptor, "--start", "2", "--count", "1"]))
            .ok()
            .unwrap()
            .stdout;

        assert!(out.contains("0/2"));
        assert!(!out.contains("0/0"));
    }

    #[test]
    fn a_single_path_descriptor_lists_only_receive() {
        let descriptor = format!("wpkh({}/0/*)", XPUB);
        let out = run(args(&["list", &descriptor, "--count", "3"]))
            .ok()
            .unwrap()
            .stdout;

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

    /// `pkh` stood here while `wpkh` was the only supported form; ticket 03 admitted
    /// it, so the example had to become a form the allowlist still excludes. A
    /// timelock branch is a durable choice — arbitrary miniscript is deferred with a
    /// known expiry rather than about to be allowed.
    #[test]
    fn an_unsupported_form_reports_the_descriptor_error() {
        let descriptor = format!("wsh(and_v(v:pk({}/0/*),older(144)))", XPUB);
        match run(args(&["list", &descriptor])) {
            Err(Failure::Descriptor(DescriptorError::UnsupportedForm { form })) => {
                // The variant is the assertion; the shape it carries is the
                // requirement. Wording around them is free to change.
                assert_eq!(form, "wsh(miniscript)");
            }
            other => panic!("expected UnsupportedForm, got {:?}", other.err()),
        }
    }

    /// `echo` prints the descriptor in full, which is the point: `list` elides it and
    /// this is the string the user has to back up.
    #[test]
    fn echo_prints_the_whole_canonical_descriptor() {
        let descriptor = format!("wpkh([aabbccdd/84h/0h/0h]{}/<0;1>/*)", XPUB);
        let out = run(args(&["echo", &descriptor])).ok().unwrap().stdout;

        // Whole, not elided — the elision marker must not appear.
        assert!(!out.contains("..."), "got: {}", out);
        assert!(out.contains(XPUB), "the full key must be present");
        assert!(out.trim_end().ends_with("#4ws9vksj"), "got: {}", out);
    }

    /// Apostrophe input is echoed back in h-form, and the rewrite is explained rather
    /// than left to look like a transcription error.
    #[test]
    fn echo_normalises_notation_and_says_so() {
        let descriptor = format!("wpkh([aabbccdd/84'/0'/0']{}/<0;1>/*)", XPUB);
        let out = run(args(&["echo", &descriptor])).ok().unwrap();

        assert!(out.stdout.contains("84h/0h/0h"));
        assert!(!out.stdout.contains('\''));
        assert!(out.advisories.contains("note:"));
        assert!(
            out.advisories.contains("rewritten"),
            "got: {}",
            out.advisories
        );
    }

    /// The relaxation is something a user types, never something the tool decides.
    /// Without the flag the duplicate is refused; with it, the same finding arrives as
    /// a note and the addresses are shown.
    #[test]
    fn allow_duplicate_keys_turns_the_refusal_into_a_note() {
        let descriptor = format!("wsh(multi(2,{}/0/*,{}/0/*))", XPUB, XPUB);

        match run(args(&["list", &descriptor, "--count", "1"])) {
            Err(Failure::Descriptor(DescriptorError::DuplicateKey { .. })) => {}
            other => panic!(
                "expected DuplicateKey without the flag, got {:?}",
                other.err()
            ),
        }

        let out = run(args(&[
            "list",
            &descriptor,
            "--count",
            "1",
            "--allow-duplicate-keys",
        ]))
        .ok()
        .unwrap();

        assert!(out.stdout.contains("bc1q"), "addresses are shown");
        assert!(
            out.advisories.contains("appears more than once"),
            "got: {}",
            out.advisories
        );
    }

    /// The echoed descriptor comes first and on its own line, so it can be redirected
    /// to a file without the address table following it.
    #[test]
    fn assemble_echoes_the_descriptor_before_the_table() {
        let out = run(args(&[
            "assemble",
            "--key",
            &format!("[aabbccdd]{}", XPUB),
            "--script",
            "wpkh",
            "--count",
            "1",
        ]))
        .ok()
        .unwrap()
        .stdout;

        let first = out.lines().next().unwrap();
        assert!(
            first.starts_with("wpkh([aabbccdd/84h/0h/0h]"),
            "got: {}",
            first
        );
        assert!(first.ends_with("#4ws9vksj"), "got: {}", first);
        assert!(out.contains("bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz"));
    }

    /// Ticket 02's refusal, surfaced where a user actually meets it — and phrased as
    /// the reason rather than as "unsupported".
    #[test]
    fn assembling_taproot_multisig_is_refused_with_the_reason() {
        match run(args(&[
            "assemble",
            "--key",
            XPUB,
            "--script",
            "tr",
            "--threshold",
            "2",
        ])) {
            Err(Failure::Usage(message)) => {
                assert!(message.contains("internal key"), "got: {}", message)
            }
            other => panic!("expected a usage refusal, got {:?}", other.err()),
        }
    }

    /// Never guess a script type. Four of them derive four incompatible sets of
    /// addresses from one key, so the absence of this flag has to be a refusal.
    #[test]
    fn assemble_requires_an_explicit_script_type() {
        match run(args(&["assemble", "--key", XPUB])) {
            Err(Failure::Usage(message)) => {
                assert!(message.contains("--script is required"), "got: {}", message)
            }
            other => panic!("expected a usage refusal, got {:?}", other.err()),
        }
    }

    /// Advisories are commentary, not data. They must not land on stdout, or piping
    /// `descaddr list` into another tool would feed it prose.
    #[test]
    fn advisories_stay_out_of_stdout() {
        let descriptor = format!("wpkh({}/<0;1>/*)", XPUB);
        let out = run(args(&["list", &descriptor, "--count", "1"]))
            .ok()
            .unwrap();

        assert!(!out.advisories.is_empty(), "this input has findings");
        assert!(!out.stdout.contains("note:"));
        assert!(out.stdout.contains("bc1q"));
    }

    /// The ticket's headline, and the one decision no test can otherwise reach: at a
    /// terminal, missing flags are a question rather than an error.
    #[test]
    fn a_terminal_with_no_flags_is_prompted_not_refused() {
        assert_eq!(route(false, false, true).ok(), Some(Route::Prompt));
    }

    /// The same absence through a pipe is a script that forgot an argument. It must
    /// fail, because prompting at it hangs a build until something times out.
    #[test]
    fn a_pipe_with_no_flags_is_refused_not_prompted() {
        match route(false, false, false) {
            Err(Failure::Usage(message)) => {
                assert!(message.contains("not a terminal"), "got: {}", message)
            }
            other => panic!("expected a usage refusal, got {:?}", other),
        }
    }

    /// `--interactive` is what makes the flow drivable by an answer file — and it has
    /// to work through a pipe, or the previous rule would make it untestable.
    #[test]
    fn interactive_prompts_whatever_stdin_is() {
        assert_eq!(route(false, true, false).ok(), Some(Route::Prompt));
        assert_eq!(route(false, true, true).ok(), Some(Route::Prompt));
    }

    /// Flags win a terminal. Someone who typed `--key` asked a complete question and
    /// should not then be asked it again.
    #[test]
    fn flags_are_taken_at_a_terminal_without_prompting() {
        assert_eq!(route(true, false, true).ok(), Some(Route::Flags));
        assert_eq!(route(true, false, false).ok(), Some(Route::Flags));
    }

    /// Both at once is a question about which wins, and this tool does not guess.
    #[test]
    fn flags_and_interactive_together_are_a_usage_error() {
        match route(true, true, true) {
            Err(Failure::Usage(message)) => {
                assert!(message.contains("--interactive"), "got: {}", message)
            }
            other => panic!("expected a usage refusal, got {:?}", other),
        }
    }

    /// The nine allowlisted forms must all reach the renderer, not just the one the
    /// tracer bullet was built around.
    #[test]
    fn a_multisig_descriptor_lists_through_the_cli() {
        let x2 = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        let descriptor = format!("wsh(sortedmulti(2,{}/<0;1>/*,{}/<0;1>/*))", XPUB, x2);
        let out = run(args(&["list", &descriptor, "--count", "1"]))
            .ok()
            .unwrap()
            .stdout;

        assert!(out.contains("bc1qpsnmhwhv2cvnyp25efl8xvpyyenc8qr7zt0fj47dklj0txpc4e0q7vlzgy"));
        assert!(out.contains("wsh(sortedmulti)"));
    }
}
