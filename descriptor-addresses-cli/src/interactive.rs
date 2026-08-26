//! Prompting for the values `--key`, `--script`, `--threshold` and `--as-given`
//! supply, for a wallet owner who has keys but not a descriptor.
//!
//! # The asymmetry is the design
//!
//! Single-sig is a **flat sequence**: a script type, a key, a confirmation. One key
//! plus a script type is nothing to review, and staging it would be ceremony.
//!
//! Multisig is **staged and ends in an editable review table**, because N keys plus a
//! threshold plus an ordering are easy to get wrong and expensive to get wrong — a
//! mistyped character in cosigner three is a wallet nobody can spend from, and it is
//! discovered when the coins are already in it. The table is the last cheap moment.
//!
//! # What this module is not
//!
//! It is not a second input model. Every path here ends at
//! [`ValidatedDescriptor::assemble_single_sig`] or
//! [`ValidatedDescriptor::assemble_multisig`], with the same [`SingleSig`] and
//! [`Multisig`] structs the flag path fills in — the library cannot tell which of them
//! it is talking to, and there is no rule reachable from one route and not the other.
//! Prompting is where a half-built spec is legitimate, which is why the `Option`
//! fields live here and not in the library.
//!
//! # Two negative constraints
//!
//! **Prompts are written to stderr, never stdout.** The descriptor is the answer;
//! the conversation that produced it is not. `descaddr assemble --interactive
//! < answers > wallet.txt` must put a wallet in that file and nothing else, for the
//! same reason advisories are already kept off stdout.
//!
//! **`crossterm` is used for cursor movement and clearing, and for nothing else.** No
//! raw mode, no alternate screen, no event polling — the review table needs to redraw
//! in place and `\r` cannot move up a line, which is the whole of the requirement. A
//! prompt library was considered and is not carrying its weight against
//! [`BufRead::read_line`]. Unless **both** streams are terminals — see [`can_redraw`]
//! — nothing is emitted at all: a pipe gets plain text, and the table simply reprints
//! below itself.

use std::io::{BufRead, IsTerminal, Write};

use crossterm::{cursor, execute, terminal};
use descriptor_addresses::{
    DescriptorKey, KeyOrdering, Multisig, MultisigScript, Network, SingleSig, SingleSigScript,
    ValidatedDescriptor,
};

use crate::Failure;

/// How wide a key is rendered in the review table.
///
/// An xpub is 111 characters and the column has to survive an 80-column terminal
/// alongside three others. The elision keeps both ends, which is what a human
/// actually compares against the device in their hand.
const KEY_COLUMN: usize = 28;

/// The commands the review table accepts, and the line that advertises them.
const REVIEW_PROMPT: &str = "   edit <n> | del <n> | add | threshold <n> | ok >";

/// A prompting session: somewhere to read answers from, somewhere to show questions.
///
/// Generic over both so the flow can be driven by an in-memory script in a unit test
/// without a process, a pipe or a terminal. The process-boundary tests drive the real
/// binary; these two type parameters are why they do not have to drive *everything*.
pub struct Session<R, W> {
    input: R,
    screen: W,
    /// Whether the screen can be redrawn in place. See [`can_redraw`]: it takes a
    /// terminal on both streams, not just the one being written to.
    redraw: bool,
    /// Lines written since the last [`Session::mark`], so a redraw knows how far up to
    /// go. Counted rather than measured because the alternative is asking the terminal
    /// where the cursor is, which needs the event machinery this module refuses.
    printed: usize,
    mark: usize,
}

impl Session<std::io::StdinLock<'static>, std::io::Stderr> {
    /// The real thing: answers from stdin, questions on stderr.
    pub fn on_stdio() -> Self {
        let screen = std::io::stderr();
        let redraw = can_redraw(screen.is_terminal(), std::io::stdin().is_terminal());
        Session {
            input: std::io::stdin().lock(),
            screen,
            redraw,
            printed: 0,
            mark: 0,
        }
    }
}

/// Whether the screen can be redrawn in place — and it takes **both** streams.
///
/// A writable terminal is not enough, because the line accounting assumes the terminal
/// echoed the user's Enter, and only a terminal *input* does that. The case that breaks
/// is the one this flow advertises: `descaddr assemble --interactive < answers.txt` run
/// at a terminal has a tty on stderr and a file on stdin, so every prompt costs zero
/// lines rather than one. `printed` would over-count, and the redraw would land above
/// the mark and erase the complaint the user was meant to read — drifting one line
/// further up each round.
///
/// A free function of two booleans because a test cannot be a terminal, and this is the
/// half of the redraw that can be wrong in a way nobody notices until they are staring
/// at a mangled screen.
fn can_redraw(screen_is_terminal: bool, input_is_terminal: bool) -> bool {
    screen_is_terminal && input_is_terminal
}

impl<R: BufRead, W: Write> Session<R, W> {
    /// A session over supplied streams, with in-place redrawing off.
    ///
    /// `#[cfg(test)]` because the only caller that supplies its own streams today is
    /// the unit suite below. The generic parameters are not for the tests' benefit —
    /// they are what lets the flow be exercised without a process — but the
    /// constructor that fixes them to an in-memory pair has no other use yet.
    #[cfg(test)]
    pub fn piped(input: R, screen: W) -> Self {
        Session {
            input,
            screen,
            redraw: false,
            printed: 0,
            mark: 0,
        }
    }

    /// Walk the user to an assembled, confirmed wallet.
    pub fn assemble(&mut self, network: Network) -> Result<ValidatedDescriptor, Failure> {
        let wallet = match self.ask_kind()? {
            Kind::Single => self.single_sig(network)?,
            Kind::Multi => self.multisig(network)?,
        };

        self.confirm(&wallet)?;
        Ok(wallet)
    }

    // ---------------------------------------------------------------- single-sig

    /// Flat: script type, key, done. Deliberately no stage headers and no review
    /// table — the confirmation *is* the review when there is one key on screen.
    fn single_sig(&mut self, network: Network) -> Result<ValidatedDescriptor, Failure> {
        let script_type = self.ask_single_sig_script()?;
        self.blank()?;

        loop {
            let key = self.ask_key("   key >")?;
            let spec = SingleSig {
                key,
                script_type,
                network,
                path: None,
            };

            // The library gets the last word even here, where nothing much can go
            // wrong. A flow that pre-judged which specs are buildable would be a
            // second rule set, and the one it disagreed with would be this one.
            match ValidatedDescriptor::assemble_single_sig(spec) {
                Ok(wallet) => return Ok(wallet),
                Err(e) => self.complain(&e.to_string())?,
            }
        }
    }

    // ------------------------------------------------------------------ multisig

    fn multisig(&mut self, network: Network) -> Result<ValidatedDescriptor, Failure> {
        self.blank()?;
        self.say("Step 1 of 3   keys")?;
        let mut keys = self.ask_keys()?;

        self.blank()?;
        self.say("Step 2 of 3   policy")?;
        let script_type = self.ask_multisig_script()?;
        let mut threshold = self.ask_threshold(keys.len())?;
        let ordering = self.ask_ordering()?;

        self.blank()?;
        self.say("Step 3 of 3   review")?;

        loop {
            self.mark();
            self.write(&review_table(
                &keys,
                threshold,
                ordering,
                script_type,
                network,
            ))?;

            let command = self.ask(REVIEW_PROMPT)?;
            match parse_review_command(&command) {
                Command::Accept => {
                    let spec = Multisig {
                        keys: keys.clone(),
                        threshold,
                        script_type,
                        ordering,
                        network,
                        path: None,
                    };
                    match ValidatedDescriptor::assemble_multisig(spec) {
                        Ok(wallet) => return Ok(wallet),
                        // Back to the table rather than out of the flow. Every refusal
                        // assembly can raise — a threshold above the key count, mixed
                        // origins — names something editable on the screen the user is
                        // looking at.
                        Err(e) => {
                            self.rewind()?;
                            self.complain(&e.to_string())?;
                        }
                    }
                }

                Command::Edit(n) => {
                    self.rewind()?;
                    match index(n, keys.len()) {
                        None => self.complain(&format!("there is no key {}", n))?,
                        Some(i) => {
                            let replacement = self.ask_key(&format!("   key {} >", n))?;
                            if let Some(clash) = duplicate_of(&replacement, &keys, Some(i)) {
                                self.complain(&format!(
                                    "that is already key {}; a quorum with a repeated key \
                                     is smaller than it looks",
                                    clash + 1
                                ))?;
                            } else {
                                keys[i] = replacement;
                            }
                        }
                    }
                }

                Command::Delete(n) => {
                    self.rewind()?;
                    match index(n, keys.len()) {
                        None => self.complain(&format!("there is no key {}", n))?,
                        // The same floor `ask_keys` enforces at entry, enforced again
                        // where it can be crossed on the way out. Deleting down to one
                        // key assembles `sortedmulti(1,…)`, which is a single-sig
                        // wallet wearing a costume — and the user picked the other
                        // branch for that.
                        Some(_) if keys.len() <= 2 => {
                            self.complain("a multisig needs at least two keys")?
                        }
                        Some(i) => {
                            keys.remove(i);
                            // Silently leaving the threshold above the key count would
                            // make the next `ok` fail for a reason the user did not
                            // cause. Lowering it and saying so is the honest repair.
                            if threshold as usize > keys.len() {
                                threshold = keys.len() as u32;
                                self.complain(&format!(
                                    "threshold lowered to {}, the number of keys left",
                                    threshold
                                ))?;
                            }
                        }
                    }
                }

                Command::Add => {
                    self.rewind()?;
                    let key = self.ask_key(&format!("   key {} >", keys.len() + 1))?;
                    match duplicate_of(&key, &keys, None) {
                        Some(clash) => self.complain(&format!(
                            "that is already key {}; a quorum with a repeated key is \
                             smaller than it looks",
                            clash + 1
                        ))?,
                        None => keys.push(key),
                    }
                }

                // `Option`, so `threshold -1` is diagnosed as a bad threshold rather
                // than as an unknown command. The verb was right; the number was not,
                // and telling the user their command does not exist sends them looking
                // for the wrong mistake.
                Command::Threshold(t) => {
                    self.rewind()?;
                    match t {
                        Some(t) if in_range(t, keys.len()) => threshold = t,
                        _ => self.complain(&threshold_range(keys.len()))?,
                    }
                }

                Command::Unknown(line) => {
                    self.rewind()?;
                    self.complain(&format!("`{}` is not one of the commands above", line))?;
                }
            }
        }
    }

    // ------------------------------------------------------------------ questions

    fn ask_kind(&mut self) -> Result<Kind, Failure> {
        loop {
            self.say("what are you building")?;
            self.say("   [1] single-sig   one key, one signature")?;
            self.say("   [2] multisig     several keys, some number of them required")?;

            match self.ask("   >")?.as_str() {
                "1" | "s" | "single" | "single-sig" => return Ok(Kind::Single),
                "2" | "m" | "multi" | "multisig" => return Ok(Kind::Multi),
                // No default, because the two answers are not comparable in cost. A
                // stray newline that picked single-sig would follow with a bare
                // `key >` — which reads exactly like the first cosigner of the
                // multisig the user meant, and produces a one-key wallet from it.
                "" => self.complain("answer 1 or 2; there is no default here")?,
                other => self.complain(&format!("`{}` is neither 1 nor 2", other))?,
            }
        }
    }

    /// The one question with no default, in either flow.
    ///
    /// Four script types derive four incompatible sets of addresses from the same key.
    /// Guessing one is the exact silent failure this crate exists to prevent, so an
    /// empty line here re-asks rather than picking the popular answer.
    fn ask_single_sig_script(&mut self) -> Result<SingleSigScript, Failure> {
        loop {
            self.blank()?;
            self.say("script type — required, and never guessed")?;
            self.say("   [1] pkh      legacy, addresses starting 1")?;
            self.say("   [2] sh-wpkh  nested segwit, addresses starting 3")?;
            self.say("   [3] wpkh     native segwit, addresses starting bc1q")?;
            self.say("   [4] tr       taproot, addresses starting bc1p")?;

            match self.ask("   >")?.as_str() {
                "1" | "pkh" => return Ok(SingleSigScript::Pkh),
                "2" | "sh-wpkh" => return Ok(SingleSigScript::ShWpkh),
                "3" | "wpkh" => return Ok(SingleSigScript::Wpkh),
                "4" | "tr" => return Ok(SingleSigScript::Tr),
                "" => self.complain(
                    "a script type is required: the four above derive four \
                     incompatible sets of addresses from the same key",
                )?,
                other => self.complain(&format!("`{}` is not one of the four above", other))?,
            }
        }
    }

    /// No taproot option, and the absence is the point: [`MultisigScript`] has no `Tr`
    /// variant, so this menu cannot offer one. The refusal is a sentence that cannot
    /// be written rather than a rule that has to be remembered here.
    fn ask_multisig_script(&mut self) -> Result<MultisigScript, Failure> {
        loop {
            self.say("   script type — required, and never guessed")?;
            self.say("   [1] wsh     native segwit, addresses starting bc1q")?;
            self.say("   [2] sh-wsh  nested segwit, addresses starting 3")?;

            match self.ask("   >")?.as_str() {
                "1" | "wsh" => return Ok(MultisigScript::Wsh),
                "2" | "sh-wsh" => return Ok(MultisigScript::ShWsh),
                "" => self.complain(
                    "a script type is required: the two above derive different \
                     addresses from the same keys",
                )?,
                other => self.complain(&format!("`{}` is neither 1 nor 2", other))?,
            }
        }
    }

    fn ask_threshold(&mut self, keys: usize) -> Result<u32, Failure> {
        loop {
            self.blank()?;
            let answer = self.ask(&format!(
                "   threshold — how many of the {} keys must sign >",
                keys
            ))?;

            match answer.parse::<u32>() {
                Ok(t) if in_range(t, keys) => return Ok(t),
                // No default. How many signatures a wallet needs is the decision the
                // wallet exists to encode, and a 1-of-3 offered as a convenience is a
                // 1-of-3 somebody ships.
                _ => self.complain(&threshold_range(keys))?,
            }
        }
    }

    fn ask_ordering(&mut self) -> Result<KeyOrdering, Failure> {
        loop {
            self.blank()?;
            self.say("   key order")?;
            self.say("   [1] sortedmulti  BIP-67 order — every cosigner derives the same")?;
            self.say("                    addresses whatever order they typed keys in")?;
            self.say("   [2] multi        the order entered above, which becomes part")?;
            self.say("                    of the wallet and must be reproduced exactly")?;

            match self.ask("   >")?.as_str() {
                // Sorted is the default because it is the safe one, matching
                // `--as-given` being the flag that has to be typed.
                "" | "1" | "sortedmulti" | "sorted" => return Ok(KeyOrdering::Sorted),
                "2" | "multi" | "as-given" => return Ok(KeyOrdering::AsGiven),
                other => self.complain(&format!("`{}` is neither 1 nor 2", other))?,
            }
        }
    }

    /// Keys, one per line, blank when done.
    ///
    /// Each is validated as it arrives rather than in a batch at the end, so a typo in
    /// the first of five is corrected before the other four are typed.
    fn ask_keys(&mut self) -> Result<Vec<DescriptorKey>, Failure> {
        self.say("   Paste one key per line, blank line when done.")?;
        self.say("   A key may state its origin as [fingerprint/path]; without one the")?;
        self.say("   BIP default for the script type is filled in.")?;

        let mut keys: Vec<DescriptorKey> = Vec::new();
        loop {
            let line = self.ask(&format!("   key {} >", keys.len() + 1))?;

            if line.is_empty() {
                // Two, not one. A 1-of-1 written as a quorum is a single-sig wallet
                // wearing a costume, and the user picked the other branch for it.
                if keys.len() < 2 {
                    self.complain("a multisig needs at least two keys")?;
                    continue;
                }
                return Ok(keys);
            }

            match DescriptorKey::parse(&line) {
                Err(e) => self.complain(&e.to_string())?,
                Ok(key) => match duplicate_of(&key, &keys, None) {
                    // Caught here rather than left to assembly, which would raise it
                    // after four more keys were typed. Same rule, earlier.
                    Some(clash) => self.complain(&format!(
                        "that is already key {}; a quorum with a repeated key is smaller \
                         than it looks — a 2-of-3 with a repeat is a 1-of-2",
                        clash + 1
                    ))?,
                    None => keys.push(key),
                },
            }
        }
    }

    fn ask_key(&mut self, prompt: &str) -> Result<DescriptorKey, Failure> {
        loop {
            let line = self.ask(prompt)?;
            match DescriptorKey::parse(&line) {
                Ok(key) => return Ok(key),
                // A rejected key re-asks. This flow exists for people who have keys and
                // not descriptors, and throwing away four correct answers over one
                // mistyped character is the behaviour it replaces.
                Err(e) => self.complain(&e.to_string())?,
            }
        }
    }

    /// Show the assembled descriptor and ask before it counts as made.
    ///
    /// The descriptor is echoed here **and** printed to stdout afterwards, which is not
    /// duplication: this copy is what the user is agreeing to, and it is on the same
    /// stream as the rest of the conversation. The stdout copy is the answer.
    fn confirm(&mut self, wallet: &ValidatedDescriptor) -> Result<(), Failure> {
        self.blank()?;
        self.say(wallet.canonical())?;
        self.blank()?;
        self.say("Back this up. It is the only thing that recovers this wallet.")?;

        // Defaulting to no. The affirmative has to be typed, because the cost of a
        // stray newline accepting a wrong wallet is not symmetric with the cost of
        // being asked twice.
        match self.ask("Correct? [y/N] >")?.to_ascii_lowercase().as_str() {
            "y" | "yes" => Ok(()),
            _ => Err(Failure::Aborted("discarded, nothing written.".to_string())),
        }
    }

    // ---------------------------------------------------------------- primitives

    /// Ask a question and read one line. End-of-input is an abort, never a retry:
    /// re-asking a stream that has ended is how a flow spins forever.
    fn ask(&mut self, prompt: &str) -> Result<String, Failure> {
        write!(self.screen, "{} ", prompt).map_err(screen_gone)?;
        self.screen.flush().map_err(screen_gone)?;

        let mut line = String::new();
        if self.input.read_line(&mut line).map_err(input_gone)? == 0 {
            return Err(Failure::Aborted(
                "input ended before the wallet was finished; nothing was written.".to_string(),
            ));
        }

        // The newline the user typed puts the cursor on the next line, so the prompt
        // costs exactly one line of screen whatever the answer was.
        self.printed += 1;
        Ok(line.trim().to_string())
    }

    fn say(&mut self, line: &str) -> Result<(), Failure> {
        writeln!(self.screen, "{}", line).map_err(screen_gone)?;
        self.printed += 1;
        Ok(())
    }

    fn blank(&mut self) -> Result<(), Failure> {
        self.say("")
    }

    /// A correction, marked so it is not mistaken for the next question.
    fn complain(&mut self, message: &str) -> Result<(), Failure> {
        let line = format!("   ! {}", message);
        self.say(&line)
    }

    /// Write a pre-rendered block, counting its lines.
    fn write(&mut self, block: &str) -> Result<(), Failure> {
        for line in block.lines() {
            self.say(line)?;
        }
        Ok(())
    }

    fn mark(&mut self) {
        self.mark = self.printed;
    }

    /// Return the cursor to the last mark and clear what was below it.
    ///
    /// On a pipe this only resets the counter: nothing is erased, the next table is
    /// printed below the old one, and the transcript reads as a log — which is what a
    /// file wanted anyway.
    fn rewind(&mut self) -> Result<(), Failure> {
        let lines = self.printed - self.mark;
        if self.redraw && lines > 0 {
            execute!(
                self.screen,
                cursor::MoveToPreviousLine(lines as u16),
                terminal::Clear(terminal::ClearType::FromCursorDown),
            )
            .map_err(screen_gone)?;
        }
        self.printed = self.mark;
        Ok(())
    }
}

/// Which flow the user is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Single,
    Multi,
}

/// A command typed at the review table.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Edit(usize),
    Delete(usize),
    Add,
    /// `None` when the argument was not a number this type can hold — `threshold -1`
    /// or `threshold 9999999999`. Carried rather than rejected so the handler can give
    /// the range, which is the answer the user needs, instead of "no such command".
    Threshold(Option<u32>),
    Accept,
    Unknown(String),
}

/// Whether a threshold makes sense for this many keys.
fn in_range(threshold: u32, keys: usize) -> bool {
    threshold >= 1 && threshold as usize <= keys
}

/// One sentence for one rule, shared by the prompt and the review table.
///
/// Two wordings for the same refusal would have the user wondering what the difference
/// was between the threshold they typed at step 2 and the one they typed at step 3.
fn threshold_range(keys: usize) -> String {
    format!("a threshold is a whole number from 1 to {}", keys)
}

/// Parse a review-table command.
///
/// A free function over `&str` rather than a method, so the grammar can be tested
/// without a session, a stream or a wallet.
fn parse_review_command(line: &str) -> Command {
    let mut words = line.split_whitespace();
    let (verb, argument) = (words.next(), words.next());

    match (verb, argument) {
        // Empty accepts. The table is on screen and was just read; the affirmative
        // default is safe here in a way it is not at the final confirmation, where the
        // descriptor rather than the review is what is being agreed to.
        (None, _) | (Some("ok"), None) => Command::Accept,
        (Some("add"), None) => Command::Add,
        (Some("edit"), Some(n)) => number(n).map_or_else(|| unknown(line), Command::Edit),
        (Some("del" | "delete"), Some(n)) => {
            number(n).map_or_else(|| unknown(line), Command::Delete)
        }
        (Some("threshold"), Some(n)) => Command::Threshold(n.parse::<u32>().ok()),
        _ => unknown(line),
    }
}

fn unknown(line: &str) -> Command {
    Command::Unknown(line.trim().to_string())
}

fn number(word: &str) -> Option<usize> {
    word.parse().ok()
}

/// Turn a 1-based row number into an index, or `None` if there is no such row.
fn index(n: usize, len: usize) -> Option<usize> {
    (n >= 1 && n <= len).then(|| n - 1)
}

/// Whether `candidate` repeats a key already in the list, ignoring `skip`.
///
/// Compared on the bare key, exactly as the library does, so the same xpub written
/// with two different origins is still one key.
fn duplicate_of(
    candidate: &DescriptorKey,
    keys: &[DescriptorKey],
    skip: Option<usize>,
) -> Option<usize> {
    keys.iter()
        .enumerate()
        .find(|(i, key)| Some(*i) != skip && key.key() == candidate.key())
        .map(|(i, _)| i)
}

/// The review table: the last cheap moment to catch a mistyped key.
///
/// Pure, so the shape of the thing a user stares at before committing their savings is
/// testable without a terminal. Fingerprint, origin and elided key are the three
/// columns worth reviewing — the elision keeps both ends of the key, which is what
/// gets compared against the device that produced it.
fn review_table(
    keys: &[DescriptorKey],
    threshold: u32,
    ordering: KeyOrdering,
    script_type: MultisigScript,
    network: Network,
) -> String {
    // Filling the default in for a key that states no path is only honest while *no*
    // key states one — that is the case where assembly really does supply it. The
    // moment one key carries its own, the others are not defaulted, they are refused:
    // a quorum split across two accounts is `AssemblyError::MixedOrigins`. Printing the
    // default into those rows would make the table agree with itself and disagree with
    // the wallet, which is the one failure a review table must not have.
    let default_path = script_type.default_origin_path(network);
    let any_stated = keys.iter().any(|key| key.origin_path().is_some());

    let mut out = String::from("\n    #  FINGERPRINT  ORIGIN            KEY\n");
    for (i, key) in keys.iter().enumerate() {
        let origin = match (key.fingerprint(), key.origin_path(), any_stated) {
            // No fingerprint, no origin — BIP-380 requires one, and assembly drops the
            // path along with it, emitting the bare key. Printing the default into this
            // row would name a path the descriptor will not carry.
            (None, _, _) => "(none)",
            (Some(_), Some(stated), _) => stated,
            (Some(_), None, true) => "(none)",
            (Some(_), None, false) => &default_path,
        };

        out.push_str(&format!(
            "   {:>2}  {:<12} {:<17} {}\n",
            i + 1,
            key.fingerprint().unwrap_or("(none)"),
            origin,
            crate::elide(key.key(), KEY_COLUMN),
        ));
    }

    out.push_str(&format!(
        "\n   {}-of-{}, {} order, {}, {}\n",
        threshold,
        keys.len(),
        match ordering {
            KeyOrdering::Sorted => "sorted",
            KeyOrdering::AsGiven => "as-entered",
        },
        match script_type {
            MultisigScript::Wsh => "wsh",
            MultisigScript::ShWsh => "sh-wsh",
        },
        network,
    ));

    out
}

/// The screen went away mid-flow. Fatal, and not the user's fault.
fn screen_gone(e: std::io::Error) -> Failure {
    Failure::Aborted(format!("the terminal went away: {}", e))
}

/// The answers could not be read. A separate sentence from [`screen_gone`] because the
/// most likely cause is the user's own file — a key pasted out of a Latin-1 document
/// fails here as "stream did not contain valid UTF-8", and blaming their terminal for
/// that sends them to look at the wrong thing.
fn input_gone(e: std::io::Error) -> Failure {
    Failure::Aborted(format!("could not read the answers: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const X1: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const X2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
    const X3: &str = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";

    fn key(s: &str) -> DescriptorKey {
        DescriptorKey::parse(s).expect("a test key parses")
    }

    /// Drive the flow with a script of answers, returning the wallet and the
    /// transcript the user would have seen.
    fn drive(answers: &[&str]) -> (Result<ValidatedDescriptor, Failure>, String) {
        let script = answers.join("\n") + "\n";
        let mut session = Session::piped(Cursor::new(script.into_bytes()), Vec::new());
        let wallet = session.assemble(Network::Bitcoin);
        let transcript = String::from_utf8(session.screen).expect("utf-8");
        (wallet, transcript)
    }

    #[test]
    fn a_flat_single_sig_run_produces_a_wallet() {
        let (wallet, _) = drive(&["1", "3", &format!("[aabbccdd]{}", X1), "y"]);
        let canonical = wallet.expect("assembles").canonical().to_string();

        assert!(canonical.starts_with("wpkh([aabbccdd/84h/0h/0h]"));
        assert!(
            canonical.contains("/<0;1>/*"),
            "both keychains: {}",
            canonical
        );
    }

    /// The founding rule, at the prompt that could most easily break it: an empty line
    /// must not pick the popular script type.
    #[test]
    fn an_empty_script_type_is_re_asked_never_defaulted() {
        let (wallet, transcript) = drive(&["1", "", "3", X1, "y"]);

        assert!(wallet.is_ok());
        assert!(
            transcript.contains("a script type is required"),
            "got: {}",
            transcript
        );
    }

    /// Ordering is the one multisig answer with a default, and it defaults to the safe
    /// one — matching `--as-given` being the flag that must be typed.
    #[test]
    fn an_empty_key_order_defaults_to_sorted() {
        let (wallet, _) = drive(&[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "2",
            "", // key order
            "ok",
            "y",
        ]);

        assert!(wallet
            .expect("assembles")
            .canonical()
            .starts_with("wsh(sortedmulti(2,"));
    }

    /// A threshold above the key count is refused at the prompt, not several answers
    /// later by assembly.
    #[test]
    fn a_threshold_above_the_key_count_is_re_asked() {
        let (wallet, transcript) = drive(&[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "9", // there are only two keys
            "2",
            "1",
            "ok",
            "y",
        ]);

        assert!(wallet.is_ok());
        assert!(
            transcript.contains("a threshold is a whole number from 1 to 2"),
            "got: {}",
            transcript
        );
    }

    /// The library's duplicate rule, applied at the moment the second copy is typed
    /// rather than after the rest of the quorum has been entered.
    #[test]
    fn a_repeated_key_is_caught_as_it_is_typed() {
        let (wallet, transcript) = drive(&[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X1), // same key, different origin
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "2",
            "1",
            "ok",
            "y",
        ]);

        assert!(wallet.is_ok());
        assert!(transcript.contains("already key 1"), "got: {}", transcript);
    }

    /// One key is not a quorum, and the user picked the quorum branch.
    #[test]
    fn a_multisig_needs_at_least_two_keys() {
        let (wallet, transcript) = drive(&[
            "2",
            &format!("[d34db33f]{}", X1),
            "", // tries to finish with one
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "2",
            "1",
            "ok",
            "y",
        ]);

        assert!(wallet.is_ok());
        assert!(
            transcript.contains("at least two keys"),
            "got: {}",
            transcript
        );
    }

    /// Deleting below the threshold repairs the threshold and says so, rather than
    /// leaving a spec that fails at `ok` for a reason the user did not cause.
    #[test]
    fn deleting_a_key_lowers_a_threshold_that_no_longer_fits() {
        let (wallet, transcript) = drive(&[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X2),
            &format!("[7e5f0091]{}", X3),
            "",
            "1",
            "3", // 3-of-3
            "1",
            "del 3",
            "ok",
            "y",
        ]);

        let canonical = wallet.expect("assembles").canonical().to_string();
        assert!(
            canonical.starts_with("wsh(sortedmulti(2,"),
            "got: {}",
            canonical
        );
        assert!(
            transcript.contains("threshold lowered to 2"),
            "got: {}",
            transcript
        );
    }

    /// The abort has to be an abort. A flow that re-asks a stream which has ended is
    /// how a pipe becomes an infinite loop.
    #[test]
    fn input_running_out_aborts_rather_than_looping() {
        let (wallet, _) = drive(&["2", X1]);

        match wallet {
            Err(Failure::Aborted(message)) => assert!(message.contains("input ended")),
            other => panic!("expected an abort, got {:?}", other.err()),
        }
    }

    /// Declining is a refusal, not a quiet success.
    #[test]
    fn declining_the_confirmation_is_an_abort() {
        let (wallet, _) = drive(&["1", "3", X1, ""]);

        match wallet {
            Err(Failure::Aborted(message)) => assert!(message.contains("discarded")),
            other => panic!("expected an abort, got {:?}", other.err()),
        }
    }

    /// The screen is not the answer. Nothing the user is asked may reach stdout, and
    /// the transcript carries the whole conversation instead.
    #[test]
    fn the_transcript_carries_the_questions() {
        let (_, transcript) = drive(&["1", "3", X1, "y"]);

        assert!(transcript.contains("what are you building"));
        assert!(transcript.contains("Back this up"));
    }

    #[test]
    fn review_commands_parse() {
        assert_eq!(parse_review_command("ok"), Command::Accept);
        assert_eq!(parse_review_command(""), Command::Accept);
        assert_eq!(parse_review_command("   "), Command::Accept);
        assert_eq!(parse_review_command("add"), Command::Add);
        assert_eq!(parse_review_command("edit 2"), Command::Edit(2));
        assert_eq!(parse_review_command("del 3"), Command::Delete(3));
        assert_eq!(parse_review_command("delete 3"), Command::Delete(3));
        assert_eq!(
            parse_review_command("threshold 2"),
            Command::Threshold(Some(2))
        );
        // A right verb with a wrong number stays a threshold, so the user is told the
        // range rather than that their command does not exist.
        assert_eq!(
            parse_review_command("threshold -1"),
            Command::Threshold(None)
        );
        assert_eq!(
            parse_review_command("threshold 9999999999"),
            Command::Threshold(None)
        );
        assert_eq!(
            parse_review_command("edit"),
            Command::Unknown("edit".to_string())
        );
        assert_eq!(
            parse_review_command("edit two"),
            Command::Unknown("edit two".to_string())
        );
        assert_eq!(
            parse_review_command("rm 1"),
            Command::Unknown("rm 1".to_string())
        );
    }

    /// Seam 2: the table is a pure function, so the thing a user stares at before
    /// committing their savings is pinned without a terminal.
    #[test]
    fn the_review_table_shows_fingerprint_origin_and_an_elided_key() {
        let table = review_table(
            &[
                key(&format!("[d34db33f]{}", X1)),
                key(&format!("[a1b2c3d4]{}", X2)),
                key(X3),
            ],
            2,
            KeyOrdering::Sorted,
            MultisigScript::Wsh,
            Network::Bitcoin,
        );

        // No key states a path, so the BIP-48 default is what assembly will write and
        // what every row therefore shows.
        assert!(
            table.contains("d34db33f     48h/0h/0h/2h"),
            "got: {}",
            table
        );
        assert!(
            table.contains("a1b2c3d4     48h/0h/0h/2h"),
            "got: {}",
            table
        );
        // No fingerprint means no origin can be written at all, per BIP-380.
        assert!(table.contains("(none)"), "got: {}", table);

        assert!(
            table.contains("xpub661MyMwAqRbc...W1EGMcet8"),
            "got: {}",
            table
        );
        assert!(!table.contains(X1), "keys are elided: {}", table);
        assert!(
            table.contains("2-of-3, sorted order, wsh, bitcoin"),
            "got: {}",
            table
        );
    }

    /// The failure a review table must not have: agreeing with itself and disagreeing
    /// with the wallet.
    ///
    /// Once one key states its own origin, the keys that do not are **refused** rather
    /// than defaulted — `AssemblyError::MixedOrigins` — so a table that filled the
    /// default into those rows would show a wallet that cannot be built, on the screen
    /// whose entire job is spotting that.
    #[test]
    fn a_stated_origin_stops_the_others_being_shown_as_defaulted() {
        let mixed = review_table(
            &[
                key(&format!("[d34db33f/48h/0h/9h/2h]{}", X1)),
                key(&format!("[a1b2c3d4]{}", X2)),
            ],
            2,
            KeyOrdering::Sorted,
            MultisigScript::Wsh,
            Network::Bitcoin,
        );

        assert!(
            mixed.contains("d34db33f     48h/0h/9h/2h"),
            "got: {}",
            mixed
        );
        assert!(
            mixed.contains("a1b2c3d4     (none)"),
            "the odd row must be visibly odd: {}",
            mixed
        );
        assert!(
            !mixed.contains("48h/0h/0h/2h"),
            "no row may claim a default that assembly will refuse to apply: {}",
            mixed
        );
    }

    /// A key with no fingerprint gets no origin **at all** — BIP-380 requires one, and
    /// assembly emits the bare key. The default path shown here would be a path the
    /// descriptor does not carry.
    #[test]
    fn a_key_without_a_fingerprint_is_not_shown_a_default_path() {
        let table = review_table(
            &[key(X1), key(&format!("[a1b2c3d4]{}", X2))],
            2,
            KeyOrdering::Sorted,
            MultisigScript::Wsh,
            Network::Bitcoin,
        );

        let bare = table
            .lines()
            .find(|line| line.contains("(none)"))
            .expect("the fingerprint-less row");
        assert!(
            !bare.contains("48h/"),
            "no origin reaches the descriptor for this key: {}",
            bare
        );
    }

    /// `del` must not walk out through the floor `ask_keys` enforces on the way in.
    /// Deleting to one key assembles `sortedmulti(1,…)`, which is a single-sig wallet
    /// wearing a costume.
    #[test]
    fn deleting_down_to_one_key_is_refused() {
        let (wallet, transcript) = drive(&[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "2",
            "1",
            "del 2", // would leave a one-key quorum
            "ok",
            "y",
        ]);

        let canonical = wallet.expect("assembles").canonical().to_string();
        assert!(
            canonical.starts_with("wsh(sortedmulti(2,"),
            "both keys survive: {}",
            canonical
        );
        assert!(
            transcript.contains("at least two keys"),
            "got: {}",
            transcript
        );
    }

    /// A wrong number after the right verb is a threshold problem, and gets the range
    /// rather than "no such command".
    #[test]
    fn a_threshold_out_of_range_at_the_table_gets_the_range() {
        let (wallet, transcript) = drive(&[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "2",
            "1",
            "threshold -1",
            "ok",
            "y",
        ]);

        assert!(wallet.is_ok());
        assert!(
            transcript.contains("a threshold is a whole number from 1 to 2"),
            "got: {}",
            transcript
        );
        assert!(
            !transcript.contains("`threshold -1` is not one of the commands"),
            "the verb was right: {}",
            transcript
        );
    }

    /// The kind question has no default, because its two answers are not comparable in
    /// cost: a stray newline picking single-sig is followed by a bare `key >` that
    /// reads exactly like the first cosigner of the multisig the user meant.
    #[test]
    fn the_kind_question_has_no_default() {
        let (wallet, transcript) = drive(&["", "2", &format!("[d34db33f]{}", X1), "", "", "", ""]);

        assert!(wallet.is_err(), "the empty answer must not have built one");
        assert!(
            transcript.contains("there is no default here"),
            "got: {}",
            transcript
        );
    }

    /// Redrawing needs a terminal on **both** streams, not just the one being written
    /// to. The line accounting assumes the terminal echoed the user's Enter, and only a
    /// terminal input does that — so `--interactive < answers.txt` at a terminal has a
    /// tty on stderr, a file on stdin, and would over-count every prompt.
    #[test]
    fn redrawing_needs_a_terminal_on_both_streams() {
        assert!(can_redraw(true, true));
        assert!(
            !can_redraw(true, false),
            "answers from a file are not echoed"
        );
        assert!(!can_redraw(false, true), "a pipe must not receive escapes");
        assert!(!can_redraw(false, false));
    }

    /// The line accounting behind the in-place redraw.
    ///
    /// Nothing else can check it: the escapes themselves are only emitted to a real
    /// terminal, and crossterm reaches for the Windows console API rather than ANSI
    /// when there is not one — so a test that asserted on the bytes would be asserting
    /// on the platform. The count is the part that can be wrong, and an off-by-one here
    /// eats a line of the user's scrollback on every edit.
    #[test]
    fn a_redraw_accounts_for_every_line_it_wrote() {
        let mut session = Session::piped(Cursor::new(b"ok\n".to_vec()), Vec::new());
        let keys = [
            key(&format!("[d34db33f]{}", X1)),
            key(&format!("[a1b2c3d4]{}", X2)),
            key(&format!("[7e5f0091]{}", X3)),
        ];

        session.mark();
        session
            .write(&review_table(
                &keys,
                2,
                KeyOrdering::Sorted,
                MultisigScript::Wsh,
                Network::Bitcoin,
            ))
            .expect("writes");
        session.ask(REVIEW_PROMPT).expect("reads");

        // Seven lines of table — a blank, a header, three rows, a blank, a summary —
        // and the prompt, whose line is closed by the user's Enter rather than by us.
        assert_eq!(session.printed - session.mark, 8);
        let written = String::from_utf8(session.screen.clone()).expect("utf-8");
        assert_eq!(
            written.matches('\n').count(),
            7,
            "the eighth line is the user's, not ours: {:?}",
            written
        );

        session.rewind().expect("rewinds");
        assert_eq!(session.printed, session.mark, "the counter goes back");
        assert!(
            !String::from_utf8(session.screen)
                .expect("utf-8")
                .contains('\x1b'),
            "a screen that cannot redraw is not written to"
        );
    }
}
