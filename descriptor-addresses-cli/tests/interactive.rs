//! Seam 3 — the CLI process boundary, driven by piped stdin.
//!
//! These spawn the real binary. That is the point: the interactive flow's contract is
//! that it reads lines from stdin and writes the wallet to stdout, and no in-process
//! test can prove the wiring between `main` and the terminal. Everything else about
//! prompting is unit-tested against an in-memory reader in `interactive.rs`.
//!
//! Prompts go to **stderr**, so every assertion on stdout here is also an assertion
//! that the transcript stayed out of the data.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const DESCADDR: &str = env!("CARGO_BIN_EXE_descaddr");

const X1: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
const X2: &str = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const X3: &str = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";

/// Run `descaddr` with the given arguments and the given lines on stdin.
fn descaddr(args: &[&str], stdin: &[&str]) -> Output {
    let mut child = Command::new(DESCADDR)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("descaddr binary is built by the test harness");

    // A failed write is not a failed test. Several of these drive `descaddr` down a
    // path where it refuses before reading a byte — a usage error, or an abort — and it
    // then exits while the answers are still in flight, closing the read end of the
    // pipe under us. `expect` here would turn that into a broken-pipe panic that fires
    // or does not depending on how the scheduler interleaved two processes. If the
    // child really did need input it never got, it aborts and the assertions below say
    // so, with a better message than this line could.
    let script = stdin.join("\n") + "\n";
    let _ = child
        .stdin
        .take()
        .expect("piped")
        .write_all(script.as_bytes());

    child.wait_with_output().expect("descaddr terminates")
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("utf-8")
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).expect("utf-8")
}

/// The ticket's headline: a full multisig assembly, driven entirely through a pipe.
///
/// It asserts against the **flag path's** output rather than a hard-coded string. A
/// literal here would pass while the two paths quietly diverged; comparing them is the
/// executable form of "the interactive flow calls the same assembly functions with the
/// same structs".
#[test]
fn a_multisig_wallet_can_be_assembled_entirely_through_a_pipe() {
    let interactive = descaddr(
        &["assemble", "--interactive", "--count", "1"],
        &[
            "2",                          // multisig
            &format!("[d34db33f]{}", X1), // key 1
            &format!("[a1b2c3d4]{}", X2), // key 2
            &format!("[7e5f0091]{}", X3), // key 3
            "",                           // done adding keys
            "1",                          // wsh
            "2",                          // threshold
            "1",                          // sortedmulti
            "ok",                         // the review table is correct
            "y",                          // and so is the descriptor
        ],
    );

    let flags = descaddr(
        &[
            "assemble",
            "--key",
            &format!("[d34db33f]{}", X1),
            "--key",
            &format!("[a1b2c3d4]{}", X2),
            "--key",
            &format!("[7e5f0091]{}", X3),
            "--script",
            "wsh",
            "--threshold",
            "2",
            "--count",
            "1",
        ],
        &[],
    );

    assert!(
        interactive.status.success(),
        "stderr: {}",
        stderr(&interactive)
    );
    assert_eq!(
        stdout(&interactive),
        stdout(&flags),
        "the two input mechanisms must produce the same wallet"
    );
    assert!(stdout(&interactive).starts_with("wsh(sortedmulti(2,"));
}

/// The review table is where a mistyped key is caught while it is still cheap, so
/// editing one has to actually change the wallet that gets built.
#[test]
fn a_key_edited_in_the_review_table_changes_the_descriptor() {
    let corrected = descaddr(
        &["assemble", "--interactive", "--count", "1"],
        &[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "2",
            "1",
            "edit 2",                     // key 2 was wrong
            &format!("[7e5f0091]{}", X3), // this is the one that was meant
            "ok",
            "y",
        ],
    );

    assert!(corrected.status.success(), "stderr: {}", stderr(&corrected));
    let out = stdout(&corrected);
    assert!(out.contains("7e5f0091"), "the replacement is present");
    assert!(!out.contains("a1b2c3d4"), "the mistake is gone: {}", out);
}

/// Single-sig is flat: no stages, no review table, one key and a script type.
#[test]
fn single_sig_is_a_flat_sequence() {
    let out = descaddr(
        &["assemble", "--interactive", "--count", "1"],
        &["1", "3", &format!("[aabbccdd]{}", X1), "y"],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).starts_with("wpkh([aabbccdd/84h/0h/0h]"));
    assert!(
        !stderr(&out).contains("Step 1 of"),
        "one key and a script type is nothing to stage: {}",
        stderr(&out)
    );
}

/// A script with no `--key` gets an error, not a prompt it can never answer. This is
/// the whole reason interactive mode is opt-in rather than inferred from an empty
/// argument list.
#[test]
fn a_pipe_without_the_flags_errors_rather_than_prompting() {
    let out = descaddr(&["assemble"], &[]);

    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2), "a usage error");
    assert!(
        stderr(&out).contains("not a terminal"),
        "the reason must name the cause: {}",
        stderr(&out)
    );
    assert!(stdout(&out).is_empty());
}

/// Stdin running out mid-flow is an abort, not a hang and not a half-built wallet.
#[test]
fn input_ending_early_aborts_instead_of_hanging() {
    let out = descaddr(&["assemble", "--interactive"], &["2", X1]);

    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("input ended"),
        "got: {}",
        stderr(&out)
    );
    assert!(stdout(&out).is_empty(), "nothing half-built reaches stdout");
}

/// Declining at the confirmation writes nothing and says so. Exit is non-zero because
/// a caller that asked for a wallet did not get one.
#[test]
fn declining_the_confirmation_discards_the_wallet() {
    let out = descaddr(&["assemble", "--interactive"], &["1", "3", X1, "n"]);

    assert!(!out.status.success());
    assert!(stdout(&out).is_empty());
    assert!(stderr(&out).contains("discarded"), "got: {}", stderr(&out));
}

/// Prompting and flags are two answers to the same question, so asking both at once is
/// a question about which one wins — and this tool does not guess.
#[test]
fn interactive_and_the_assembly_flags_cannot_be_combined() {
    let out = descaddr(
        &["assemble", "--interactive", "--key", X1],
        &["1", "3", X1, "y"],
    );

    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("--interactive"),
        "got: {}",
        stderr(&out)
    );
}

/// A rejected key is re-asked rather than fatal. The flow exists for users who have
/// keys and not descriptors, and a typo throwing away four correct answers is the
/// behaviour it replaces.
#[test]
fn a_bad_key_is_re_asked_not_fatal() {
    let out = descaddr(
        &["assemble", "--interactive", "--count", "1"],
        &[
            "1",
            "3",
            "xpub-obviously-not-a-key",
            &format!("[aabbccdd]{}", X1),
            "y",
        ],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).starts_with("wpkh([aabbccdd/84h/0h/0h]"));
}

/// No escape sequences reach a pipe. crossterm is for a terminal that can redraw; a
/// file or another program gets plain text.
#[test]
fn a_pipe_receives_no_cursor_escapes() {
    let out = descaddr(
        &["assemble", "--interactive", "--count", "1"],
        &[
            "2",
            &format!("[d34db33f]{}", X1),
            &format!("[a1b2c3d4]{}", X2),
            "",
            "1",
            "2",
            "1",
            "del 2",
            "add",
            &format!("[7e5f0091]{}", X3),
            "ok",
            "y",
        ],
    );

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        !stderr(&out).contains('\x1b'),
        "an escape sequence reached a pipe"
    );
    assert!(stdout(&out).contains("7e5f0091"));
}
