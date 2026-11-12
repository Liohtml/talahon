//! `talahon` host binary. See the library docs (`talon` crate) for the
//! architecture; the command line, logging and dispatch live in
//! [`talon::entry`].

use std::process::ExitCode;

fn main() -> ExitCode {
    talon::entry::main(talon::entry::InvokedAs::Current)
}
