//! `talon`: the pre-rename name of the `talahon` host binary, kept as an
//! alias for one major version. Same code; it prints a deprecation notice
//! (see [`talon::entry`]).

use std::process::ExitCode;

fn main() -> ExitCode {
    talon::entry::main(talon::entry::InvokedAs::Legacy)
}
