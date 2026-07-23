mod cmd;
mod repl;
mod session;

use anyhow::Result;
use clap::{Parser, Subcommand};
use repl::Repl;
use rustyline::{DefaultEditor, error::ReadlineError};
use session::{Note, spawn_printer};
use std::sync::mpsc;

#[derive(Parser)]
#[command(no_binary_name = true)] // a REPL line has no argv[0] so every token is a real arg
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ping the server
    Ping,
    /// Show the source IP, or set it when given an address
    SrcIp { ip: Option<String> },
    /// Open a connection and make it the active session
    Connect { host: String },
    /// List open sessions
    Sessions,
    /// Switch the active session
    Session { id: u32 },
    /// List a remote directory on the active session
    Ls {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Close the active session
    Disconnect,
    /// Random stuff for testing
    TestCrypto,
    /// Exit
    Exit,
    /// Exit
    Quit,
}

enum Flow {
    Continue,
    Exit,
}

/// Run a parsed command. Returns `Flow::Exit` to quit; errors bubble up to the loop, which prints
/// them and keeps going.
fn eval(repl: &mut Repl, command: Command) -> Result<Flow> {
    match command {
        Command::Ping => println!("pong"),
        Command::SrcIp { ip } => cmd::src_ip(repl, ip),
        Command::Connect { host } => cmd::connect(repl, host),
        Command::Sessions => cmd::list(repl),
        Command::Session { id } => cmd::switch(repl, id)?,
        Command::Ls { path } => cmd::ls(repl, path)?,
        Command::Disconnect => cmd::disconnect(repl)?,
        Command::TestCrypto => cmd::test_crypto()?,
        Command::Exit | Command::Quit => return Ok(Flow::Exit),
    }
    Ok(Flow::Continue)
}

fn main() -> rustyline::Result<()> {
    let mut rl = DefaultEditor::new()?;
    // Create the printer from the editor before moving it to its own thread.
    let printer = rl.create_external_printer()?;
    let (notes, note_rx) = mpsc::channel::<Note>();
    spawn_printer(printer, note_rx);

    let mut repl = Repl::new(rl, notes);

    loop {
        let prompt = repl.prompt();
        match repl.rl.readline(&prompt) {
            Ok(line) => {
                let tokens = match shlex::split(&line) {
                    Some(t) if !t.is_empty() => t,
                    _ => continue,
                };
                repl.record(&line);

                match Cli::try_parse_from(tokens) {
                    // try_parse_from, not parse_from: parse_from calls exit() on bad input and on
                    // --help, which would kill the REPL. This hands back the error to print
                    // instead.
                    Ok(cli) => match eval(&mut repl, cli.command) {
                        Ok(Flow::Exit) => break,
                        Ok(Flow::Continue) => {}
                        // {e:#} prints anyhow's full context chain on one line.
                        Err(e) => eprintln!("error: {e:#}"),
                    },
                    Err(e) => {
                        let _ = e.print();
                    }
                }
            }
            Err(ReadlineError::Interrupted) => continue, // Ctrl-C abandons the current line
            Err(ReadlineError::Eof) => break,            // Ctrl-D exits
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
