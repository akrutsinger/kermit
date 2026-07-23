//! Session workers and the printer thread that shows their output above the prompt.

use rustyline::ExternalPrinter;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

/// Sent from the REPL to a session worker.
pub enum Req {
    /// List a remote directory.
    List(String),
    /// Stop the worker and close the connection.
    Shutdown,
}

/// Anything a worker sends back. Command output and status both flow through here to the printer
/// thread.
pub enum Event {
    Notice(String),
    #[allow(dead_code)]
    Error(String),
}

/// A worker event tagged with the session id that produced it.
pub type Note = (u32, Event);

/// A worker's handle for sending events, tagged with its session id.
pub struct Notifier {
    pub id: u32,
    pub tx: Sender<Note>,
}

impl Notifier {
    pub fn notice(&self, msg: impl Into<String>) {
        let _ = self.tx.send((self.id, Event::Notice(msg.into())));
    }

    #[allow(dead_code)]
    pub fn error(&self, msg: impl Into<String>) {
        let _ = self.tx.send((self.id, Event::Error(msg.into())));
    }
}

/// Runs the one thread that owns the printer. Every worker sends here, so their output never
/// interleaves. Only the main thread's own `println!` can race it.
pub fn spawn_printer(mut printer: impl ExternalPrinter + Send + 'static, notes: Receiver<Note>) {
    const DIM: &str = "\x1b[2m";
    const BOLD: &str = "\x1b[1m";
    const RESET: &str = "\x1b[0m";
    thread::spawn(move || {
        while let Ok((id, ev)) = notes.recv() {
            let line = match ev {
                Event::Notice(msg) => format!("{DIM}[{id}] {msg}{RESET}"),
                Event::Error(msg) => format!("{BOLD}[{id}] error: {msg}{RESET}"),
            };
            let _ = printer.print(format!("{line}\n"));
        }
    });
}

/// One connection: a worker thread and the channel to send it requests. The REPL never touches the
/// socket itself, so a stalled connection can't block it.
pub struct Session {
    pub id: u32,
    /// Shown in the prompt and `sessions` list, e.g. `"user@host"`.
    pub label: String,
    pub tx: Sender<Req>,
    pub handle: JoinHandle<()>,
    /// Per-session command history; switching sessions swaps the recall buffer.
    pub history: Vec<String>,
}

/// Starts the worker thread for one session. The connection lives entirely on this thread; results
/// and status go back through `notifier`.
pub fn spawn_session(id: u32, host: String, notifier: Notifier) -> Session {
    let (req_tx, req_rx) = mpsc::channel::<Req>();
    let label = host.clone();

    let handle = thread::spawn(move || {
        // TODO: open the real connection here. On failure, notifier.error(..) and return.
        notifier.notice(format!("connected to {host}"));
        while let Ok(req) = req_rx.recv() {
            match req {
                Req::List(path) => notifier.notice(format!("{path}/example.txt")),
                Req::Shutdown => break,
            }
        }
        notifier.notice("disconnected");
    });
    Session {
        id,
        label,
        tx: req_tx,
        handle,
        history: Vec::new(),
    }
}
