//! Command implementations.

use crate::repl::Repl;
use crate::session::{Notifier, Req, spawn_session};
use anyhow::{Context, Result, bail};
use common::dbgprintln;
use crypto::*;

/// Show or set the source IP.
pub fn src_ip(repl: &mut Repl, ip: Option<String>) {
    match ip {
        Some(ip) => {
            println!("source ip set to {ip}");
            repl.src_ip = Some(ip);
        }
        None => match &repl.src_ip {
            Some(ip) => println!("current source ip: {ip}"),
            None => println!("current source ip: <unset>"),
        },
    }
}

/// Open a new session and make it active.
pub fn connect(repl: &mut Repl, host: String) {
    let id = repl.next_id;
    repl.next_id += 1;
    let notifier = Notifier {
        id,
        tx: repl.notes.clone(),
    };
    repl.sessions.push(spawn_session(id, host, notifier));
    repl.active = Some(id);
    repl.reload_history(Some(id));
    println!("[*] session {id} opened");
}

/// List open sessions, marking the active one.
pub fn list(repl: &Repl) {
    if repl.sessions.is_empty() {
        println!("no sessions");
        return;
    }
    for s in &repl.sessions {
        let marker = if repl.active == Some(s.id) { '*' } else { ' ' };
        let status = if s.handle.is_finished() {
            " [dead]"
        } else {
            ""
        };
        println!("{marker} {} {}{status}", s.id, s.label);
    }
}

/// Switch the active session.
pub fn switch(repl: &mut Repl, id: u32) -> Result<()> {
    let s = repl
        .sessions
        .iter()
        .find(|s| s.id == id)
        .with_context(|| format!("no such session: {id}"))?;
    if s.handle.is_finished() {
        bail!("session {id} is dead");
    }
    repl.active = Some(id);
    repl.reload_history(Some(id));
    Ok(())
}

/// List a remote directory. The result comes back asynchronously through the printer.
pub fn ls(repl: &Repl, path: String) -> Result<()> {
    let s = repl.active().context("no active session")?;
    if s.tx.send(Req::List(path)).is_err() {
        bail!("session worker is gone");
    }
    Ok(())
}

/// Close the active session, join its worker, and fall back to another.
pub fn disconnect(repl: &mut Repl) -> Result<()> {
    let id = repl.active.context("no active session")?;
    // active id is set, so position() is Some.
    let pos = repl.sessions.iter().position(|s| s.id == id).unwrap();
    let s = repl.sessions.remove(pos);
    let _ = s.tx.send(Req::Shutdown);
    let _ = s.handle.join();
    repl.active = repl.sessions.first().map(|s| s.id);
    let target = repl.active;
    repl.reload_history(target);
    println!("[*] session {id} closed");
    Ok(())
}

/// Tests crypto primitive and shows some byte overhead counts
pub fn test_crypto() -> Result<()> {
    // let mut base_key = [0u8; 32];
    let base_key = *b"holla-test-key-0000000000000000";
    type Stream = chacha20::ChaCha20;
    let p = StreamAead::<Stream, 8, 4>::new(&base_key)?;

    let msg: &[u8] = b"123456";
    dbgprintln!(
        "message: {:?} ({} bytes)\n",
        String::from_utf8_lossy(msg),
        msg.len()
    );

    dbgprintln!("{:>5} data", "wire");
    dbgprintln!("{}", "-".repeat(78));
    let wire = p.seal(msg)?;
    dbgprintln!("{:>5} {:?}", wire.len(), wire);

    Ok(())
}
