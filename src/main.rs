mod filter;
mod os;
mod source;

use anyhow::Result;
//use rustix::path::Arg;
use source::PacketSource;

use listen::crypto::*;
//use rand_core::{OsRng, RngCore};

/// Like `println!`, but dead-code-eliminated in release builds (`cfg!(debug_assertions)`
/// is a constant `false` there, so the optimizer drops the whole branch).
macro_rules! dprintln {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}

async fn handle(pkt: Vec<u8>) {
    dprintln!("matched: {} bytes", pkt.len());
}

fn crypto_play() {
    // let mut base_key = [0u8; 32];
    // OsRng.fill_bytes(&mut base_key);
    let base_key = *b"listen-test-key-0000000000000000";
    type Stream = chacha20::ChaCha20;
    let p = Box::new(StreamSiv::<Stream, 4>::new(&base_key, "StreamSiv4"));

    let msg: &[u8] = b"123456";
    let framed = prepend_nonce(msg);
    dprintln!(
        "message: {}-byte app nonce + {:?} ({} bytes) = {}-byte payload\n",
        APP_NONCE_LEN,
        std::str::from_utf8(msg).unwrap(),
        msg.len(),
        framed.len()
    );

    dprintln!("{:>5} data", "wire");
    dprintln!("{}", "-".repeat(78));
    let wire = p.seal(&framed);
    dprintln!("{:>5} {:?}", wire.len(), wire);

    check_and_record_nonce(&framed[..APP_NONCE_LEN], &base_key)
        .unwrap_or_else(|_e| dprintln!("nonce check: {_e}"));
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    crypto_play();

    // Optional CLI arg: interface name (Linux/BSD) or local IPv4 (Windows).
    // Open + filter synchronously so setup errors (e.g. a bad interface) surface here.
    let iface = std::env::args().nth(1);
    let mut src = os::Source::open(iface.as_deref())?;
    src.attach_filter(&os::FILTER)?;

    // The capture syscall is blocking, so it runs on its own OS thread and never stalls the
    // runtime. Each packet is copied out of the source's internal buffer (valid only until the next
    // recv) and spawned straight onto the runtime. Traffic is sporadic, so unbounded spawning is a
    // non-issue and we skip the channel.
    let rt = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        loop {
            match src.recv() {
                Ok(pkt) => {
                    rt.spawn(handle(pkt.to_vec()));
                }
                Err(_e) => {
                    dprintln!("capture stopped: {_e}");
                    break;
                }
            }
        }
    });

    // Park the main task so the runtime stays alive and keeps polling handlers.
    std::future::pending::<()>().await;
    Ok(())
}
