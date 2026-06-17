mod filter;
mod os;
mod source;

use anyhow::Result;
//use rustix::path::Arg;
use source::PacketSource;

use listen::crypto::*;
//use rand_core::{OsRng, RngCore};

macro_rules! dbgprintln {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        println!($($arg)*);
    }};
}

fn packet_handler(pkt: Vec<u8>) {
    dbgprintln!("matched: {} bytes", pkt.len());
}

fn crypto_play() -> anyhow::Result<()> {
    // let mut base_key = [0u8; 32];
    // OsRng.fill_bytes(&mut base_key);
    let base_key = *b"listen-test-key-0000000000000000";
    type Stream = chacha20::ChaCha20;
    let p = Box::new(StreamSiv::<Stream, 4>::new(&base_key)?);

    let msg: &[u8] = b"123456";
    let framed = prepend_nonce(msg);
    dbgprintln!(
        "message: {}-byte app nonce + {:?} ({} bytes) = {}-byte payload\n",
        APP_NONCE_LEN,
        std::str::from_utf8(msg).unwrap(),
        msg.len(),
        framed.len()
    );

    dbgprintln!("{:>5} data", "wire");
    dbgprintln!("{}", "-".repeat(78));
    let wire = p.seal(&framed)?;
    dbgprintln!("{:>5} {:?}", wire.len(), wire);

    check_and_record_nonce(&framed[..APP_NONCE_LEN], &base_key)
        .unwrap_or_else(|_e| dbgprintln!("nonce check: {_e}"));
    Ok(())
}

fn main() -> Result<()> {
    crypto_play()?;

    let iface = std::env::args().nth(1);
    let mut src = os::Source::open(iface.as_deref())?;
    src.attach_filter(&os::FILTER)?;

    loop {
        match src.recv() {
            Ok(pkt) => {
                let pkt = pkt.to_vec();
                std::thread::spawn(move || packet_handler(pkt));
            }
            Err(_e) => {
                dbgprintln!("capture stopped: {_e}");
                break;
            }
        }
    }
    Ok(())
}
