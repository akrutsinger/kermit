mod filter;
mod os;
mod source;

use rand_core::{OsRng, RngCore};

//use rustix::path::Arg;
use common::dbgprintln;
use crypto::*;
use source::PacketSource;

fn packet_handler(pkt: Vec<u8>) {
    dbgprintln!("matched: {} bytes", pkt.len());
}

fn main() {
    let base_key = *b"listen-test-key-0000000000000000";
    let mut nonce = [0u8; APP_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    match check_and_record_nonce(&nonce, &base_key) {
        Ok(()) => (),
        Err(e) => {
            dbgprintln!("nonce check failed: {e}");
            return;
        }
    };

    let iface = std::env::args().nth(1);

    let mut src = match os::Source::open(iface.as_deref()) {
        Ok(src) => src,
        Err(e) => {
            dbgprintln!("failed to open packet source: {e}");
            return;
        }
    };

    match src.attach_filter(&os::FILTER) {
        Ok(()) => (),
        Err(e) => {
            dbgprintln!("failed to attach filter: {e}");
            return;
        }
    };

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
}
