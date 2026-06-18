use anyhow::Result;
use common::dbgprintln;
use crypto::*;

fn main() -> Result<()> {
    // let mut base_key = [0u8; 32];
    let base_key = *b"holla-test-key-0000000000000000";
    type Stream = chacha20::ChaCha20;
    let p = StreamSiv::<Stream, 4>::new(&base_key)?;

    let msg: &[u8] = b"123456";
    let framed = prepend_nonce(msg)?;
    dbgprintln!(
        "message: {}-byte app nonce + {:?} ({} bytes) = {}-byte payload\n",
        APP_NONCE_LEN,
        String::from_utf8_lossy(msg),
        msg.len(),
        framed.len()
    );

    dbgprintln!("{:>5} data", "wire");
    dbgprintln!("{}", "-".repeat(78));
    let wire = p.seal(&framed)?;
    dbgprintln!("{:>5} {:?}", wire.len(), wire);

    Ok(())
}
