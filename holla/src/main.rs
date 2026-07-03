use anyhow::Result;
use common::dbgprintln;
use crypto::*;

fn main() -> Result<()> {
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
