use listen::crypto::{
    APP_NONCE_LEN, AeadOnly, Protocol, SignAead, SignStream, SivShortNonce, StreamOnly, StreamRaw,
    StreamSiv, aead_seal_with_nonce, derive_enc_key, prepend_nonce, stream_iv_len,
};

use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};

type Aead = chacha20poly1305::ChaCha20Poly1305;
type Stream = chacha20::ChaCha20;
type Siv = aes_gcm_siv::Aes256GcmSiv;
// type Aead = aes_gcm::Aes256Gcm;
// type Stream = ctr::Ctr64BE<aes::Aes256>;  // (add `ctr`, `aes` deps)

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn counter_nonce(len: usize, ctr: u64) -> Vec<u8> {
    let mut n = vec![0u8; len];
    n[len - 8..].copy_from_slice(&ctr.to_be_bytes());
    n
}

fn main() {
    let signing = SigningKey::generate(&mut OsRng);
    let mut base_key = [0u8; 32];
    OsRng.fill_bytes(&mut base_key);

    let protocols: Vec<Box<dyn Protocol>> = vec![
        Box::new(StreamRaw::<Stream>::new(&base_key)),
        Box::new(StreamOnly::<Stream>::new(&base_key)),
        Box::new(StreamSiv::<Stream, 4>::new(&base_key, "StreamSiv4")),
        Box::new(StreamSiv::<Stream, 6>::new(&base_key, "StreamSiv6")),
        Box::new(StreamSiv::<Stream, 8>::new(&base_key, "StreamSiv8")),
        Box::new(StreamSiv::<Stream, 12>::new(&base_key, "StreamSiv12")),
        Box::new(StreamSiv::<Stream, 16>::new(&base_key, "StreamSiv16")),
        Box::new(SivShortNonce::<Siv>::new(&base_key)),
        Box::new(AeadOnly::<Aead>::new(&base_key)),
        Box::new(SignStream::<Stream>::new(&base_key, signing.clone())),
        Box::new(SignAead::<Aead>::new(&base_key, signing.clone())),
    ];

    let msg: &[u8] = b"123456";
    let framed = prepend_nonce(msg);
    println!(
        "message: {}-byte app nonce + {:?} ({} bytes) = {}-byte payload\n",
        APP_NONCE_LEN,
        std::str::from_utf8(msg).unwrap(),
        msg.len(),
        framed.len()
    );

    println!(
        "{:<11} {:>5} {:>9}  guarantees",
        "protocol", "wire", "overhead"
    );
    println!("{}", "-".repeat(78));
    for p in &protocols {
        let wire = p.seal(&framed);
        assert_eq!(p.overhead(), wire.len() - framed.len());
        assert_eq!(p.open(&wire).unwrap(), framed);
        println!(
            "{:<11} {:>5} {:>9}  {}",
            p.name(),
            wire.len(),
            format!("+{}", p.overhead()),
            p.guarantees()
        );
    }

    let iv_w = stream_iv_len::<Stream>();
    println!("\nStreamSiv byte-budget (stream IV width = {iv_w} bytes):");
    println!("  {:>2}  {:<8}  keystream-reuse birthday", "N", "forgery");
    for n in [4usize, 6, 8, 12, 16] {
        let birthday = 4 * n.min(iv_w);
        let note = if n > iv_w { "  (IV capped)" } else { "" };
        println!(
            "  {:>2}  {:<8}  2^{} messages{}",
            n,
            format!("2^-{}", 8 * n),
            birthday,
            note
        );
    }

    println!("\ntamper test (flip 1 wire byte):");
    for p in &protocols {
        let mut wire = p.seal(&framed);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        match p.open(&wire) {
            Err(e) => println!("  \x1b[32m✓\x1b[0m {:<11} rejected: {e}", p.name()),
            Ok(m) if m == framed => println!(
                "  \x1b[31m✗\x1b[0m {:<11} ACCEPTED (corruption missed)",
                p.name()
            ),
            Ok(m) => println!(
                "  \x1b[31m✗\x1b[0m {:<11} ACCEPTED, message silently altered -> {:?}",
                p.name(),
                String::from_utf8_lossy(&m)
            ),
        }
    }

    println!("\nnonce-reuse demo (same nonce, two different messages):");
    let enc_key = derive_enc_key(&base_key);
    let nonce = counter_nonce(12, 0);
    let m1 = b"transfer 0100 usd";
    let m2 = b"transfer 9999 usd";
    let pt_xor = xor(m1, m2);

    let (c1, _) = aead_seal_with_nonce::<Aead>(&enc_key, &nonce, m1);
    let (c2, _) = aead_seal_with_nonce::<Aead>(&enc_key, &nonce, m2);
    let leaks = xor(&c1, &c2) == pt_xor;
    println!(
        "  {} ChaCha20-Poly1305  ct1^ct2 == pt1^pt2 ? {leaks:<5} {}",
        if leaks {
            "\x1b[31m✗\x1b[0m"
        } else {
            "\x1b[32m✓\x1b[0m"
        },
        if leaks {
            "<- keystream reuse leaks the plaintext XOR"
        } else {
            ""
        }
    );

    let (s1, _) = aead_seal_with_nonce::<Siv>(&enc_key, &nonce, m1);
    let (s2, _) = aead_seal_with_nonce::<Siv>(&enc_key, &nonce, m2);
    let leaks_siv = xor(&s1, &s2) == pt_xor;
    println!(
        "  {} AES-256-GCM-SIV    ct1^ct2 == pt1^pt2 ? {leaks_siv:<5} {}",
        if !leaks_siv {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        },
        if !leaks_siv {
            "<- synthetic IV depends on plaintext; no XOR leak"
        } else {
            ""
        }
    );

    println!("\nequality-leak demo (AES-256-GCM-SIV, identical message sent twice):");
    let m = b"status: idle";
    let fixed = counter_nonce(12, 0);
    let (a, _) = aead_seal_with_nonce::<Siv>(&enc_key, &fixed, m);
    let (b, _) = aead_seal_with_nonce::<Siv>(&enc_key, &fixed, m);
    let fixed_eq = a == b;
    println!(
        "  {} fixed nonce   ct1 == ct2 ? {fixed_eq:<5} <- repeats are linkable on the wire",
        if fixed_eq {
            "\x1b[31m✗\x1b[0m"
        } else {
            "\x1b[32m✓\x1b[0m"
        }
    );

    let mut r1 = vec![0u8; 12];
    let mut r2 = vec![0u8; 12];
    OsRng.fill_bytes(&mut r1);
    OsRng.fill_bytes(&mut r2);
    let (c, _) = aead_seal_with_nonce::<Siv>(&enc_key, &r1, m);
    let (d, _) = aead_seal_with_nonce::<Siv>(&enc_key, &r2, m);
    let rand_eq = c == d;
    println!(
        "  {} random nonce  ct1 == ct2 ? {rand_eq:<5} <- repeats hidden (costs nonce bytes)",
        if rand_eq {
            "\x1b[31m✗\x1b[0m"
        } else {
            "\x1b[32m✓\x1b[0m"
        }
    );

    let siv = StreamSiv::<Stream, 12>::new(&base_key, "StreamSiv12");
    let raw = StreamRaw::<Stream>::new(&base_key);

    println!("\nStreamSiv keystream-reuse check (two different messages):");
    let (w1, w2) = (siv.seal(m1), siv.seal(m2));
    let body = siv.overhead();
    let siv_leaks = xor(&w1[body..], &w2[body..]) == pt_xor;
    println!(
        "  {} StreamSiv12  ct1^ct2 == pt1^pt2 ? {siv_leaks:<5} <- IV = HMAC(msg) diverges per message",
        if !siv_leaks {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        }
    );
    let raw_leaks = xor(&raw.seal(m1), &raw.seal(m2)) == pt_xor;
    println!(
        "  {} StreamRaw    ct1^ct2 == pt1^pt2 ? {raw_leaks:<5} <- fixed IV: keystream reuse leaks",
        if raw_leaks {
            "\x1b[31m✗\x1b[0m"
        } else {
            "\x1b[32m✓\x1b[0m"
        }
    );

    println!("\nStreamSiv equality-leak check (identical message sent twice):");
    let eq_bare = siv.seal(m) == siv.seal(m);
    println!(
        "  {} no app nonce  wire1 == wire2 ? {eq_bare:<5} <- deterministic; repeats linkable",
        if eq_bare {
            "\x1b[31m✗\x1b[0m"
        } else {
            "\x1b[32m✓\x1b[0m"
        }
    );
    let eq_nonced = siv.seal(&prepend_nonce(m)) == siv.seal(&prepend_nonce(m));
    println!(
        "  {} + app nonce   wire1 == wire2 ? {eq_nonced:<5} <- fresh nonce per send hides repeats",
        if !eq_nonced {
            "\x1b[32m✓\x1b[0m"
        } else {
            "\x1b[31m✗\x1b[0m"
        }
    );
}
