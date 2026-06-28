// keen-emu — Enshrouded Keen online-backend emulator (RE'd).
//
// Transport: raw TCP, frame = [op:u32 LE][len:u32 LE][rsvd:u16 LE][body:len].
// Request  : libsodium crypto_box_seal to the server X25519 key (48B overhead).
// Response : libsodium crypto_sign (Ed25519, 64B sig) verified vs pinned key.
// Injection: game launched with --keenonline-server-data-file <our json>, whose
//            publicEncryptionKey/publicSignatureKey are OUR pubkeys → we hold the
//            private keys → we decrypt the real LoginRequest plaintext here.
//
// This is the bring-up stub: it completes the crypto handshake and DUMPS the
// decrypted LoginRequest so we can map the body format, then replies with a
// signed stub (the game will log the parse error, which guides the next iter).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use base64::Engine;
use dryoc::dryocbox::{DryocBox, KeyPair};
use dryoc::sign::SigningKeyPair;
use dryoc::types::Bytes;

type SignKp = SigningKeyPair<dryoc::sign::PublicKey, dryoc::sign::SecretKey>;

const ADDR: &str = "127.0.0.1:27503";
const DATA_FILE: &str = "keenonline-emu.json";

// ---- KNF bitstream writer (MSB-first, big-endian — matches FUN_14097d060/1b0) ----
struct BitWriter {
    bytes: Vec<u8>,
    nbits: usize,
}
impl BitWriter {
    fn new() -> Self { BitWriter { bytes: Vec::new(), nbits: 0 } }
    fn bit(&mut self, b: u8) {
        if self.nbits % 8 == 0 { self.bytes.push(0); }
        if b & 1 != 0 {
            let byte = self.nbits / 8;
            let off = 7 - (self.nbits % 8); // MSB-first
            self.bytes[byte] |= 1 << off;
        }
        self.nbits += 1;
    }
    // write `n` bits of `v`, most-significant bit first
    fn bits(&mut self, v: u64, n: u32) {
        for i in (0..n).rev() {
            self.bit(((v >> i) & 1) as u8);
        }
    }
    fn u8(&mut self, v: u8) { self.bits(v as u64, 8); }
    fn u16(&mut self, v: u16) { self.bits(v as u64, 16); }
    fn u32(&mut self, v: u32) { self.bits(v as u64, 32); }
    // 64-bit = hi32 then lo32, each MSB-first (per case 9/10 in the reader)
    fn u64(&mut self, v: u64) { self.bits(v >> 32, 32); self.bits(v & 0xffff_ffff, 32); }
    fn present(&mut self, p: bool) { self.bit(if p { 1 } else { 0 }); } // kind-0 optional flag
    fn varray_u8(&mut self, data: &[u8]) {        // kind-2: u16 length + bytes
        self.u16(data.len() as u16);
        for &b in data { self.u8(b); }
    }
    fn finish(self) -> Vec<u8> { self.bytes }
}

// ---- KNF bit reader (MSB-first), enough to pull sessionKey from the request ----
struct BitReader<'a> { d: &'a [u8], pos: usize }
impl<'a> BitReader<'a> {
    fn new(d: &'a [u8], bitpos: usize) -> Self { BitReader { d, pos: bitpos } }
    fn bits(&mut self, n: u32) -> u64 {
        let mut v = 0u64;
        for _ in 0..n {
            let byte = self.d[self.pos >> 3];
            let bit = (byte >> (7 - (self.pos & 7))) & 1;
            v = (v << 1) | bit as u64;
            self.pos += 1;
        }
        v
    }
    fn varray(&mut self) -> Vec<u8> {           // kind2: u16 len + bytes
        let n = self.bits(16) as usize;
        (0..n).map(|_| self.bits(8) as u8).collect()
    }
}

// LoginRequest plaintext = [MessageHeader(4B): seq:u16, cmd:u16][sessionKey varray]
// [sessionKeyId u8]...  Returns (32-byte session key, sessionKeyId).
fn parse_session(plain: &[u8]) -> Option<(Vec<u8>, u32)> {
    if plain.len() < 7 { return None; }
    let mut r = BitReader::new(plain, 32); // skip 4-byte MessageHeader
    let sk = r.varray();
    if sk.len() != 32 { return None; }
    let skid = r.bits(8) as u32;
    Some((sk, skid))
}

// LoginResponse per the RE'd schema (descriptor 0x141edf750).
// matchmakingServer points back at us so the game talks matchmaking to the emu.
fn build_login_response(enc_pub: &[u8], sig_pub: &[u8], sign_kp: &SignKp, session_key: &[u8]) -> Vec<u8> {
    // da50 session-key path: FUN_1405d5490(out, in[:len-24], len-24,
    // nonce=in[len-24:], key=object+0x5f0=sessionKey). So token =
    // crypto_secretbox(sessionKey, nonce, plaintext) || nonce(24).  We pick the
    // nonce (0x5a marker so the exfil detour fires) and append it.
    // ServerEntry.token: u8[max 59].  Real format (RE'd from the token decoder
    // FUN_1410065d0 -> de50): [mode:u8=1][seq:u8=0][secretbox(sessionKey,
    // ServerTokenData{accountId:u64, expiry:u64}) || nonce(24)].
    //   = 2 + (16 MAC+ct) ... = 2 + 32 + 24 = 58 bytes (<= 59).
    let token = {
        let mut td = BitWriter::new();
        td.u64(1); // accountId
        td.u64(0x0000_00ff_ffff_ffff); // expiry (far future)
        let plain = td.finish(); // 16 bytes
        let nonce = [0u8; 24];
        let mut sb = secretbox_with_nonce(&plain, session_key, &nonce); // 16+16=32
        sb.extend_from_slice(&nonce); // +24 = 56
        let mut t = vec![1u8, 0u8]; // [mode=1][seq=0]
        t.extend_from_slice(&sb); // 2 + 56 = 58
        t
    };
    let mut w = BitWriter::new();
    w.u32(1);                       // sessionId
    w.u64(0x0000_00ff_ffff_ffff);   // sessionExpiry (far future)
    // authenticationServerLoginData (kind-0 optional → present)
    w.present(true);
    w.u64(1);                       // accountId
    w.u8(0xff);                     // permissionMask
    w.u32(1);                       // acceptedTerms
    // authenticationCode (kind-1 → no present flag)
    w.u64(0);                       // timestamp
    let ac_sig = sign_kp.sign_with_defaults(&[1u8]).map(|s| s.to_vec()).unwrap_or_default();
    w.varray_u8(&ac_sig[..64.min(ac_sig.len())]); // signature (64B ed25519)
    // matchmakingServer (kind-0 optional → present): point back at the emu.
    w.present(true);
    w.u32(0x0100_007f);             // ip4Address 127.0.0.1
    w.u16(27503);                   // port (emu)
    w.varray_u8(enc_pub);           // publicEncryptionKey (our X25519, 32B)
    w.varray_u8(sig_pub);           // publicSignatureKey  (our Ed25519, 32B)
    w.varray_u8(&token);            // token (session-key secretbox, <=59B)
    // baseSharingServer (kind-0 optional → present): also point at the emu so the
    // client accepts the address ("Received invalid base sharing server address").
    w.present(true);
    w.u32(0x0100_007f);
    w.u16(27503);
    w.varray_u8(enc_pub);
    w.varray_u8(sig_pub);
    w.varray_u8(&token);
    // top-level optionals
    w.present(true); w.u8(0);       // autonomyTimeInMins
    w.present(true); w.u16(0);      // publicPort
    w.finish()
}

// Build the keenonline message PAYLOAD (everything after the frame's
// [op:u32][len:u32][mode:u8][seq:u8] header).  RE'd from the runtime exfil:
// the frame is [op][len][mode][seq][payload]; the 2 bytes after `len` are
// [mode][seq], NOT reserved (the request's "00 00" = mode 0 = sealed box).
//   mode = 1  -> session-key encrypted; the receiver de50-decrypts the payload
//   payload   = crypto_secretbox(sessionKey, nonce, plaintext) [16B MAC + ct]
//               || nonce(24)        (FUN_1405d5490 reads the nonce as the LAST 24)
// plaintext (after decrypt) = [MessageHeader: seq:u16=0, commandId:u16][KNF body]
// (matches the request plaintext, which is [4-byte MessageHeader][KNF]).
// No inner Ed25519 sign on the session-key path.
fn build_payload(
    enc_pub: &[u8],
    sig_pub: &[u8],
    sign_kp: &SignKp,
    session_key: &[u8],
    command_id: u16,
) -> Vec<u8> {
    let knf = build_login_response(enc_pub, sig_pub, sign_kp, session_key);

    // inner plaintext: MessageHeader(seq=0, commandId) + KNF body
    let mut mh = BitWriter::new();
    mh.u16(0); // sequenceNumber
    mh.u16(command_id); // commandId
    let mut plaintext = mh.finish(); // exactly 4 bytes
    plaintext.extend_from_slice(&knf);

    // payload = secretbox(sessionKey, nonce, plaintext) || nonce(24)
    let nonce = [0u8; 24];
    let mut enc = secretbox_with_nonce(&plaintext, session_key, &nonce);
    enc.extend_from_slice(&nonce);
    enc
}

// Build a complete keenonline message as the client's recv loop (FUN_141002130 ->
// FUN_141001280) parses it directly off the TCP stream — there is NO [op][len]
// frame.  Layout (RE'd; the request decodes the same way):
//   [mode:u8 = 1]                                  (1 = session-key encrypted)
//   PlainHeader (MSB-first / big-endian, desc 0x141edf390):
//     messageSize:u32 = byte length of the payload (encrypted region)
//     sessionId:u32   = nonzero -> da50 session-key path (callback 0x141000650
//                       returns object+0x5f0 = the request's sessionKey)
//     authenticationCode present-bit = 0 (absent)
//   -> 65 bits, byte-padded to 9 bytes
//   payload = secretbox(sessionKey, plaintext) || nonce(24)   (messageSize bytes)
fn build_message(
    enc_pub: &[u8],
    sig_pub: &[u8],
    sign_kp: &SignKp,
    session_key: &[u8],
    session_id: u32,
    command_id: u16,
) -> Vec<u8> {
    let payload = build_payload(enc_pub, sig_pub, sign_kp, session_key, command_id);
    let sid = if session_id != 0 { session_id } else { 1 };
    let mut ph = BitWriter::new();
    ph.u32(payload.len() as u32); // messageSize (big-endian)
    ph.u32(sid); // sessionId (big-endian, nonzero)
    ph.present(false); // authenticationCode absent
    let ph_bytes = ph.finish(); // 9 bytes
    let mut out = Vec::with_capacity(1 + ph_bytes.len() + payload.len());
    out.push(1u8); // mode = 1
    out.extend_from_slice(&ph_bytes);
    out.extend_from_slice(&payload);
    out
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

// crypto_secretbox (xsalsa20-poly1305) of the response with the client's session
// key. Nonce: zero for the first message (likely a counter — iterate if MAC fails).
fn secretbox_with_nonce(msg: &[u8], key: &[u8], nonce24: &[u8; 24]) -> Vec<u8> {
    use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
    let k = Key::try_from(key).expect("32-byte key");
    let n = Nonce::try_from(&nonce24[..]).expect("24-byte nonce");
    DryocSecretBox::encrypt_to_vecbox(msg, &n, &k).to_vec()
}

fn hexdump(b: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in b.chunks(16).enumerate() {
        let hexs: Vec<String> = chunk.iter().map(|x| format!("{:02x}", x)).collect();
        let ascii: String = chunk
            .iter()
            .map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '.' })
            .collect();
        out.push_str(&format!("  {:04x}  {:<48}  {}\n", i * 16, hexs.join(" "), ascii));
    }
    out
}

fn read_frame(s: &mut TcpStream) -> std::io::Result<(u32, u16, Vec<u8>)> {
    let mut hdr = [0u8; 10];
    s.read_exact(&mut hdr)?;
    let op = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
    let rsvd = u16::from_le_bytes(hdr[8..10].try_into().unwrap());
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)?;
    Ok((op, rsvd, body))
}

fn send_frame(s: &mut TcpStream, op: u32, rsvd: u16, body: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&op.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&rsvd.to_le_bytes());
    out.extend_from_slice(body);
    s.write_all(&out)
}

fn handle(
    s: &mut TcpStream,
    box_kp: &KeyPair,
    sign_kp: &SignKp,
    enc_pub: &[u8],
    sig_pub: &[u8],
) -> std::io::Result<()> {
    let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    loop {
        let (op, rsvd, body) = match read_frame(s) {
            Ok(f) => f,
            Err(_) => {
                eprintln!("[emu] {} closed", peer);
                return Ok(());
            }
        };
        eprintln!("[emu] {} <- op={} rsvd={} len={}", peer, op, rsvd, body.len());

        match op {
            1 => {
                // LoginRequest: anonymous sealed box to our X25519 key.
                let sess = match DryocBox::from_sealed_bytes(body.as_slice())
                    .and_then(|sb| sb.unseal_to_vec(box_kp))
                {
                    Ok(plain) => {
                        eprintln!("[emu] LoginRequest plaintext ({} bytes):\n{}", plain.len(), hexdump(&plain));
                        let s = parse_session(&plain);
                        match &s {
                            Some((k, id)) => eprintln!(
                                "[emu] sessionKey ({}B)={} sessionKeyId={}",
                                k.len(), hex::encode(k), id),
                            None => eprintln!("[emu] could NOT parse session:\n{}", hexdump(&plain)),
                        }
                        s
                    }
                    Err(e) => { eprintln!("[emu] unseal FAILED: {:?}", e); None }
                };
                // Response is written RAW (no [op][len] frame): the client recv
                // loop parses [mode=1][PlainHeader][secretbox||nonce] off the stream.
                let _ = op;
                match sess {
                    Some((key, skid)) => {
                        let msg = build_message(enc_pub, sig_pub, sign_kp, &key, skid, 1);
                        s.write_all(&msg)?;
                        eprintln!("[emu] -> raw [mode=1][PlainHeader][secretbox||nonce] {} bytes:\n{}",
                                  msg.len(), hexdump(&msg));
                    }
                    None => eprintln!("[emu] no session key; not replying"),
                }
            }
            other => {
                eprintln!("[emu] unknown op {} ({} byte body):\n{}", other, body.len(), hexdump(&body));
            }
        }
    }
}

fn main() {
    // Bind address and data-file path are overridable via env so splitux (or any
    // launcher) can place the data file where the game's --keenonline-server-data-file
    // arg points and pick the listen address. Defaults match a standalone run.
    let addr = std::env::var("KEEN_ADDR").unwrap_or_else(|_| ADDR.to_string());
    let data_file = std::env::var("KEEN_DATA_FILE").unwrap_or_else(|_| DATA_FILE.to_string());

    // Fresh keypairs each run; write the data file the game loads.
    let box_kp = KeyPair::gen();
    let sign_kp = SigningKeyPair::gen_with_defaults();

    let enc_pub = b64(box_kp.public_key.as_slice());
    let sig_pub = b64(sign_kp.public_key.as_slice());

    let data_doc = serde_json::json!({
        "addressAndPort": addr,
        "publicSignatureKey": sig_pub,
        "publicEncryptionKey": enc_pub,
    });
    if let Some(parent) = std::path::Path::new(&data_file).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&data_file, serde_json::to_string_pretty(&data_doc).unwrap())
        .expect("write data file");

    eprintln!("[emu] data file: {}", std::fs::canonicalize(&data_file).unwrap_or_else(|_| data_file.clone().into()).display());
    eprintln!("[emu]   addressAndPort      = {}", addr);
    eprintln!("[emu]   publicSignatureKey  = {}", sig_pub);
    eprintln!("[emu]   publicEncryptionKey = {}", enc_pub);
    eprintln!("[emu] launch the game with:  --keenonline-server-data-file {}", data_file);

    let enc_pub_bytes = box_kp.public_key.as_slice().to_vec();
    let sig_pub_bytes = sign_kp.public_key.as_slice().to_vec();

    // Share the keys across per-connection threads so multiple game instances
    // (host + joiner) can authenticate concurrently without blocking each other.
    use std::sync::Arc;
    let box_kp = Arc::new(box_kp);
    let sign_kp = Arc::new(sign_kp);
    let enc_pub_bytes = Arc::new(enc_pub_bytes);
    let sig_pub_bytes = Arc::new(sig_pub_bytes);

    let listener = TcpListener::bind(&addr).expect("bind keen-emu addr");
    eprintln!("[emu] listening on {}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                let (bk, sk, ep, sp) = (
                    Arc::clone(&box_kp), Arc::clone(&sign_kp),
                    Arc::clone(&enc_pub_bytes), Arc::clone(&sig_pub_bytes),
                );
                std::thread::spawn(move || {
                    if let Err(e) = handle(&mut s, &bk, &sk, &ep, &sp) {
                        eprintln!("[emu] conn error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("[emu] accept error: {}", e),
        }
    }
}
