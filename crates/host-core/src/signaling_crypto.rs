use anyhow::{anyhow, Result};
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

const PROTOCOL_INFO_PREFIX: &[u8] = b"pocketshell-files-v1";

/// Direction flag for nonce construction — prevents nonce collision between sides.
const DIRECTION_HOST_TO_MOBILE: u32 = 0x00000001;
const DIRECTION_MOBILE_TO_HOST: u32 = 0x00000000;

/// Ephemeral X25519 keypair for a single session.
pub struct EphemeralKeypair {
    secret: Option<EphemeralSecret>,
    pub public_key: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            public_key,
        }
    }

    /// Consume the private key to compute the shared secret.
    /// After this call, the ephemeral private key no longer exists.
    pub fn diffie_hellman(mut self, their_public: &PublicKey) -> SharedSecret {
        let secret = self
            .secret
            .take()
            .expect("ephemeral secret already consumed");
        secret.diffie_hellman(their_public)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    pub fn public_key_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.public_key.as_bytes())
    }
}

/// Derives a 256-bit session content key from X25519 shared secret.
pub fn derive_session_key(
    shared_secret: &[u8; 32],
    auth_nonce: &[u8],
    mobile_x25519_pub: &[u8; 32],
    host_x25519_pub: &[u8; 32],
    session_id: &str,
) -> Result<[u8; 32]> {
    // info = protocol_prefix || mobile_pub || host_pub || session_id
    let mut info = Vec::with_capacity(
        PROTOCOL_INFO_PREFIX.len() + 32 + 32 + session_id.len(),
    );
    info.extend_from_slice(PROTOCOL_INFO_PREFIX);
    info.extend_from_slice(mobile_x25519_pub);
    info.extend_from_slice(host_x25519_pub);
    info.extend_from_slice(session_id.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(auth_nonce), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(&info, &mut key)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    Ok(key)
}

/// Per-session encryption/decryption state.
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
    /// Counter for outbound messages (host→mobile).
    send_counter: u64,
    /// Counter for inbound messages (mobile→host) — for replay detection.
    recv_counter: u64,
    is_host: bool,
}

impl SessionCipher {
    pub fn new_host(session_key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&session_key)
                .expect("session key is 32 bytes"),
            send_counter: 0,
            recv_counter: 0,
            is_host: true,
        }
    }

    pub fn new_mobile(session_key: [u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new_from_slice(&session_key)
                .expect("session key is 32 bytes"),
            send_counter: 0,
            recv_counter: 0,
            is_host: false,
        }
    }

    /// Build a 96-bit nonce: 4 bytes direction + 8 bytes counter.
    fn build_nonce(direction: u32, counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&direction.to_be_bytes());
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Encrypt a plaintext payload. Returns (nonce_bytes, ciphertext).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let direction = if self.is_host {
            DIRECTION_HOST_TO_MOBILE
        } else {
            DIRECTION_MOBILE_TO_HOST
        };

        let nonce = Self::build_nonce(direction, self.send_counter);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("encryption failed: {}", e))?;

        self.send_counter += 1;

        Ok((nonce.as_slice().to_vec(), ciphertext))
    }

    /// Decrypt a ciphertext payload. Validates nonce counter for replay protection.
    pub fn decrypt(&mut self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        if nonce_bytes.len() != 12 {
            return Err(anyhow!("invalid nonce length: {}", nonce_bytes.len()));
        }

        let nonce = Nonce::from_slice(nonce_bytes);

        // Validate direction: incoming messages should be from the other side
        let expected_direction = if self.is_host {
            DIRECTION_MOBILE_TO_HOST
        } else {
            DIRECTION_HOST_TO_MOBILE
        };

        let msg_direction =
            u32::from_be_bytes([nonce_bytes[0], nonce_bytes[1], nonce_bytes[2], nonce_bytes[3]]);
        if msg_direction != expected_direction {
            return Err(anyhow!(
                "unexpected nonce direction: expected {}, got {}",
                expected_direction,
                msg_direction
            ));
        }

        // Extract counter and check for replay
        let msg_counter =
            u64::from_be_bytes([
                nonce_bytes[4], nonce_bytes[5], nonce_bytes[6], nonce_bytes[7],
                nonce_bytes[8], nonce_bytes[9], nonce_bytes[10], nonce_bytes[11],
            ]);
        if msg_counter < self.recv_counter {
            return Err(anyhow!(
                "replay detected: counter {} < expected {}",
                msg_counter,
                self.recv_counter
            ));
        }

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("decryption failed: {}", e))?;

        // Advance counter past the received message
        self.recv_counter = msg_counter + 1;

        Ok(plaintext)
    }

    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }
}

/// Parse a base64-encoded X25519 public key.
pub fn parse_x25519_public_key(b64: &str) -> Result<PublicKey> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| anyhow!("invalid base64 for X25519 public key: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "X25519 public key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange_and_encrypt_decrypt() {
        // Simulate both sides
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        // Both sides compute shared secret
        let host_shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let mobile_shared = mobile_kp.diffie_hellman(&PublicKey::from(host_pub));

        assert_eq!(host_shared.as_bytes(), mobile_shared.as_bytes());

        let auth_nonce = b"test-auth-nonce-32-bytes-padding!";
        let session_id = "test-session-123";

        // Derive session keys
        let host_key = derive_session_key(
            host_shared.as_bytes(),
            auth_nonce,
            &mobile_pub,
            &host_pub,
            session_id,
        )
        .unwrap();
        let mobile_key = derive_session_key(
            mobile_shared.as_bytes(),
            auth_nonce,
            &mobile_pub,
            &host_pub,
            session_id,
        )
        .unwrap();

        assert_eq!(host_key, mobile_key);

        // Create ciphers
        let mut host_cipher = SessionCipher::new_host(host_key);
        let mut mobile_cipher = SessionCipher::new_mobile(mobile_key);

        // Host encrypts, mobile decrypts
        let plaintext = b"hello from host";
        let (nonce, ciphertext) = host_cipher.encrypt(plaintext).unwrap();
        let decrypted = mobile_cipher.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Mobile encrypts, host decrypts
        let plaintext2 = b"hello from mobile";
        let (nonce2, ciphertext2) = mobile_cipher.encrypt(plaintext2).unwrap();
        let decrypted2 = host_cipher.decrypt(&nonce2, &ciphertext2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_replay_protection() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let auth_nonce = b"replay-test-nonce-32-bytes-pad!!";

        let key =
            derive_session_key(shared.as_bytes(), auth_nonce, &mobile_pub, &host_pub, "s1")
                .unwrap();

        let mut host_cipher = SessionCipher::new_host(key);
        let mut mobile_cipher = SessionCipher::new_mobile(key);

        // Host sends two messages
        let (nonce1, ct1) = host_cipher.encrypt(b"msg1").unwrap();
        let (nonce2, ct2) = host_cipher.encrypt(b"msg2").unwrap();

        // Mobile receives both in order
        mobile_cipher.decrypt(&nonce1, &ct1).unwrap();
        mobile_cipher.decrypt(&nonce2, &ct2).unwrap();

        // Replaying nonce1 should fail
        let result = mobile_cipher.decrypt(&nonce1, &ct1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("replay"));
    }

    #[test]
    fn test_wrong_direction_rejected() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let auth_nonce = b"direction-test-nonce-32-pad!!!!!";

        let key =
            derive_session_key(shared.as_bytes(), auth_nonce, &mobile_pub, &host_pub, "s2")
                .unwrap();

        let mut host_cipher = SessionCipher::new_host(key);
        let mut host_cipher2 = SessionCipher::new_host(key);

        // Host encrypts (direction = host→mobile)
        let (nonce, ct) = host_cipher.encrypt(b"msg").unwrap();

        // Another host instance tries to decrypt as if it were inbound — wrong direction
        let result = host_cipher2.decrypt(&nonce, &ct);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("direction"));
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();

        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();

        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let auth_nonce = b"tamper-test-nonce-32-bytes-pad!!";

        let key =
            derive_session_key(shared.as_bytes(), auth_nonce, &mobile_pub, &host_pub, "s3")
                .unwrap();

        let mut host_cipher = SessionCipher::new_host(key);
        let mut mobile_cipher = SessionCipher::new_mobile(key);

        let (nonce, mut ct) = host_cipher.encrypt(b"sensitive data").unwrap();

        // Flip a byte
        ct[0] ^= 0xff;

        let result = mobile_cipher.decrypt(&nonce, &ct);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("decryption failed"));
    }

    #[test]
    fn test_parse_x25519_public_key() {
        let kp = EphemeralKeypair::generate();
        let b64 = kp.public_key_base64();
        let parsed = parse_x25519_public_key(&b64).unwrap();
        assert_eq!(parsed.as_bytes(), kp.public_key.as_bytes());
    }

    #[test]
    fn test_different_sessions_produce_different_keys() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();
        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();
        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));
        let salt = b"same-salt-for-both-sessions!!!!!";

        let key1 = derive_session_key(shared.as_bytes(), salt, &mobile_pub, &host_pub, "session-A").unwrap();
        let key2 = derive_session_key(shared.as_bytes(), salt, &mobile_pub, &host_pub, "session-B").unwrap();

        assert_ne!(key1, key2, "different session_ids must produce different keys");
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let host_kp = EphemeralKeypair::generate();
        let mobile_kp = EphemeralKeypair::generate();
        let host_pub = host_kp.public_key_bytes();
        let mobile_pub = mobile_kp.public_key_bytes();
        let shared = host_kp.diffie_hellman(&PublicKey::from(mobile_pub));

        let key1 = derive_session_key(shared.as_bytes(), b"salt-one-32-bytes-pad!!!!!!!!!", &mobile_pub, &host_pub, "s").unwrap();
        let key2 = derive_session_key(shared.as_bytes(), b"salt-two-32-bytes-pad!!!!!!!!!", &mobile_pub, &host_pub, "s").unwrap();

        assert_ne!(key1, key2, "different salts must produce different keys");
    }

    #[test]
    fn test_nonce_never_reused_within_session() {
        let key = [0x42u8; 32];
        let mut cipher = SessionCipher::new_host(key);

        let (nonce1, _) = cipher.encrypt(b"msg1").unwrap();
        let (nonce2, _) = cipher.encrypt(b"msg2").unwrap();
        let (nonce3, _) = cipher.encrypt(b"msg3").unwrap();

        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        assert_ne!(nonce1, nonce3);
    }

    #[test]
    fn test_counter_monotonically_increases() {
        let key = [0x42u8; 32];
        let mut cipher = SessionCipher::new_host(key);

        assert_eq!(cipher.send_counter(), 0);
        cipher.encrypt(b"a").unwrap();
        assert_eq!(cipher.send_counter(), 1);
        cipher.encrypt(b"b").unwrap();
        assert_eq!(cipher.send_counter(), 2);
    }

    #[test]
    fn test_out_of_order_allowed_but_replay_rejected() {
        let key = [0x42u8; 32];
        let mut host = SessionCipher::new_host(key);
        let mut mobile = SessionCipher::new_mobile(key);

        let (n1, c1) = host.encrypt(b"msg1").unwrap();
        let (n2, c2) = host.encrypt(b"msg2").unwrap();
        let (n3, c3) = host.encrypt(b"msg3").unwrap();

        // Receive out of order: 3, then 1 skipped, then replay 3
        mobile.decrypt(&n3, &c3).unwrap(); // counter jumps to 3
        // n1 has counter 0 which is < recv_counter (3), so rejected
        assert!(mobile.decrypt(&n1, &c1).is_err());
        // n2 has counter 1 which is also < recv_counter (3)
        assert!(mobile.decrypt(&n2, &c2).is_err());
        // replaying n3 again: counter 2 < recv_counter (3)
        assert!(mobile.decrypt(&n3, &c3).is_err());
    }

    #[test]
    fn test_large_payload_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let mut host = SessionCipher::new_host(key);
        let mut mobile = SessionCipher::new_mobile(key);

        // 200 KB payload (at the signaling limit)
        let payload = vec![0xABu8; 200 * 1024];
        let (nonce, ct) = host.encrypt(&payload).unwrap();
        let decrypted = mobile.decrypt(&nonce, &ct).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_ephemeral_key_consumed_after_dh() {
        let kp = EphemeralKeypair::generate();
        let other_pub = EphemeralKeypair::generate().public_key;

        // After diffie_hellman, the private key is consumed
        let _shared = kp.diffie_hellman(&other_pub);
        // kp is moved — cannot be used again (enforced by Rust ownership)
    }

    #[test]
    fn test_cross_session_cipher_isolation() {
        // Two sessions with different keys cannot decrypt each other's messages
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        let mut host1 = SessionCipher::new_host(key1);
        let mut mobile2 = SessionCipher::new_mobile(key2);

        let (nonce, ct) = host1.encrypt(b"secret").unwrap();
        let result = mobile2.decrypt(&nonce, &ct);
        assert!(result.is_err(), "different session keys must not decrypt");
    }

    #[test]
    fn test_invalid_public_key_rejected() {
        // Too short
        let short = base64::engine::general_purpose::STANDARD.encode(&[0u8; 16]);
        assert!(parse_x25519_public_key(&short).is_err());

        // Too long
        let long = base64::engine::general_purpose::STANDARD.encode(&[0u8; 64]);
        assert!(parse_x25519_public_key(&long).is_err());

        // Invalid base64
        assert!(parse_x25519_public_key("not-valid-base64!!!").is_err());
    }
}
