# A Zero-Trust FTP wrapper for Beyond Compare, turning hostile WiFi into a private encrypted tunnel

This project provides a secure tunnel for Beyond Compare SE users working on compromised or untrusted WiFi networks. By wrapping standard FTP and SOCKS5 traffic in an authenticated encryption layer based on RFC 8439 (ChaCha20-Poly1305 AEAD), it prevents man-in-the-middle attackers from sniffing credentials, stealing file contents, or injecting malicious data into the transfer stream.

In addition to the encrypted proxy, this project will include a minimal FTP server implementation designed to accept only ChaCha20-Poly1305 AEAD-wrapped connections. Plaintext FTP will be rejected entirely, ensuring that only authenticated, encrypted clients can access the protected file endpoints.

* **Downgrade Protection:** The server cannot speak plaintext under any circumstances. There is no negotiation step (such as STARTTLS) that an attacker could intercept or strip.
* **Replay Protection:** Each packet uses a strictly incrementing 96-bit nonce, preventing attackers from replaying captured commands or data.
* **Minimal Footprint:** Compiling with tcc produces a tiny binary with zero dependencies, reducing the attack surface of the proxy itself.
## Security Model

This project treats the local WiFi network as a fully hostile environment. All unencrypted traffic is confined to the local machine, and all remote communication is wrapped in ChaCha20-Poly1305 AEAD.

**Boundary 1 — Local:**  
Beyond Compare ↔ Local Proxy (plain SOCKS5, bound to 127.0.0.1 only)

**Boundary 2 — Network:**  
Local Proxy ↔ Remote FTP Server (all data encapsulated in the AEAD envelope)

This separation ensures that the only traffic exposed to the hostile network is encrypted, authenticated, and replay-protected.

## Packet Anatomy (AEAD Envelope)

| Field      | Size       | Description                                              |
|------------|------------|----------------------------------------------------------|
| Length     | 4 bytes    | Length of the ciphertext that follows                   |
| Nonce      | 12 bytes   | Unique per-packet 96-bit value (prevents replay)        |
| Ciphertext | Variable   | Encrypted FTP/SOCKS5 payload (ChaCha20)                 |
| Auth Tag   | 16 bytes   | Poly1305 MAC (detects tampering or corruption)          |

This structure makes the protocol self-delimiting, tamper-evident, and resistant to replay attacks.

## Silent Drop Behavior

Because the threat model includes an active MITM probing for weaknesses, the server implements silent rejection:

- If the length header is malformed  
- If the Poly1305 tag fails  
- If the nonce is reused or out of sequence  

…the server immediately closes the socket without sending any error message.

Silence is a defensive posture: it denies attackers feedback about whether their guesses, injections, or bit-flips were close to valid.

## Replay Protection Details

To ensure replay protection in a Zero-Trust environment, the client and server synchronize nonces implicitly. Each session begins with a 96-bit nonce initialized to 0, and the sender increments it by 1 for every packet transmitted.

Because the nonce space is 96 bits (2^96), exhaustion is practically impossible. If the server receives a packet whose nonce is not exactly the previous value plus one, it triggers a Silent Drop. This prevents attackers from dropping, reordering, or replaying packets in an attempt to manipulate the session.
