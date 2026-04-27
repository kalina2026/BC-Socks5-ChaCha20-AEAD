# BC-Socks5-ChaCha20-AEAD
### A Zero-Trust FTP wrapper for Beyond Compare, turning hostile WiFi into a private encrypted tunnel.

This project provides a secure tunnel for **Beyond Compare SE** users working on compromised or untrusted WiFi networks. By wrapping standard FTP and SOCKS5 traffic in an authenticated encryption layer based on **RFC 8439 (ChaCha20-Poly1305 AEAD)**, it prevents man-in-the-middle attackers from sniffing credentials, stealing file contents, or injecting malicious data into the transfer stream.

---

## Key Features

* **AEAD Enforcement:** All network traffic is protected by authenticated encryption.
* **Dual-Port Mirroring:** The server manages command and data channels through a symbiotic port-swap (2121/2122) to satisfy complex FTP handshakes.
* **Downgrade Protection:** When compiled with `AEAD_ONLY`, the server physically disables plaintext entry points.
* **Silent Drop Behavior:** Rejects malformed or unauthenticated packets without feedback to the attacker.
* **Micro-Footprint:** Optimized for `tcc`. Server: **27kB**, Proxy: **16kB**. Zero external dependencies.

---

## Security Model

This project treats the network as a fully hostile environment. All unencrypted traffic is confined to the local machine (`127.0.0.1`).

1.  **Boundary 1 (Local):** Beyond Compare ↔ Local Proxy (Plain SOCKS5)
2.  **Boundary 2 (Network):** Local Proxy ↔ Remote FTP Server (AEAD Envelope)

### Replay & Integrity Protection
Each packet uses a strictly incrementing 96-bit nonce. If the server receives a packet with an out-of-sequence nonce or a failed Poly1305 tag, it immediately terminates the connection.

---

## Deployment & Build

### 1. Hardening (Optional but Recommended)
Before compiling, edit `tcc_ftp_aead.c` and `socks4_win_proxy.c`:
* Uncomment `#define AEAD_ONLY` in the server to disable the plaintext debug port (2121).
* Change the `global_key[32]` to your own private 256-bit key.

### 2. Compilation
The project is designed to be built with the **Tiny C Compiler (TCC)** for a minimal attack surface.

**Linux (Server):**
`tcc -o ftp_server tcc_ftp_aead.c`

**Windows (Proxy):**
`tcc socks4_win_proxy.c -lws2_32 -o proxy.exe`

---

## Technical Specifications

### Packet Anatomy (AEAD Envelope)

| Field | Size | Description |
| :--- | :--- | :--- |
| **Length** | 4 bytes | Little-endian length of the ciphertext |
| **Nonce** | 12 bytes | 96-bit unique value (Salt + Counter) |
| **Payload** | Variable | Encrypted FTP/SOCKS5 data (ChaCha20) |
| **Auth Tag** | 16 bytes | Poly1305 MAC |

### Port Mirroring Logic
The system utilizes a permanent dual-port bind to handle the FTP Data Channel:
* **Secure Entry (Port 2122):** Used for the Command Channel.
* **Data Transit (Port 2121):** Dynamically opened for the Data Channel only after a secure command session is authenticated.

In `AEAD_ONLY` mode, Port 2121 acts as a "Black Hole"—it will not accept new command sessions, leaving attackers with no metadata or response.

---

## License
**MIT** — Free and open for personal or professional use.
**Origin:** Human + Gemini 3 Flash + Copilot.
