<div align="center">

<br>

<img src="https://img.shields.io/badge/%E2%96%B2-KOE--CORE-0a0a0a?style=for-the-badge&labelColor=0a0a0a" alt="koe-core" height="50">

<br><br>

# The Cryptographic Core of the Koe Protocol

**No internet required. No accounts. No phone number.**<br>
**Pure P2P messaging, encrypted end-to-end, written in C.**

<br>

<a href="#protocol"><img src="https://img.shields.io/badge/PROTOCOL-0a0a0a?style=for-the-badge" alt="Protocol"></a>
&nbsp;&nbsp;
<a href="#architecture"><img src="https://img.shields.io/badge/ARCHITECTURE-0a0a0a?style=for-the-badge" alt="Architecture"></a>
&nbsp;&nbsp;
<a href="#building"><img src="https://img.shields.io/badge/BUILD-0a0a0a?style=for-the-badge" alt="Build"></a>

<br><br>

[![License](https://img.shields.io/badge/MIT-1a1a1a?style=flat-square&logo=opensourceinitiative&logoColor=white)](LICENSE)
&nbsp;
[![Language](https://img.shields.io/badge/C11-1a1a1a?style=flat-square&logo=c&logoColor=white)](#)
&nbsp;
[![libsodium](https://img.shields.io/badge/libsodium-1a1a1a?style=flat-square&logoColor=white)](#)
&nbsp;
[![Opus](https://img.shields.io/badge/Opus-1a1a1a?style=flat-square&logoColor=white)](#)
&nbsp;
[![CMake](https://img.shields.io/badge/CMake-1a1a1a?style=flat-square&logo=cmake&logoColor=white)](#)
&nbsp;
[![ARM64](https://img.shields.io/badge/ARM64-1a1a1a?style=flat-square&logoColor=white)](#)

<br>

---

<br>

<table>
<tr>
<td width="50%" valign="top">

**The engine behind Koe-chat.**<br><br>
XChaCha20-Poly1305 message encryption.<br>
X25519 ephemeral key exchange.<br>
Ed25519 identity and signatures.<br>
WiFi Direct and Bluetooth transport.<br>
Opus voice call encoding and decoding.<br>
Offline message queue, persistent and encrypted.<br>
Self-destruct timers, ghost mode, travel mode.

</td>
<td width="50%" valign="top">

**Designed to run anywhere C runs.**<br><br>
Tested on ARM64 Android via Termux.<br>
No Android SDK. No JNI. No Java.<br>
Single static library, two dependencies.<br>
Clean C11, no undefined behaviour.<br>
<br>
Consumed by koe-chat (Rust), koe-server (Go), and koe-api (C++/Swift).

</td>
</tr>
</table>

<br>

</div>

---

<br>

<div align="center">

## What is koe-core?

</div>

<br>

**koe-core** is the cryptographic and protocol foundation of the [Koe-chat](https://github.com/koe-chat) ecosystem. It implements the complete Koe wire protocol in a single static library with no external dependencies beyond libsodium and libopus. Everything above this layer — the Rust TUI, the Go relay server, the C++ API — links against koe-core and speaks the protocol through its public header `koe.h`.

The library was designed from the start to run on constrained hardware. The primary development environment is a Redmi 12 (Snapdragon 685) running Termux. Every design decision — from the choice of XChaCha20 over AES (no hardware acceleration on ARM Cortex-A53) to the 8 kHz Opus narrowband voice encoding — reflects that constraint.

<br>

---

<br>

<div align="center">

## Protocol

</div>

<br>

### Cryptographic Primitives

| Primitive | Algorithm | Purpose |
|:----------|:----------|:--------|
| Symmetric encryption | XChaCha20-Poly1305 | Message and audio frame encryption |
| Key exchange | X25519 (ECDH) | Ephemeral session key derivation |
| Identity | Ed25519 | Long-term keypair, signatures, peer addressing |
| Key derivation | BLAKE2b-256 | Session key derivation from shared secret |
| Password hashing | Argon2id | Identity file encryption, backup passphrase |
| Random nonces | libsodium `randombytes_buf` | Per-message nonce generation |

<br>

### Packet Format

Every Koe packet has a fixed 102-byte header followed by a variable-length encrypted payload.

```
Offset   Size   Field
------   ----   -----
     0      4   magic       "KOE\x01"
     4      1   type        KOE_TYPE_MSG | AUDIO | HANDSHAKE | ACK | ...
     5      1   flags       KOE_FLAG_ENCRYPTED | SIGNED | FRAGMENTED | ...
     6      4   length      payload length (uint32, big-endian)
    10     32   from        sender Ed25519 public key
    42     32   to          recipient Ed25519 public key
    74     24   nonce       XChaCha20-Poly1305 nonce
    98      4   checksum    CRC32 over bytes [0..97]
   102      *   payload     encrypted content
```

<br>

### Handshake (Two-Round Key Exchange)

```
Initiator (A)                              Responder (B)
─────────────                              ─────────────
eph_a = X25519 keypair
HELLO = { id_a.pk, eph_a.pk, sig_a }
                    ──── HELLO ────►
                                           eph_b = X25519 keypair
                                           derive session keys
                                           HELLO_ACK = { id_b.pk, eph_b.pk, sig_b }
                    ◄── HELLO_ACK ────
derive session keys
verify sig_b
                    ──── ACK ────►
                                           session established
session established
```

Session keys are derived from the X25519 shared secret, both long-term public keys, and a BLAKE2b-256 hash. The initiator's `tx_key` equals the responder's `rx_key`. Ephemeral keypairs are discarded immediately after derivation — forward secrecy is guaranteed.

<br>

### Transport Priority

```
Same local network    ──►  WiFi Direct (P2P, lowest latency)
                      ──►  Bluetooth RFCOMM (fallback, ~60–110 ms RTT)
Long distance         ──►  TCP relay via Koe-server (E2E encrypted, server sees nothing)
```

<br>

---

<br>

<div align="center">

## Architecture

</div>

<br>

```
                         koe.h  (public API)
                              │
          ┌───────────────────┼────────────────────┐
          │                   │                    │
   koe_crypto.c         koe_transport.c      koe_message.c
   koe_identity.c       koe_audio.c          koe_queue.c
   koe_handshake.c      koe_backup.c         koe_store.c
                        koe_channel.c        koe_ghost.c
                        koe_revoke.c         koe_event.c
                              │
          ┌───────────────────┼────────────────────┐
          │                   │                    │
     libsodium            libopus              libc
  (crypto primitives)  (voice encoding)   (POSIX sockets)
```

<br>

<table>
<tr>
<td width="50%" valign="top">

**Core modules**

| Module | Responsibility |
|:-------|:---------------|
| `koe_crypto` | libsodium wrappers, key generation, encrypt/decrypt, sign/verify |
| `koe_identity` | Profile management, contact book, short ID derivation |
| `koe_handshake` | Two-round X25519 key exchange, session derivation |
| `koe_packet` | Wire format serialisation and deserialisation |
| `koe_transport` | WiFi Direct, Bluetooth, TCP relay, discovery |
| `koe_message` | Application-level messages, self-destruct, scheduling |

</td>
<td width="50%" valign="top">

**Feature modules**

| Module | Responsibility |
|:-------|:---------------|
| `koe_queue` | Persistent offline message queue, per-peer, encrypted at rest |
| `koe_audio` | Opus encoding/decoding, jitter buffer, call signalling |
| `koe_backup` | Local `.koebak` export, server upload, P2P device migration |
| `koe_channel` | Broadcast channels, per-subscriber encryption |
| `koe_ghost` | Ghost mode, secret chats, travel mode |
| `koe_revoke` | Key revocation and identity recovery |
| `koe_event` | Poll-based event loop, scheduled messages, self-destruct pump |

</td>
</tr>
</table>

<br>

---

<br>

<div align="center">

## Features

</div>

<br>

<table>
<tr>
<td width="50%" valign="top">

<h3>End-to-End Encryption</h3>

Every message is encrypted with XChaCha20-Poly1305 using a session key that never leaves the two communicating devices. The relay server, if used, sees only opaque ciphertext. Authentication tags prevent tampering in transit.

<br>

<h3>Offline Message Queue</h3>

Messages sent to unreachable peers are stored in an encrypted per-peer queue on disk. When the peer comes online, the queue drains automatically in sequence order. Entries older than seven days are expired. The cap is configurable per peer.

<br>

<h3>Voice Calls</h3>

Live audio encoded with Opus at 8 kHz narrowband, 8 kbps, 20 ms frames. Each frame is individually encrypted and wrapped in a `KOE_TYPE_AUDIO` packet. Packet loss concealment via Opus PLC means dropped frames are synthesised rather than heard as glitches. Discontinuous transmission (DTX) silences the channel during pauses to conserve bandwidth.

<br>

<h3>Self-Destruct Messages</h3>

Messages carry an optional TTL in seconds. Both sender and recipient start independent countdown timers on delivery. When the timer fires, the message body is zeroed in memory before the allocation is freed, then removed from the store. The `koe_event` pump checks expiry on every poll cycle.

</td>
<td width="50%" valign="top">

<h3>Ghost Mode</h3>

When active, the node stops responding to discovery pings and suppresses read receipts and typing indicators. Incoming messages are still received and queued. Peers see the user as permanently offline.

<br>

<h3>Secret Chats</h3>

A dedicated encrypted partition inside the data directory, unlocked by a separate PIN. Invisible from the main chat list even if the device is unlocked with the primary passphrase. Wiped automatically after a configurable number of failed PIN attempts.

<br>

<h3>Travel Mode</h3>

Encrypts the full conversation history and contact book under a recovery PIN, then removes the plaintext files. The app continues to function for new messages; history appears empty. Restore with the recovery PIN when safe. Designed for border crossings and device inspections.

<br>

<h3>Device Migration</h3>

Direct P2P transfer of the full user data to a new device over WiFi Direct or Bluetooth. A 5-minute transfer window and a displayed verification token prevent interception. No data passes through the relay server.

</td>
</tr>
</table>

<br>

---

<br>

<div align="center">

## Building

</div>

<br>

### Dependencies

```bash
# Termux (Android)
pkg install libsodium libopus cmake ninja

# Debian / Ubuntu
apt install libsodium-dev libopus-dev cmake ninja-build

# Arch
pacman -S libsodium opus cmake ninja
```

<br>

### Compile

```bash
git clone https://github.com/koe-chat/koe-core
cd koe-core

cmake -B build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release

cmake --build build

# The static library is at:
#   build/libkoe-core.a
```

<br>

### Debug Build (with AddressSanitizer)

```bash
cmake -B build-debug -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug

cmake --build build-debug
```

<br>

### Use as a Dependency

```cmake
# In your CMakeLists.txt
add_subdirectory(koe-core)
target_link_libraries(your_target PRIVATE koe-core)
```

```rust
// In build.rs (for koe-chat)
println!("cargo:rustc-link-lib=static=koe-core");
println!("cargo:rustc-link-lib=sodium");
println!("cargo:rustc-link-lib=opus");
```

```go
// In koe-server
// #cgo LDFLAGS: -lkoe-core -lsodium -lopus
// #include "koe.h"
import "C"
```

<br>

---

<br>

<div align="center">

## Usage

</div>

<br>

```c
#include "koe.h"

static void on_event(const koe_event_t *ev, void *ctx)
{
    (void)ctx;

    switch (ev->type) {
    case KOE_EV_MSG_RECEIVED:
        printf("message: %.*s\n",
               (int)ev->data.message.msg->body_len,
               ev->data.message.msg->body);
        break;

    case KOE_EV_PEER_ONLINE:
        printf("peer online\n");
        break;

    case KOE_EV_CALL_INCOMING:
        printf("incoming call\n");
        break;

    default:
        break;
    }
}

int main(void)
{
    koe_config_t cfg = {
        .data_dir             = "/data/data/com.termux/files/home/.koe",
        .passphrase           = "your-passphrase",
        .relay_host           = "koe-relay.hf.space",
        .relay_port           = 9474,
        .discovery_timeout_ms = 500,
        .bluetooth_enabled    = 1,
        .queue_max_per_peer   = 512,
    };

    koe_ctx_t ctx;
    if (koe_init(&ctx, &cfg) != 0)
        return 1;

    koe_event_register(on_event, NULL);

    /* Main loop — driven by the TUI at ~60 fps. */
    while (running) {
        koe_event_poll(16);
        /* render UI */
    }

    koe_shutdown(&ctx);
    return 0;
}
```

<br>

### Send a Text Message

```c
/* Plain message */
koe_send_text(&ctx, recipient_pk, "hello", 0);

/* Self-destructs after 60 seconds */
koe_send_text(&ctx, recipient_pk, "this disappears", 60);

/* Scheduled for tomorrow */
koe_send_text_scheduled(&ctx, recipient_pk, "don't forget", tomorrow);
```

<br>

### Start a Voice Call

```c
koe_audio_ctx_t *call = koe_start_call(&ctx, recipient_pk);
if (!call) { /* peer unreachable */ }

/* Capture and send audio frames at 20 ms intervals */
koe_audio_encode_frame(call, pcm_frame, &session, &pkt);
koe_transport_send(&peer, &pkt);

/* End the call */
koe_end_call(&ctx, call);
```

<br>

---

<br>

<div align="center">

## Security Model

</div>

<br>

<table>
<tr>
<td width="50%" valign="top">

**What koe-core guarantees**

The relay server cannot read message content. Forward secrecy: compromising today's session key does not reveal past messages. Message authenticity: Ed25519 signatures prevent impersonation. Identity binding: the public key is the address — no phone number, no email, no central registry.

</td>
<td width="50%" valign="top">

**What koe-core does not guarantee**

Self-destruct relies on mutual cooperation. A malicious recipient can screenshot or copy a message before its timer fires. Backup security depends on passphrase strength. Key verification requires an out-of-band step (the 6-digit token displayed on both screens).

</td>
</tr>
</table>

<br>

---

<br>

<div align="center">

## Roadmap

</div>

<br>

### v0.1 — Foundation (Current)

- [x] XChaCha20-Poly1305 + X25519 + Ed25519 full crypto stack
- [x] Two-round handshake with forward secrecy
- [x] WiFi Direct and TCP relay transport
- [x] Offline message queue, encrypted at rest
- [x] Opus voice call encoding and decoding
- [x] Self-destruct messages
- [x] Ghost mode, secret chats, travel mode
- [x] Local and server-side backup
- [x] P2P device migration
- [x] Broadcast channels
- [x] Key revocation
- [x] Poll-based event loop

### v0.2 — Transport (Planned)

- [ ] Bluetooth RFCOMM transport (full implementation)
- [ ] WiFi Direct nl80211 discovery (wpa_supplicant P2P socket)
- [ ] Fragment reassembly for messages above KOE_MAX_PAYLOAD
- [ ] Relay authentication protocol
- [ ] Server-side backup upload and versioning

### v1.0 — Stable Protocol

- [ ] Formal protocol specification in koe-protocol
- [ ] Independent security audit
- [ ] Compatibility with Torch (pending protocol alignment)
- [ ] Group messaging via Matrix-compatible koe-server
- [ ] `koe_ffi.h` — simplified FFI surface for Rust and Go

<br>

---

<br>

<div align="center">

## Ecosystem

</div>

<br>

| Repository | Language | Description |
|:-----------|:---------|:------------|
| [koe-core](https://github.com/koe-chat/koe-core) | C | This library. Protocol implementation, crypto, transport |
| [koe-protocol](https://github.com/koe-chat/koe-protocol) | C / Markdown | Formal protocol specification and reference implementation |
| [koe-chat](https://github.com/koe-chat/koe-chat) | Rust / Ruby | Terminal UI client with plugin system |
| [koe-server](https://github.com/koe-chat/koe-server) | Go | Relay server, Matrix-compatible, self-hostable |
| [koe-api](https://github.com/koe-chat/koe-api) | C++ / Swift | REST API layer over koe-server |

<br>

---

<br>

<div align="center">

## Links

</div>

<br>

<div align="center">

[![Organization](https://img.shields.io/badge/Koe--chat_Org-GitHub-1a1a1a?style=for-the-badge&logo=github&logoColor=white)](https://github.com/koe-chat)
&nbsp;
[![Protocol Spec](https://img.shields.io/badge/Protocol_Spec-koe--protocol-1a1a1a?style=for-the-badge&logo=github&logoColor=white)](https://github.com/koe-chat/koe-protocol)
&nbsp;
[![Report Issue](https://img.shields.io/badge/Report_Issue-GitHub-1a1a1a?style=for-the-badge&logo=github&logoColor=white)](https://github.com/koe-chat/koe-core/issues)

<br>

[![OpceanAI](https://img.shields.io/badge/OpceanAI-Hugging_Face-ffd21e?style=for-the-badge&logo=huggingface&logoColor=black)](https://huggingface.co/OpceanAI)
&nbsp;
[![Sponsor](https://img.shields.io/badge/Sponsor-GitHub_Sponsors-ea4aaa?style=for-the-badge&logo=githubsponsors&logoColor=white)](https://github.com/sponsors/aguitauwu)

</div>

<br>

---

<br>

<div align="center">

## License

</div>

<br>

```
MIT License

Copyright (c) 2026 Koe-chat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

<br>

---

<br>

<div align="center">

**No internet required. No server required. No trust required.**

<br>

[![Koe-chat](https://img.shields.io/badge/Koe--chat-2026-0a0a0a?style=for-the-badge)](https://github.com/koe-chat)

<br>

</div>
