# OTP PSK based chacha20-poly1305 implementation 

## One-Time-Pad pre-shared key based chacha20-poly1305 implementation in a UDP tunnel on a local network for information-theoretically secure data transfer and storage 

## Employ strict OTP protocol for security! If protocol breached - rip. 

> NOTE: This is super early alpha proof of concept implementation. Contributions welcome, dm me on X.

Traditional WireGuard:
======================
Public Key Auth → ECDH → Mix PSK → Session Keys → Encrypt  
    ↑                                                  
Vulnerable to:  
- Quantum computers breaking ECDH  
- Side-channel attacks on curve operations  
- Implementation flaws in elliptic curve code  
- Key generation vulnerabilities  

Pure PSK System:
================
Shared Key Material → Direct Encryption with Authentication
                      ↑
Advantages:
✓ Information-theoretically secure (if keys truly random)
✓ Simpler implementation (fewer moving parts)
✓ No quantum vulnerability
✓ No complex key exchange
✓ Authentication via shared secret
✓ Perfect forward secrecy through key consumption
✓ No public key infrastructure needed  

## Critical Requirements

For this to work securely:

✓ Key Material Quality:
  - Truly random (from hardware RNG or /dev/random)
  - Never reused
  - Physically secured

✓ Synchronization:
  - Both sides must consume keys identically
  - Offset tracking with recovery mechanisms
  - Checksums to verify sync

✓ Physical Security:
  - Key material never transmitted electronically
  - Stored on encrypted, tamper-evident media
  - Destroyed after use (or marked as consumed)

✓ Time-Bounded:
  - System only works while key material lasts
  - Must distribute new material before exhaustion  

## Architecture  

PSK File Structure  
┌──────────────────────────────────────────────────────────────────────┐  
│ Offset 0:   [Auth_Tag_A][Nonce_A][Key_A][Auth_Tag_B][Nonce_B][Key_B] │  
│ Offset 120: [Auth_Tag_A][Nonce_A][Key_A][Auth_Tag_B][Nonce_B][Key_B] │  
│ Offset 240: [Auth_Tag_A][Nonce_A][Key_A][Auth_Tag_B][Nonce_B][Key_B] │  
│ ...                                                                  │  
└──────────────────────────────────────────────────────────────────────┘  

Each "slot" contains:
- 16 bytes: Authentication tag for direction A→B
- 12 bytes: Nonce for A→B
- 32 bytes: Encryption key for A→B  
- 16 bytes: Authentication tag for direction B→A
- 12 bytes: Nonce for B→A
- 32 bytes: Encryption key for B→A
Total: 120 bytes per slot

Authentication:
- Both sides know the auth tags
- Sender includes their auth tag in packet
- Receiver verifies tag matches expected value from PSK
- This proves sender has the PSK file (authentication)

- Note: The 16-byte header auth tag is distinct from the Poly1305 AEAD tag. It is a per-direction cookie from the PSK file and is included as AEAD Additional Authenticated Data (AAD), so ChaCha20-Poly1305 binds it (with magic/version/flags/direction/sequence) to the ciphertext.

### File Overview

- **core_protocol.py**: Main PSK-only tunnel implementation over UDP using ChaCha20-Poly1305. Handles PSK slot parsing, sequence numbers and replay protection, key rotation, and integrates a TUN interface for routing IP packets. Exposes a CLI (`--psk`, `--local-port`, `--remote-host`, `--remote-port`, `--initiator`, `--local-ip`, `--remote-ip`, `--state`).
- **psk_file_generator.py**: Generates a large PSK file composed of 120-byte slots (auth tags, nonces, keys) filled with cryptographically secure random bytes. Prints capacity estimates and writes a `.sha256` checksum file for verification.
- **rpi5_deployment.sh**: Deployment helper for Raspberry Pi (or Debian-based) systems. Installs Python dependencies, prepares directories, enables the TUN module, and installs the tunnel script to `/usr/local/bin`. Note: it assumes a script named `psk_tunnel.py`; in this repo the main implementation is `core_protocol.py` (copy/rename as needed).
- **laptop_launch.sh**: Launch helper for Laptop (Site A, initiator). Sets local/remote TUN IPs and peer transport IP, then starts the tunnel with `--initiator` and a site-specific state file.
- **rpi5_launch.sh**: Launch helper for RPi5 (Site B, responder). Sets local/remote TUN IPs and peer transport IP, then starts the tunnel without `--initiator`, using a site-specific state file.
- **set_up_static_IP.sh**: Configures a static IPv4 address on `eth0` for direct laptop↔Raspberry Pi connections without DHCP. Uses NetworkManager `nmcli` to set manual IPv4, disables IPv6, restarts the connection, and prints status. Requires root and NetworkManager running; edit `STATIC_IP`, `NETMASK`, `LAPTOP_IP`, and `CONNECTION_NAME` before use.
- **README.md**: Project overview, security model, requirements, architecture, and file descriptions.

### Slot and key usage

- **Packets per slot (per direction)**: Each direction uses a slot’s key and nonce prefix for up to 1000 packets, then rotates to the next 120‑byte slot. Rotation is deterministic from the packet sequence number.
- **Nonce per message**: For every packet, a new 12‑byte nonce is constructed as `[8‑byte nonce_prefix from slot] + [4‑byte sequence]`, guaranteeing nonce uniqueness within the slot.
- **Independent directions**: A→B and B→A have independent sequences and rotate independently. The receiver derives the correct RX slot from the sequence carried in the packet header; no coordination messages are required.
- **Capacity formula**:
  - Slots = floor(PSK_file_bytes / 120)
  - Packets per direction = Slots × 1000
  - Packets total (both directions) ≈ 2 × Slots × 1000
  - Example (1 GiB = 1,073,741,824 bytes): Slots = 8,947,848 → ~8.95×10^9 packets per direction (~17.9×10^9 both directions)


## Deployment

### 1) Generate and distribute PSK

```bash
python3 psk_file_generator.py /tmp/psk.bin 1  # 1 GB example
sha256sum /tmp/psk.bin
```

- Copy the exact PSK file to both endpoints at `/mnt/secure/psk.bin`.
- Verify the SHA256 checksum matches on both sides (the generator writes `/tmp/psk.bin.sha256`).

### 2) Network setup (direct cable option)

- On Raspberry Pi 5:
  ```bash
  sudo bash set_up_static_IP.sh
  ```
  This sets `eth0` to `169.254.10.3/24` (no gateway).

- On Laptop (Site A):
  - Set the interface directly connected to the Pi to `169.254.10.2/24` (no gateway).

### 2a) Mounting the key directory (`/mnt/secure`)

`/mnt/secure` is where the PSK file (`psk.bin`) is read from. Depending on how you store key material, choose one of the following:

- Bind-mount an existing directory (recommended for a plain folder):
  ```bash
  sudo mkdir -p /mnt/secure
  sudo mount --bind /path/to/key_01 /mnt/secure
  # optional hardening
  sudo mount -o remount,bind,ro,nosuid,nodev,noexec /mnt/secure
  ```

- Loop-mount a filesystem image:
  ```bash
  sudo mkdir -p /mnt/secure
  sudo mount -o loop /path/to/key_01.img /mnt/secure
  # optional hardening
  sudo mount -o remount,ro,nosuid,nodev,noexec /mnt/secure
  ```

- Mount a removable drive (e.g., USB):
  ```bash
  lsblk   # identify device, e.g., /dev/sdb1
  sudo mkdir -p /mnt/secure
  sudo mount /dev/sdb1 /mnt/secure
  ```

- Or simply copy the PSK file (no mount):
  ```bash
  sudo mkdir -p /mnt/secure
  sudo cp /path/to/psk.bin /mnt/secure/
  ```

Notes:
- A plain `mount key_01 /mnt/secure` will fail: use `--bind` for directories.
- Verify the file is present: `ls -l /mnt/secure/psk.bin`.
- Verify checksum matches the generator's `.sha256` file before use.

### 3) Install runtime

- On RPi5 (Debian-based):
  ```bash
  sudo bash rpi5_deployment.sh
  ```

- On Laptop (Fedora/RHEL):
  ```bash
  sudo bash laptop_deployment.sh
  ```

Both scripts will:
- Create a venv at `/opt/psk-tunnel/venv` and install `cryptography` and `tqdm`.
- Install the runtime entry script to `/usr/local/bin/psk_tunnel.py` (from `core_protocol.py`).
- Ensure the TUN module is available for the current session.

### 4) Configure and start the tunnel

- On RPi5 (Site B / responder):
  - Edit `rpi5_launch.sh` and set:
    - `REMOTE_HOST="169.254.10.2"` (peer laptop IP)
    - `PSK_FILE="/mnt/secure/psk.bin"`
  - Start:
    ```bash
    sudo bash rpi5_launch.sh
    ```

- On Laptop (Site A / initiator):
  - Edit `laptop_launch.sh` and set:
    - `REMOTE_HOST="169.254.10.3"` (peer RPi IP)
    - `PSK_FILE="/mnt/secure/psk.bin"`
  - Start:
    ```bash
    sudo bash laptop_launch.sh
    ```

Start the responder first, then the initiator.

Note on addresses:
- `REMOTE_HOST` is always the peer's transport IP (the other machine on the link).
  - On Laptop (Site A), set `REMOTE_HOST` to the RPi's `169.254.10.3`.
  - On RPi (Site B), set `REMOTE_HOST` to the Laptop's `169.254.10.2`.
- `LOCAL_IP`/`REMOTE_IP` in the scripts are the TUN addresses:
  - Site A uses `LOCAL_IP=10.0.0.1`, `REMOTE_IP=10.0.0.2`.
  - Site B uses `LOCAL_IP=10.0.0.2`, `REMOTE_IP=10.0.0.1`.

### 5) Status and key usage

- At startup, a banner shows local/remote endpoints and role.
- Every 10 seconds, stats are printed (TX/RX packets/bytes, auth failures, replays).
- A progress bar shows PSK slot consumption with remaining slots and estimated remaining packets.

### 6) Stopping the tunnel

- Press Ctrl+C in the initiator or responder terminal, or send SIGINT/SIGTERM. State (PSK offset, sequences) is saved to `/var/lib/psk-tunnel/state_*.json`.

### 7) Performance tuning (network buffers)

- The tunnel uses larger UDP socket buffers by default (8 MB). To let those sizes take effect, raise kernel limits once per host:
  ```bash
  sudo bash tune_net_buffers.sh
  ```
  This sets `net.core.rmem_max/wmem_max` and defaults to reasonable values. Both deployment scripts call this if the script is present.

- You can verify current limits:
  ```bash
  sysctl -n net.core.rmem_default net.core.wmem_default net.core.rmem_max net.core.wmem_max
  ```

- Optional: if you see heavy reordering/latency on `eth0`, consider testing with GRO/LRO off:
  ```bash
  sudo ethtool -K eth0 gro off lro off
  ```

### 8) Replay handling (sliding window)

- The tunnel accepts out-of-order packets using a sliding replay window. This prevents dropping late-but-valid packets that often occur on multi-queue NICs or Wi‑Fi.
- Default window: `REPLAY_WINDOW = 4096` packets. Packets older than the window are dropped; duplicates within the window are rejected as replays.
- You can tune the window in `core_protocol.py` if your network reorders more or less aggressively. 

### 9) Hardware-backed identity (TPM/SE)

- **What**: Keep the device identity private key inside a TPM 2.0, secure element (e.g., ATECC608A), or a PKCS#11 token so the key is non‑exportable. Use it only to sign the identity‑binding handshake transcript.

- **Why**: Prevents key extraction from disk; enables strong device binding and straightforward revocation/pinning even if host storage is compromised.

- **Provisioning (one‑time)**:
  1) Generate the identity key inside the hardware (non‑exportable); export the public key.
  2) Compute `identity_id = first_8_bytes(SHA‑256(pubkey))` and pin it at the peer.
  3) Expose the key to the app via PKCS#11 (URI) or a TPM handle; store only the public key on disk.

- **Handshake use**:
  - Sender signs: context || header AAD || session_id || challenges; receiver verifies with the pinned public key and caches `(session_id → identity_id)`.
  - Optional mutual auth: responder returns a signature over both challenges to bind its identity too.

- **Optional attestation**:
  - TPM quote: include a quote over a fresh nonce and selected PCRs; receiver validates the quote and policy (measured boot).

- **Integration (Linux)**:
  - TPM: provision with `tpm2-tools`, expose via `tpm2-pkcs11` so userland can sign through PKCS#11.
  - Secure elements (e.g., ATECC608A): use vendor PKCS#11; configure token/slot and key label.
  - Application: perform signatures via PKCS#11 or a small helper service; keep peer public keys pinned in config.


- **Optional: hashed hardware serial as identity token**:
  - Read a stable hardware serial/UUID (e.g., `/sys/class/dmi/id/product_uuid`, `/sys/class/dmi/id/board_serial`, RPi: `/proc/device-tree/serial-number`).
  - Derive `identity_id` = first_8_or_16_bytes(SHA-256("psk-tunnel/v1" || deployment_salt || serial_bytes)). Use a per-deployment salt to avoid cross-deployment correlation.
  - Use this `identity_id` in the HELLO handshake and include it (or a short AAD tag derived from it) in DATA AAD after binding; maintain an allowlist on the peer.
  - Treat it as an identifier, not a secret. To prevent insider spoofing, pair it with a hardware-backed signature (preferred) or per-device HMAC proof in HELLO.
  - Privacy: the salted hash prevents raw serial leakage on the wire and across deployments; still avoid exposing unsalted serials in logs.

### Minimal design (PSK-only)
HELLO (sender → peer):
fields: version, role, random_nonce_A, identity_id
auth: HMAC-SHA256 over all fields using a “hello key” derived from the PSK (e.g., first slot’s B→A key material via HKDF with context “hello”)
WELCOME (peer → sender):
fields: random_nonce_A (echo), random_nonce_B, identity_id(peer)
auth: HMAC-SHA256 over all fields using the same hello key
Bind:
On success, cache (peer_ip, peer_port) → identity_id.
Optionally require identity_id to be in an allowlist.
Start normal DATA; no wire changes needed to data packets.

### Deriving the identity token (example)

```Python
import hashlib, os, pathlib

def read_serial_bytes() -> bytes:
    candidates = [
        "/proc/device-tree/serial-number",             # RPi
        "/sys/class/dmi/id/product_uuid",              # PC/server
        "/sys/class/dmi/id/board_serial",
    ]
    for p in candidates:
        try:
            data = pathlib.Path(p).read_bytes().strip()
            if data:
                return data
        except Exception:
            pass
    raise RuntimeError("No stable hardware serial found")

def derive_identity_id(deployment_salt: bytes, length: int = 8) -> bytes:
    serial = read_serial_bytes()
    digest = hashlib.sha256(b"psk-tunnel/v1" + deployment_salt + serial).digest()
    return digest[:length]  # 8 or 16 bytes
```

**Notes**: 
Use a per-deployment salt (identical on both peers) to prevent cross-deployment correlation.
Treat identity_id as an identifier, not a secret; HMAC in HELLO/WELCOME prevents spoofing without adding public keys.
Backward compatible: make the handshake required or optional via a flag; if disabled, current data path remains unchanged.

- **Limitations**:
  - A fully compromised host can request signatures at runtime (non‑exportable ≠ misuse‑proof), but cannot extract the key.
  - PQ: most TPM/SE do not yet support post‑quantum signature algorithms.


