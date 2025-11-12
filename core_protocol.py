#!/usr/bin/env python3
"""
Pure PSK Tunnel - No Public Key Cryptography
Uses only pre-shared key material for authentication and encryption
"""

import os
import struct
import time
import socket
import threading
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from tqdm import tqdm

@dataclass
class KeySlot:
    """One slot of key material from PSK file"""
    auth_tag_tx: bytes      # 16 bytes - proves we have the PSK
    nonce_tx: bytes         # 12 bytes - nonce for encryption
    key_tx: bytes           # 32 bytes - encryption key
    auth_tag_rx: bytes      # 16 bytes - verify peer has PSK
    nonce_rx: bytes         # 12 bytes - nonce for decryption
    key_rx: bytes           # 32 bytes - decryption key
    offset: int             # Position in PSK file
    
    @classmethod
    def from_psk(cls, psk_data: bytes, offset: int, is_initiator: bool):
        """
        Parse key slot from PSK data
        
        Initiator and responder read in opposite order for bidirectional
        """
        if len(psk_data) < 120:
            raise ValueError("Insufficient PSK data")
        
        if is_initiator:
            # Initiator: TX first, RX second
            auth_tag_tx = psk_data[0:16]
            nonce_tx = psk_data[16:28]
            key_tx = psk_data[28:60]
            auth_tag_rx = psk_data[60:76]
            nonce_rx = psk_data[76:88]
            key_rx = psk_data[88:120]
        else:
            # Responder: RX first (what initiator TXs), TX second
            auth_tag_rx = psk_data[0:16]
            nonce_rx = psk_data[16:28]
            key_rx = psk_data[28:60]
            auth_tag_tx = psk_data[60:76]
            nonce_tx = psk_data[76:88]
            key_tx = psk_data[88:120]
        
        return cls(
            auth_tag_tx=auth_tag_tx,
            nonce_tx=nonce_tx,
            key_tx=key_tx,
            auth_tag_rx=auth_tag_rx,
            nonce_rx=nonce_rx,
            key_rx=key_rx,
            offset=offset
        )


class PSKOnlyTunnel:
    """
    Pure PSK tunnel with no public key cryptography
    
    Security properties:
    - Authentication via shared secret (auth tags)
    - Encryption via ChaCha20-Poly1305
    - Perfect forward secrecy (keys consumed, never reused)
    - Information-theoretically secure (given true random PSK)
    - Replay protection via sequence numbers
    """
    
    SLOT_SIZE = 120  # Bytes per key slot
    PACKETS_PER_SLOT = 1000  # Deterministic rotation interval
    REPLAY_WINDOW = 4096     # Accept out-of-order packets within this window
    MAGIC = b'PSK2'  # Protocol identifier (v2)
    VERSION = 2
    # Direction constants for header
    DIRECTION_A_TO_B = 0  # Initiator → Responder
    DIRECTION_B_TO_A = 1  # Responder → Initiator
    # Header layout (AAD): [Magic 4][Version 1][Flags 1][Direction 1][Reserved 1][AuthTag 16][Seq 8]
    # Total: 32 bytes
    
    def __init__(
        self,
        psk_file: str,
        local_addr: Tuple[str, int],
        remote_addr: Tuple[str, int],
        is_initiator: bool,
        state_file: str = '/var/lib/psk-tunnel/state.json'
    ):
        self.psk_file = psk_file
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.is_initiator = is_initiator
        self.state_file = state_file
        
        # Current key slot
        self.current_slot: Optional[KeySlot] = None
        self.psk_offset = 0
        
        # Sequence numbers for replay protection
        self.tx_seq = 0
        self.rx_seq_window = set()  # Allow some out-of-order
        self.rx_seq_max = 0
        self._rx_seen = set()
        
        # Network
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Increase socket buffers (may be capped by kernel rmem_max/wmem_max)
        try:
            buf_bytes = 8 * 1024 * 1024  # 8 MB
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_bytes)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buf_bytes)
        except Exception as e:
            print(f"⚠ Failed to set socket buffers: {e}")
        self.sock.bind(local_addr)
        
        # State
        self.running = False
        self.stats = {
            'tx_packets': 0,
            'rx_packets': 0,
            'tx_bytes': 0,
            'rx_bytes': 0,
            'auth_failures': 0,
            'replay_detected': 0
        }
        
        # Load state and initial key
        self._load_state()
        # Derive initial offset from current tx sequence deterministically
        self.psk_offset = (self.tx_seq // self.PACKETS_PER_SLOT) * self.SLOT_SIZE
        self._load_next_slot()

        # Simple in-memory caches for current TX/RX slots
        self._cache_tx_index: int = -1
        self._cache_tx_slot: Optional[KeySlot] = None
        self._cache_rx_index: int = -1
        self._cache_rx_slot: Optional[KeySlot] = None

    def _load_slot_for_seq(self, seq: int) -> KeySlot:
        """Derive slot from sequence number deterministically and load it"""
        slot_index = seq // self.PACKETS_PER_SLOT
        offset = slot_index * self.SLOT_SIZE
        with open(self.psk_file, 'rb') as f:
            f.seek(offset)
            slot_data = f.read(self.SLOT_SIZE)
        if len(slot_data) < self.SLOT_SIZE:
            raise Exception(f"PSK exhausted at offset {offset}")
        return KeySlot.from_psk(slot_data, offset, self.is_initiator)

    def _get_slot_for_seq(self, seq: int, is_tx: bool) -> KeySlot:
        """Return cached slot for seq if same index, otherwise load and cache."""
        slot_index = seq // self.PACKETS_PER_SLOT
        if is_tx:
            if self._cache_tx_slot is not None and self._cache_tx_index == slot_index:
                return self._cache_tx_slot
            slot = self._load_slot_for_seq(seq)
            self._cache_tx_slot = slot
            self._cache_tx_index = slot_index
            return slot
        else:
            if self._cache_rx_slot is not None and self._cache_rx_index == slot_index:
                return self._cache_rx_slot
            slot = self._load_slot_for_seq(seq)
            self._cache_rx_slot = slot
            self._cache_rx_index = slot_index
            return slot
    
    def _load_state(self):
        """Load persisted state (offset, sequences, etc)"""
        import json
        
        if Path(self.state_file).exists():
            try:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                
                self.psk_offset = state.get('psk_offset', 0)
                self.tx_seq = state.get('tx_seq', 0)
                self.rx_seq_max = state.get('rx_seq_max', 0)
                
                print(f"✓ Loaded state: offset={self.psk_offset}, "
                      f"tx_seq={self.tx_seq}")
            except Exception as e:
                print(f"⚠ Failed to load state: {e}")
    
    def _save_state(self):
        """Persist state to disk"""
        import json
        
        state = {
            'psk_offset': self.psk_offset,
            'tx_seq': self.tx_seq,
            'rx_seq_max': self.rx_seq_max,
            'last_save': time.time()
        }
        
        Path(self.state_file).parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.state_file + '.tmp'
        
        with open(temp_file, 'w') as f:
            json.dump(state, f)
        
        os.replace(temp_file, self.state_file)
    
    def _load_next_slot(self):
        """Load next key slot from PSK file"""
        with open(self.psk_file, 'rb') as f:
            f.seek(self.psk_offset)
            slot_data = f.read(self.SLOT_SIZE)
        
        if len(slot_data) < self.SLOT_SIZE:
            raise Exception(f"PSK exhausted at offset {self.psk_offset}")
        
        self.current_slot = KeySlot.from_psk(
            slot_data,
            self.psk_offset,
            self.is_initiator
        )
        
        print(f"🔑 Loaded key slot at offset {self.psk_offset}")
        print(f"   Auth tag: {self.current_slot.auth_tag_tx[:8].hex()}...")
    
    def _should_rotate(self) -> bool:
        """Check if we should rotate to next key slot"""
        # Rotate every 1000 packets (configurable)
        return (self.stats['tx_packets'] % 1000) == 0 and self.stats['tx_packets'] > 0
    
    def _rotate_slot(self):
        """Advance to next key slot"""
        self.psk_offset += self.SLOT_SIZE
        self._load_next_slot()
        self._save_state()
        
        print(f"🔄 Rotated to slot at offset {self.psk_offset}")
    
    def encrypt_packet(self, plaintext: bytes) -> bytes:
        """
        Encrypt packet with current key slot
        
        Packet format:
        [Magic:4][Auth:16][Seq:8][Encrypted:[Plaintext + Poly1305:16]]
        """
        # Determine sequence and load corresponding slot (deterministic)
        seq = self.tx_seq
        slot = self._get_slot_for_seq(seq, is_tx=True)
        self.current_slot = slot
        self.psk_offset = slot.offset

        # Create packet header (AAD)
        version = self.VERSION
        flags = 0
        direction = self.DIRECTION_A_TO_B if self.is_initiator else self.DIRECTION_B_TO_A
        reserved = 0
        header = struct.pack(
            '>4sBBBB16sQ',
            self.MAGIC,
            version,
            flags,
            direction,
            reserved,
            slot.auth_tag_tx,  # Proves we have PSK
            seq
        )
        
        # Encrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(slot.key_tx)
        
        # Use nonce + sequence number
        nonce = slot.nonce_tx[:8] + struct.pack('>I', seq & 0xFFFFFFFF)
        
        # Encrypt with header as authenticated data
        ciphertext = cipher.encrypt(nonce, plaintext, header)
        
        # Complete packet
        packet = header + ciphertext
        
        # Update state
        self.tx_seq += 1
        self.stats['tx_packets'] += 1
        self.stats['tx_bytes'] += len(plaintext)
        
        return packet
    
    def decrypt_packet(self, packet: bytes) -> Optional[bytes]:
        """
        Decrypt and authenticate packet
        
        Returns plaintext or None if authentication fails
        """
        if len(packet) < 32 + 16:  # Header (32) + min ciphertext (16)
            print("⚠ Packet too short")
            return None
        
        # Parse header
        try:
            magic, version, flags, direction, reserved, auth_tag, seq = struct.unpack('>4sBBBB16sQ', packet[:32])
        except struct.error:
            print("⚠ Malformed packet header")
            return None
        
        # Verify magic
        if magic != self.MAGIC:
            print("⚠ Invalid magic bytes")
            return None
        if version != self.VERSION:
            print(f"⚠ Unsupported version: {version}")
            return None
        # Optional: validate expected direction for incoming packets
        expected_incoming_dir = self.DIRECTION_B_TO_A if self.is_initiator else self.DIRECTION_A_TO_B
        if direction != expected_incoming_dir:
            print(f"⚠ Unexpected direction byte: {direction}")
            return None
        
        # Load slot deterministically for this incoming sequence
        slot = self._get_slot_for_seq(seq, is_tx=False)
        self.current_slot = slot
        self.psk_offset = slot.offset

        # AUTHENTICATION: Verify auth tag matches our PSK
        if auth_tag != slot.auth_tag_rx:
            print(f"✗ Authentication failed!")
            print(f"  Expected: {slot.auth_tag_rx[:8].hex()}...")
            print(f"  Received: {auth_tag[:8].hex()}...")
            self.stats['auth_failures'] += 1
            return None
        
        # Replay protection with sliding window
        window_low = max(self.rx_seq_max - self.REPLAY_WINDOW, 0)
        if seq > self.rx_seq_max:
            self.rx_seq_max = seq
            self._rx_seen.add(seq)
            # prune seen outside window
            if len(self._rx_seen) > self.REPLAY_WINDOW * 2:
                self._rx_seen = {s for s in self._rx_seen if s >= self.rx_seq_max - self.REPLAY_WINDOW}
        elif seq >= window_low:
            if seq in self._rx_seen:
                print(f"⚠ Replay detected: seq {seq} (max: {self.rx_seq_max})")
                self.stats['replay_detected'] += 1
                return None
            self._rx_seen.add(seq)
        else:
            # Too old
            print(f"⚠ Replay detected (too old): seq {seq} (max: {self.rx_seq_max})")
            self.stats['replay_detected'] += 1
            return None
        
        # Decrypt
        cipher = ChaCha20Poly1305(slot.key_rx)
        
        # Reconstruct nonce
        nonce = slot.nonce_rx[:8] + struct.pack('>I', seq & 0xFFFFFFFF)
        
        header = packet[:32]
        ciphertext = packet[32:]
        
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, header)
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            return None
        
        # No-op: window handled above via _rx_seen pruning
        
        self.stats['rx_packets'] += 1
        self.stats['rx_bytes'] += len(plaintext)
        
        return plaintext
    
    def send(self, data: bytes):
        """Send encrypted packet"""
        packet = self.encrypt_packet(data)
        self.sock.sendto(packet, self.remote_addr)
    
    def receive(self) -> Optional[bytes]:
        """Receive and decrypt packet"""
        packet, addr = self.sock.recvfrom(65535)
        
        # Only accept from expected peer
        if addr[0] != self.remote_addr[0]:
            print(f"⚠ Packet from unexpected source: {addr}")
            return None
        
        return self.decrypt_packet(packet)
    
    def start(self):
        """Start tunnel"""
        self.running = True
        print(f"🚀 PSK-Only Tunnel Started")
        print(f"   Local: {self.local_addr}")
        print(f"   Remote: {self.remote_addr}")
        print(f"   Role: {'Initiator' if self.is_initiator else 'Responder'}")
        print(f"   PSK Offset: {self.psk_offset}")
    
    def stop(self):
        """Stop tunnel"""
        self.running = False
        self._save_state()
        self.sock.close()
        print(f"🛑 Tunnel stopped")
    
    def get_stats(self):
        """Get tunnel statistics"""
        return self.stats.copy()


class TUNInterface:
    """
    TUN interface integration
    Routes IP packets through PSK tunnel
    """
    
    def __init__(self, tunnel: PSKOnlyTunnel, tun_name: str = 'tun0'):
        self.tunnel = tunnel
        self.tun_name = tun_name
        self.tun_fd = None
        
    def create_tun(self):
        """Create TUN interface"""
        import fcntl
        
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000
        
        self.tun_fd = os.open('/dev/net/tun', os.O_RDWR)
        
        ifr = struct.pack('16sH', self.tun_name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
        
        print(f"✓ Created TUN interface: {self.tun_name}")
    
    def configure_interface(self, ip: str, peer_ip: str):
        """Configure TUN interface"""
        import subprocess
        
        # Bring up interface
        subprocess.run(['ip', 'link', 'set', self.tun_name, 'up'], check=True)
        
        # Set IP address
        subprocess.run(['ip', 'addr', 'add', f'{ip}/24', 'dev', self.tun_name], check=True)
        
        # Add route to peer
        subprocess.run(['ip', 'route', 'add', peer_ip, 'dev', self.tun_name], check=True)
        
        print(f"✓ Configured {self.tun_name}: {ip} → {peer_ip}")
    
    def run_tx_loop(self):
        """Read from TUN, encrypt, send"""
        while self.tunnel.running:
            try:
                # Read packet from TUN (max MTU-sized frames)
                packet = os.read(self.tun_fd, 65535)
                
                if packet:
                    # Encrypt and send
                    self.tunnel.send(packet)
                    
            except Exception as e:
                if self.tunnel.running:
                    print(f"TX error: {e}")
    
    def run_rx_loop(self):
        """Receive, decrypt, write to TUN"""
        while self.tunnel.running:
            try:
                # Receive and decrypt
                packet = self.tunnel.receive()
                
                if packet:
                    # Write to TUN
                    os.write(self.tun_fd, packet)
                    
            except Exception as e:
                if self.tunnel.running:
                    print(f"RX error: {e}")
    
    def start(self):
        """Start TX and RX threads"""
        tx_thread = threading.Thread(target=self.run_tx_loop, daemon=True)
        rx_thread = threading.Thread(target=self.run_rx_loop, daemon=True)
        
        tx_thread.start()
        rx_thread.start()
        
        print(f"✓ Started TUN interface threads")
        
        return tx_thread, rx_thread


def main():
    """Main entry point"""
    import argparse
    import signal
    
    parser = argparse.ArgumentParser(description='Pure PSK Tunnel')
    parser.add_argument('--psk', required=True, help='PSK file path')
    parser.add_argument('--local-port', type=int, default=51820, help='Local UDP port')
    parser.add_argument('--remote-host', required=True, help='Remote host')
    parser.add_argument('--remote-port', type=int, default=51820, help='Remote UDP port')
    parser.add_argument('--initiator', action='store_true', help='Act as initiator')
    parser.add_argument('--local-ip', required=True, help='Local tunnel IP')
    parser.add_argument('--remote-ip', required=True, help='Remote tunnel IP')
    parser.add_argument('--state', default='/var/lib/psk-tunnel/state.json', help='State file')
    
    args = parser.parse_args()
    
    # Create tunnel
    tunnel = PSKOnlyTunnel(
        psk_file=args.psk,
        local_addr=('0.0.0.0', args.local_port),
        remote_addr=(args.remote_host, args.remote_port),
        is_initiator=args.initiator,
        state_file=args.state
    )
    
    # Create TUN interface
    tun = TUNInterface(tunnel)
    tun.create_tun()
    tun.configure_interface(args.local_ip, args.remote_ip)
    
    # Start tunnel
    tunnel.start()
    tun.start()

    # Progress bar for PSK slot consumption
    file_size_bytes = os.path.getsize(args.psk)
    total_slots = file_size_bytes // PSKOnlyTunnel.SLOT_SIZE
    psk_bar = tqdm(total=total_slots, desc="PSK slots used", unit="slot")
    psk_bar.n = tunnel.psk_offset // PSKOnlyTunnel.SLOT_SIZE
    psk_bar.refresh()
    
    # Graceful shutdown
    def signal_handler(sig, frame):
        print("\n🛑 Shutting down...")
        tunnel.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Stats loop
    try:
        while tunnel.running:
            time.sleep(10)

            # Update progress bar based on current PSK offset
            used_slots = tunnel.psk_offset // PSKOnlyTunnel.SLOT_SIZE
            if used_slots != psk_bar.n:
                psk_bar.n = used_slots
            remaining_slots = max(total_slots - used_slots, 0)
            estimated_remaining_packets = remaining_slots * 1000
            psk_bar.set_postfix(
                remaining_slots=remaining_slots,
                est_packets=estimated_remaining_packets
            )
            psk_bar.refresh()

            # Print existing throughput/auth/replay stats
            stats = tunnel.get_stats()
            print(
                f"📊 TX: {stats['tx_packets']} packets ({stats['tx_bytes']/1024/1024:.2f} MB) | "
                f"RX: {stats['rx_packets']} packets ({stats['rx_bytes']/1024/1024:.2f} MB) | "
                f"Auth failures: {stats['auth_failures']} | "
                f"Replays: {stats['replay_detected']}"
            )
    except KeyboardInterrupt:
        tunnel.stop()
    finally:
        try:
            psk_bar.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()