#!/usr/bin/env python3
"""
Generate PSK file for pure PSK tunnel

Optionally supports deterministic generation for testing via --seed.
"""

import os
import hashlib
import hmac
import struct
from pathlib import Path

def _generate_deterministic_slot(seed: bytes, counter: int, slot_size: int) -> bytes:
    """
    Generate a deterministic slot of `slot_size` bytes using HMAC-SHA256
    with the provided seed and a counter. For testing only.
    """
    chunks = []
    needed = slot_size
    i = 0
    while needed > 0:
        msg = counter.to_bytes(8, 'big') + i.to_bytes(4, 'big')
        digest = hmac.new(seed, msg, hashlib.sha256).digest()
        take = min(len(digest), needed)
        chunks.append(digest[:take])
        needed -= take
        i += 1
    return b"".join(chunks)


def generate_psk_file(output_file: str, size_gb: int, seed: str | None):
    """
    Generate PSK file with structured key slots
    
    Each slot (120 bytes):
    - 16 bytes: Auth tag A→B (proves A has PSK)
    - 12 bytes: Nonce A→B
    - 32 bytes: Key A→B
    - 16 bytes: Auth tag B→A (proves B has PSK)
    - 12 bytes: Nonce B→A
    - 32 bytes: Key B→A
    """
    
    SLOT_SIZE = 120
    total_bytes = size_gb * 1024 * 1024 * 1024
    num_slots = total_bytes // SLOT_SIZE
    
    print(f"Generating {size_gb} GB PSK file...")
    if seed is not None:
        print("Mode: DETERMINISTIC (testing only) — using provided seed")
    print(f"Total slots: {num_slots:,}")
    print(f"Each slot provides: ~1000 packets of security")
    print(f"Total capacity: ~{num_slots * 1000:,} packets")
    print()
    
    with open(output_file, 'wb') as f:
        if seed is None:
            for i in range(num_slots):
                # Generate random key material
                slot_data = os.urandom(SLOT_SIZE)
                f.write(slot_data)
                if (i + 1) % 10000 == 0:
                    progress = (i + 1) * SLOT_SIZE / total_bytes * 100
                    print(f"Progress: {progress:.1f}% ({i+1:,} / {num_slots:,} slots)")
        else:
            seed_bytes = seed.encode('utf-8')
            for i in range(num_slots):
                slot_data = _generate_deterministic_slot(seed_bytes, i, SLOT_SIZE)
                f.write(slot_data)
                if (i + 1) % 10000 == 0:
                    progress = (i + 1) * SLOT_SIZE / total_bytes * 100
                    print(f"Progress: {progress:.1f}% ({i+1:,} / {num_slots:,} slots)")
    
    # Calculate checksum
    sha256 = hashlib.sha256()
    with open(output_file, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    
    checksum = sha256.hexdigest()
    
    print()
    print(f"✓ PSK file generated: {output_file}")
    print(f"  Size: {size_gb} GB")
    print(f"  Slots: {num_slots:,}")
    print(f"  SHA256: {checksum}")
    print()
    print("IMPORTANT: Copy this EXACT file to both endpoints")
    print("Verify SHA256 matches on both sides!")
    
    # Save checksum
    with open(f"{output_file}.sha256", 'w') as f:
        f.write(f"{checksum}  {Path(output_file).name}\n")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Generate PSK file for pure PSK tunnel')
    parser.add_argument('output_file', help='Output PSK file path')
    parser.add_argument('size_gb', type=int, help='File size in gigabytes')
    parser.add_argument('--seed', help='Deterministic generation seed (testing only)')

    args = parser.parse_args()

    if args.size_gb <= 0:
        raise ValueError('size_gb must be > 0')

    generate_psk_file(args.output_file, args.size_gb, args.seed)