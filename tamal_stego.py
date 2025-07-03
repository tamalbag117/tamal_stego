#!/usr/bin/env python3
"""
tamal‑stego – lightweight steganography CLI
===========================================
Hide any file inside loss‑less images (PNG/BMP/TIFF) with modern crypto.

Crypto engines
--------------
* fernet  : Fernet‑AES‑GCM (passphrase, default)
* aesgcm  : Raw AES‑256‑GCM  (passphrase)
* kyber   : Kyber768 KEM → AES‑256‑GCM hybrid (requires `pqcrypto`)

Stego back‑end
--------------
* lsb     : Least‑significant‑bit substitution on RGB
"""
from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path
from typing import Iterator

from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:
    from pqcrypto.kem import kyber768
except ImportError:
    kyber768 = None  # Kyber disabled if pqcrypto isn’t available

_BANNER = r"""
████████╗ █████╗ ███╗   ███╗ █████╗ ██╗      ███████╗████████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔══██╗████╗ ████║██╔══██╗██║      ██╔════╝╚══██╔══╝██╔════╝ ██╔════╝ 
   ██║   ███████║██╔████╔██║███████║██║█████╗█████╗     ██║   ██║  ███╗██║  ███╗
   ██║   ██╔══██║██║╚██╔╝██║██╔══██║██║╚════╝██╔══╝     ██║   ██║   ██║██║   ██║
   ██║   ██║  ██║██║ ╚═╝ ██║██║  ██║███████╗ ███████╗   ██║   ╚██████╔╝╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ 
"""

_SALT_SIZE        = 16
_NONCE_SIZE_GCM   = 12
_HEADER_FERNET    = b"F"
_HEADER_AESGCM    = b"G"
_HEADER_KYBER     = b"K"

# ── Key derivation ────────────────────────────────────────────────────────────
def _derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    kdf = Scrypt(salt=salt, length=length, n=2**15, r=8, p=1,
                 backend=default_backend())
    return kdf.derive(password.encode())

# ── Pass‑phrase encryption engines ────────────────────────────────────────────
def _encrypt_passphrase(data: bytes, password: str, engine: str) -> bytes:
    salt = os.urandom(_SALT_SIZE)
    key  = _derive_key(password, salt)
    if engine == "fernet":
        fkey   = base64.urlsafe_b64encode(key)
        cipher = Fernet(fkey).encrypt(data)
        return _HEADER_FERNET + salt + cipher
    if engine == "aesgcm":
        nonce  = os.urandom(_NONCE_SIZE_GCM)
        cipher = AESGCM(key).encrypt(nonce, data, b"")
        return _HEADER_AESGCM + salt + nonce + cipher
    raise ValueError("Unknown passphrase engine.")

def _decrypt_passphrase(blob: bytes, password: str) -> bytes:
    head = blob[:1]
    if head == _HEADER_FERNET:
        salt   = blob[1:1+_SALT_SIZE]
        cipher = blob[1+_SALT_SIZE:]
        fkey   = base64.urlsafe_b64encode(_derive_key(password, salt))
        return Fernet(fkey).decrypt(cipher)
    if head == _HEADER_AESGCM:
        salt  = blob[1:1+_SALT_SIZE]
        nonce = blob[1+_SALT_SIZE:1+_SALT_SIZE+_NONCE_SIZE_GCM]
        cipher= blob[1+_SALT_SIZE+_NONCE_SIZE_GCM:]
        key   = _derive_key(password, salt)
        return AESGCM(key).decrypt(nonce, cipher, b"")
    raise ValueError("Unknown passphrase blob header.")

# ── Kyber hybrid (optional) ───────────────────────────────────────────────────
def _encrypt_kyber(data: bytes, pubkey_path: Path) -> bytes:
    if kyber768 is None:
        raise RuntimeError("pqcrypto not installed – cannot use Kyber.")
    ct, ss = kyber768.encrypt(pubkey_path.read_bytes())
    key    = ss[:32]
    nonce  = os.urandom(_NONCE_SIZE_GCM)
    cipher = AESGCM(key).encrypt(nonce, data, b"")
    return _HEADER_KYBER + len(ct).to_bytes(2, "big") + ct + nonce + cipher

def _decrypt_kyber(blob: bytes, seckey_path: Path) -> bytes:
    if kyber768 is None:
        raise RuntimeError("pqcrypto not installed – cannot use Kyber.")
    ct_len = int.from_bytes(blob[1:3], "big")
    ct     = blob[3:3+ct_len]
    nonce  = blob[3+ct_len:3+ct_len+_NONCE_SIZE_GCM]
    cipher = blob[3+ct_len+_NONCE_SIZE_GCM:]
    ss     = kyber768.decrypt(ct, seckey_path.read_bytes())
    key    = ss[:32]
    return AESGCM(key).decrypt(nonce, cipher, b"")

# ── LSB steganography ─────────────────────────────────────────────────────────
class StegoLSB:
    name = "lsb"
    @staticmethod
    def _bytes_to_bits(data: bytes) -> Iterator[int]:
        for b in data:
            for i in range(7, -1, -1):
                yield (b >> i) & 1
    @staticmethod
    def _bits_to_bytes(bits: Iterator[int], n: int) -> bytes:
        out, acc = bytearray(), 0
        for i, bit in enumerate(bits):
            acc = (acc << 1) | bit
            if (i + 1) % 8 == 0:
                out.append(acc); acc = 0
                if len(out) == n: break
        return bytes(out)

    def encode(self, cover: Path, payload: bytes) -> Image.Image:
        img = Image.open(cover).convert("RGB")
        w, h = img.size
        if len(payload)*8 > w*h*3:
            raise ValueError("Cover too small for payload.")
        bits = self._bytes_to_bits(payload)
        pixels = img.load()
        done = False
        for y in range(h):
            for x in range(w):
                chan = list(pixels[x, y])
                for i in range(3):
                    try:
                        chan[i] = (chan[i] & ~1) | next(bits)
                    except StopIteration:
                        done = True; break
                pixels[x, y] = tuple(chan)
                if done: break
            if done: break
        return img

    def decode(self, stego: Path) -> bytes:
        img = Image.open(stego).convert("RGB")
        w, h = img.size
        pixels = img.load()
        bits   = (pixels[i % w, i // w][j] & 1
                  for i in range(w*h) for j in range(3))
        length = int.from_bytes(self._bits_to_bytes(bits, 4), "big")
        return self._bits_to_bytes(bits, length)

ALGORITHMS = {"lsb": StegoLSB()}

def _save_image(img: Image.Image, out: Path):
    fmt = {"jpg": "JPEG", "jpeg": "JPEG", "png": "PNG", "bmp": "BMP", "tiff": "TIFF"}
    img.save(out, fmt.get(out.suffix.lstrip(".").lower(), "PNG"))

# ── Wrapper commands ─────────────────────────────────────────────────────────-
def _encode_cmd(a):
    data = Path(a.input).read_bytes()
    if a.engine == "kyber":
        blob = _encrypt_kyber(data, Path(a.pubkey))
    else:
        if not a.password:
            raise ValueError("Password required for passphrase engines.")
        blob = _encrypt_passphrase(data, a.password, a.engine)
    payload = len(blob).to_bytes(4, "big") + blob
    img = ALGORITHMS[a.algorithm].encode(Path(a.cover), payload)
    _save_image(img, Path(a.output))
    print(_BANNER)
    print(f"[tamal‑stego] Embedded '{a.input}' → '{a.output}' | algo={a.algorithm} | enc={a.engine}")

def _decode_cmd(a):
    payload = ALGORITHMS[a.algorithm].decode(Path(a.input))
    if a.engine == "kyber":
        plaintext = _decrypt_kyber(payload, Path(a.seckey))
    else:
        if not a.password:
            raise ValueError("Password required for passphrase engines.")
        plaintext = _decrypt_passphrase(payload, a.password)
    Path(a.output).write_bytes(plaintext)
    print(_BANNER)
    print(f"[tamal‑stego] Extracted → '{a.output}' | algo={a.algorithm}")

def _genkeys_cmd(a):
    if kyber768 is None:
        raise RuntimeError("pqcrypto not installed – cannot generate Kyber keys.")
    pub, sec = kyber768.generate_keypair()
    Path(a.output + ".kyber.pub").write_bytes(pub)
    Path(a.output + ".kyber.sec").write_bytes(sec)
    print(f"[tamal‑stego] Kyber keys written → {a.output}.kyber.*")

# ── CLI builder ───────────────────────────────────────────────────────────────
def _cli():
    p = argparse.ArgumentParser("tamal‑stego",
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("-a", "--algorithm", default="lsb",
                   choices=ALGORITHMS.keys(), help="Steganography algorithm")
    p.add_argument("-e", "--engine", default="fernet",
                   choices=("fernet", "aesgcm", "kyber"),
                   help="Encryption engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encode", help="Encrypt + embed")
    enc.add_argument("-c", "--cover",   required=True, help="Cover image")
    enc.add_argument("-i", "--input",   required=True, help="File to hide")
    enc.add_argument("-o", "--output",  required=True, help="Output image")
    enc.add_argument("-p", "--password", help="Passphrase (fernet/aesgcm)")
    enc.add_argument("-K", "--pubkey",   help="Kyber public key")
    enc.set_defaults(func=_encode_cmd)

    dec = sub.add_parser("decode", help="Extract + decrypt")
    dec.add_argument("-i", "--input",  required=True, help="Stego image")
    dec.add_argument("-o", "--output", required=True, help="Output file")
    dec.add_argument("-p", "--password", help="Passphrase (fernet/aesgcm)")
    dec.add_argument("-S", "--seckey",   help="Kyber secret key")
    dec.set_defaults(func=_decode_cmd)

    gk = sub.add_parser("genkeys", help="Generate Kyber key pair")
    gk.add_argument("-o", "--output", required=True, help="Key file prefix")
    gk.set_defaults(func=_genkeys_cmd)
    return p

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        args = _cli().parse_args()
        args.func(args)
    except Exception as e:
        print(f"[tamal‑stego] Error: {e}", file=sys.stderr)
        sys.exit(1)
