"""VMess frame round-trip test — mirrors the real wire path.

Encodes frames with VmessStreamEncoder (server -> client direction), feeds them
to a VmessStreamDecoder (client -> server direction) using separate cipher
instances (as in the real code where req_cipher and resp_cipher are distinct),
splitting the wire stream at arbitrary boundaries like real WebSocket messages.

Exercises all option combos, both AEAD ciphers, multi-frame + split-frame +
padding + authenticated-length, the padding double-count fix, the _pending
hasSize fix, and the AEAD EOF sentinel.
"""
import os
import sys

sys.path.insert(0, "/Users/soheilforootan/Desktop/Claude Venv/RVG-main")

import pytest

from protocol.vmess.vmess import (
    VmessCipher,
    VmessStreamDecoder,
    VmessStreamEncoder,
    SEC_AES128_GCM,
    SEC_CHACHA20_POLY1305,
)


def _pair(key, iv, sec, cs, cm, gp, al):
    """Encoder + decoder backed by SEPARATE cipher instances (wire-accurate)."""
    enc_c = VmessCipher(sec, key, iv)
    dec_c = VmessCipher(sec, key, iv)
    enc = VmessStreamEncoder(enc_c, cs, cm, gp, al)
    dec = VmessStreamDecoder(dec_c, cs, cm, gp, al)
    return enc, dec


def _run(enc, dec, payloads, split_points):
    """Feed the whole wire stream into the decoder, splitting at arbitrary
    boundaries (simulating WebSocket messages arriving in pieces). Returns the
    concatenated decrypted payloads."""
    wire = b"".join(enc.encode_chunk(p) for p in payloads)
    wire += enc.encode_chunk(b"")   # EOF frame
    received = b""
    for pt in split_points:
        dec.feed(wire[:pt])
        wire = wire[pt:]
        for chunk in dec.try_decrypt_chunks():
            received += chunk
    dec.feed(wire)
    for chunk in dec.try_decrypt_chunks():
        received += chunk
    return received


def test_all_configs_split_roundtrip():
    payloads = [
        os.urandom(50),
        os.urandom(2000),
        os.urandom(17000),     # > CHUNK_MAX — old guard would have rejected
        os.urandom(70000),     # multi-frame (2 chunks)
        os.urandom(100),
    ]
    split_points = [3, 7, 509, 1749, 8493, 20001, 90000, 5, 333, 1]

    for sec in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
        for (cs, cm, gp, al) in (
            (True, False, False, False),
            (True, True, False, False),
            (True, True, True, False),   # global padding + masking
            (True, True, True, True),    # + authenticated length
            (True, True, False, True),   # auth_len + masking, no padding
        ):
            key, iv = os.urandom(16), os.urandom(16)
            enc, dec = _pair(key, iv, sec, cs, cm, gp, al)
            got = _run(enc, dec, payloads, split_points)
            expect = b"".join(payloads)
            assert got == expect, (
                f"mismatch sec={sec} opts=({cs},{cm},{gp},{al}) "
                f"got={len(got)} expect={len(expect)}"
            )


def test_single_frame_max_chunk():
    for sec in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
        key, iv = os.urandom(16), os.urandom(16)
        enc, dec = _pair(key, iv, sec, True, True, True, True)
        payload = os.urandom(16000)
        got = _run(enc, dec, [payload], [2, 4000])
        assert got == payload, f"single-frame roundtrip failed sec={sec}"


def test_incomplete_frame_no_mask_desync():
    """A partial frame must not consume the SHAKE/nonce stream (hasSize)."""
    key, iv = os.urandom(16), os.urandom(16)
    enc, dec = _pair(key, iv, SEC_AES128_GCM, True, True, True, True)

    p1, p2 = os.urandom(100), os.urandom(300)
    f1, f2 = enc.encode_chunk(p1), enc.encode_chunk(p2)

    # feed frame1 fully + only the 18-byte size field of frame2
    dec.feed(f1 + f2[:18])
    chunks = list(dec.try_decrypt_chunks())
    assert chunks == [p1], f"expected only p1, got {len(chunks)} chunks"

    dec.feed(f2[18:])
    chunks = list(dec.try_decrypt_chunks())
    assert chunks == [p2], f"expected p2, got {len(chunks)}"


def test_eof_frame_authlen():
    """encode_chunk(b'') under auth_len must decode as EOF, not crash."""
    for sec in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
        key, iv = os.urandom(16), os.urandom(16)
        enc, dec = _pair(key, iv, sec, True, True, True, True)
        f = enc.encode_chunk(b"")
        dec.feed(f)
        assert dec.try_decrypt_chunks() == [], f"EOF decode failed sec={sec}"
