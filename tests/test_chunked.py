"""Round-trip tests for the chunked encoder/decoder (no device needed)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from miband2021.chunked import ChunkedDecoder, ChunkedEncoder  # noqa: E402

ok = True


def check(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name)
    ok = ok and cond


def round_trip(payload, endpoint=0x0082, encrypt=False, mtu=247):
    enc = ChunkedEncoder(mtu)
    dec = ChunkedDecoder(force_2021=True)
    if encrypt:
        key = os.urandom(16)
        enc.set_encryption(0x11223344, key)
        dec.set_encryption(key)
    chunks = enc.write(endpoint, payload, extended_flags=True, encrypt=encrypt)
    msg = None
    for chunk in chunks:
        _, msg = dec.decode(chunk)
    return chunks, msg


# small unencrypted message
chunks, msg = round_trip(b"\x04\x02\x00\x02" + os.urandom(48))
check("plaintext round-trip", msg is not None and msg.endpoint == 0x0082
      and msg.payload.startswith(b"\x04\x02\x00\x02"))

# encrypted message (also exercises multi-chunk + length/CRC framing)
body = os.urandom(300)
chunks, msg = round_trip(body, encrypt=True, mtu=23)  # tiny MTU -> many chunks
check("encrypted multi-chunk round-trip", msg is not None and msg.payload == body)
check("multi-chunk produced several chunks", len(chunks) > 1)
check("last chunk requests ack", bool(chunks[-1][1] & 0x04))

# first chunk header must carry length + endpoint
first = chunks[0]
length = int.from_bytes(first[5:9], "little")
endpoint = int.from_bytes(first[9:11], "little")
check("first chunk length is the plaintext length", length == len(body))
check("first chunk endpoint correct", endpoint == 0x0082)

print("OK" if ok else "FAILURES")
sys.exit(0 if ok else 1)