"""Huami "2021" chunked transport (encoder + decoder).

Python port of Gadgetbridge ``Huami2021ChunkedEncoder`` /
``Huami2021ChunkedDecoder``.

Wire format of one chunk::

    byte 0       0x03 (chunk marker)
    byte 1       flags: 0x01 first | 0x02 last | 0x04 ack-req | 0x08 encrypted
    byte 2       0x00 when the extended header is in use, else part of handle
    byte 3       write handle            (extended)  /  byte 2 (non-extended)
    byte 4       chunk counter           (extended)  /  byte 3 (non-extended)
    ...          first chunk only: uint32 LE total length, uint16 LE endpoint
    ...          payload

The "extended header" is used by the 2021 protocol (``force_new_protocol``).
"""

from __future__ import annotations

from .crypto import aes_ecb_decrypt, aes_ecb_encrypt, calc_max_write_chunk, crc32

CHUNK_MARKER = 0x03
ACK_MARKER = 0x04

FLAG_FIRST = 0x01
FLAG_LAST = 0x02
FLAG_ACK = 0x04
FLAG_ENCRYPTED = 0x08


class ChunkedEncoder:
    def __init__(self, mtu: int = 247):
        self.mtu = mtu
        self.write_handle = 0
        self.encrypted_seq = 0
        self.session_key: bytes | None = None

    def set_encryption(self, encrypted_seq: int, session_key: bytes) -> None:
        self.encrypted_seq = encrypted_seq
        self.session_key = session_key

    def reset(self) -> None:
        self.write_handle = 0
        self.encrypted_seq = 0

    def write(self, endpoint: int, data: bytes,
              extended_flags: bool = True, encrypt: bool = False) -> list[bytes]:
        """Encode ``data`` for ``endpoint`` into a list of chunk byte strings."""
        if encrypt and self.session_key is None:
            raise RuntimeError("cannot encrypt without a shared session key")

        self.write_handle = (self.write_handle + 1) & 0xFF
        length = len(data)
        remaining = length
        count = 0
        header_size = 10 + (1 if extended_flags else 0)

        if extended_flags and encrypt:
            message_key = bytes(self.session_key[i] ^ self.write_handle for i in range(16))
            encrypted_length = length + 8
            overflow = encrypted_length % 16
            if overflow:
                encrypted_length += 16 - overflow
            payload = bytearray(encrypted_length)
            payload[:length] = data
            payload[length:length + 4] = self.encrypted_seq.to_bytes(4, "little")
            self.encrypted_seq = (self.encrypted_seq + 1) & 0xFFFFFFFF
            checksum = crc32(bytes(payload[:length + 4]))
            payload[length + 4:length + 8] = checksum.to_bytes(4, "little")
            remaining = encrypted_length
            data_to_send = aes_ecb_encrypt(bytes(payload), message_key)
        else:
            data_to_send = bytes(data)

        chunks: list[bytes] = []
        while remaining > 0:
            max_chunk_length = calc_max_write_chunk(self.mtu) - header_size
            copy_bytes = min(remaining, max_chunk_length)
            chunk = bytearray(copy_bytes + header_size)

            flags = 0
            if encrypt:
                flags |= FLAG_ENCRYPTED
            if count == 0:
                flags |= FLAG_FIRST
                i = 4 + (1 if extended_flags else 0)
                chunk[i:i + 4] = length.to_bytes(4, "little")
                i += 4
                chunk[i:i + 2] = (endpoint & 0xFFFF).to_bytes(2, "little")
                i += 2
            if remaining <= max_chunk_length:
                flags |= FLAG_LAST | FLAG_ACK

            chunk[0] = CHUNK_MARKER
            chunk[1] = flags
            if extended_flags:
                chunk[2] = 0
                chunk[3] = self.write_handle
                chunk[4] = count
            else:
                chunk[2] = self.write_handle
                chunk[3] = count

            start = len(data_to_send) - remaining
            chunk[header_size:header_size + copy_bytes] = data_to_send[start:start + copy_bytes]
            chunks.append(bytes(chunk))
            remaining -= copy_bytes
            header_size = 4 + (1 if extended_flags else 0)
            count += 1
        return chunks


class DecodedMessage:
    def __init__(self, endpoint: int, payload: bytes):
        self.endpoint = endpoint
        self.payload = payload

    def __repr__(self):
        return "DecodedMessage(endpoint=0x%04x, payload=%s)" % (self.endpoint, self.payload.hex())


class ChunkedDecoder:
    def __init__(self, force_2021: bool = True):
        self.force_2021 = force_2021
        self.session_key: bytes | None = None
        self.last_handle = 0
        self.last_count = 0
        self._reset()

    def set_encryption(self, session_key: bytes) -> None:
        self.session_key = session_key

    def _reset(self) -> None:
        self.current_handle = None
        self.current_type = 0
        self.current_length = 0
        self.buffer = bytearray()

    def decode(self, data: bytes):
        """Feed one notification.

        Returns ``(needs_ack, message)`` where ``message`` is a
        :class:`DecodedMessage` once a full message has been reassembled, or
        ``None`` while more chunks are pending.  ``data`` that is not a chunk
        (e.g. an ack) returns ``(False, None)``.
        """
        i = 0
        if len(data) < 2 or data[i] != CHUNK_MARKER:
            return False, None
        i += 1
        flags = data[i]
        i += 1
        encrypted = bool(flags & FLAG_ENCRYPTED)
        first_chunk = bool(flags & FLAG_FIRST)
        last_chunk = bool(flags & FLAG_LAST)
        needs_ack = bool(flags & FLAG_ACK)

        if self.force_2021:
            i += 1  # skip extended header byte
        handle = data[i]
        i += 1

        if self.current_handle is not None and self.current_handle != handle:
            raise ValueError("interleaved chunk handle %d, expected %d"
                             % (handle, self.current_handle))
        self.last_handle = handle
        self.last_count = data[i]
        i += 1

        if first_chunk:
            full_length = int.from_bytes(data[i:i + 4], "little")
            i += 4
            self.current_length = full_length
            if encrypted:
                encrypted_length = full_length + 8
                overflow = encrypted_length % 16
                if overflow:
                    encrypted_length += 16 - overflow
                full_length = encrypted_length
            self.buffer = bytearray()
            self.current_type = int.from_bytes(data[i:i + 2], "little")
            i += 2
            self.current_handle = handle

        chunk_data = data[i:]
        self.buffer.extend(chunk_data)

        message = None
        if last_chunk:
            buf = bytes(self.buffer)
            if encrypted:
                if self.session_key is None:
                    self._reset()
                    raise RuntimeError("got encrypted message without a session key")
                message_key = bytes(self.session_key[j] ^ handle for j in range(16))
                buf = aes_ecb_decrypt(buf, message_key)[:self.current_length]
            else:
                buf = buf[:self.current_length] if self.current_length else buf
            message = DecodedMessage(self.current_type, buf)
            self._reset()

        return needs_ack, message