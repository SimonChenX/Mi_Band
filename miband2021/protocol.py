"""Huami "2021" authentication over BLE (Mi Band 7+ / Xiaomi Wear devices).

Flow (see ``docs/PROTOCOL.md``):

1. generate an ephemeral ECDH key pair on curve B-163,
2. send ``04 02 00 02 || public(48)`` to chunked endpoint ``0x0082``,
3. device answers with ``10 04 01 || remoteRandom(16) || remotePublic(48)``,
4. derive the shared session key and send back
   ``05 || AES(remoteRandom, secretKey) || AES(remoteRandom, sessionKey)``,
5. device answers ``10 05 01`` on success, ``10 05 25`` on failure.
"""

from __future__ import annotations

import asyncio
import os

from bleak import BleakClient, BleakScanner

from .chunked import ChunkedDecoder, ChunkedEncoder
from .crypto import aes_ecb_encrypt
from .ecdh_b163 import generate_public, generate_shared

# Huami 2021 characteristics
CHUNKED2021_WRITE = "00000016-0000-3512-2118-0009af100700"
CHUNKED2021_READ = "00000017-0000-3512-2118-0009af100700"
# classic characteristics
BATTERY = "00000006-0000-3512-2118-0009af100700"
DEVICE_INFO = "0000180a-0000-1000-8000-00805f9b34fb"
DEVICE_INFO_CHARS = {
    "model": "00002a24-0000-1000-8000-00805f9b34fb",
    "serial": "00002a25-0000-1000-8000-00805f9b34fb",
    "firmware": "00002a26-0000-1000-8000-00805f9b34fb",
    "hardware": "00002a27-0000-1000-8000-00805f9b34fb",
    "software": "00002a28-0000-1000-8000-00805f9b34fb",
}

AUTH_ENDPOINT = 0x0082


class AuthError(Exception):
    pass


class MiBand2021:
    def __init__(self, address: str | None = None, name_filter: str = "Band"):
        self.address = address
        self.name_filter = name_filter
        self.client: BleakClient | None = None
        self.encoder: ChunkedEncoder | None = None
        self.decoder: ChunkedDecoder | None = None
        self._queue: asyncio.Queue = asyncio.Queue()
        self.authenticated = False
        self.session_key: bytes | None = None
        self.mtu = 23

    # -- discovery -----------------------------------------------------------
    async def discover(self, timeout: float = 25.0) -> str:
        found = {}

        def cb(dev, adv):
            name = adv.local_name or dev.name or ""
            uuids = "".join(adv.service_uuids or []).lower()
            match = (self.name_filter.lower() in name.lower()) or ("fee0" in uuids)
            if self.address and dev.address.upper() == self.address.upper():
                found["addr"] = dev.address
            elif not self.address and match:
                found["addr"] = dev.address

        async with BleakScanner(detection_callback=cb):
            waited = 0.0
            while waited < timeout and "addr" not in found:
                await asyncio.sleep(0.5)
                waited += 0.5
        if "addr" not in found:
            raise AuthError("device not found in scan (is it connected to the phone?)")
        return found["addr"]

    # -- notifications -------------------------------------------------------
    def _on_notify(self, _sender, data: bytearray):
        if os.environ.get("MI_BAND_DEBUG"):
            print("   <- %s" % bytes(data).hex())
        self._queue.put_nowait(bytes(data))

    async def _send_ack(self, handle: int, count: int):
        await self.client.write_gatt_char(
            CHUNKED2021_READ, bytes([0x04, 0x00, handle, 0x01, count]), response=False)

    async def _write_chunks(self, chunks):
        for chunk in chunks:
            await self.client.write_gatt_char(CHUNKED2021_WRITE, chunk, response=False)

    # -- main auth -----------------------------------------------------------
    async def connect_and_authenticate(self, secret_key: bytes):
        addr = self.address or await self.discover()
        self.address = addr
        self.client = BleakClient(addr, timeout=25)
        await self.client.connect()
        try:
            self.mtu = min(self.client.mtu_size or 23, 512)
            self.encoder = ChunkedEncoder(self.mtu)
            self.decoder = ChunkedDecoder(force_2021=True)
            await self.client.start_notify(CHUNKED2021_READ, self._on_notify)

            private_ec = os.urandom(24)
            public_ec = generate_public(private_ec)
            if public_ec is None:
                raise AuthError("generated private key was too small")

            cmd = bytes([0x04, 0x02, 0x00, 0x02]) + public_ec
            await self._write_chunks(self.encoder.write(AUTH_ENDPOINT, cmd,
                                                        extended_flags=True, encrypt=False))

            deadline = asyncio.get_event_loop().time() + 20
            while True:
                timeout = max(0.1, deadline - asyncio.get_event_loop().time())
                if timeout <= 0.1:
                    raise AuthError("timed out waiting for the device")
                try:
                    data = await asyncio.wait_for(self._queue.get(), timeout)
                except asyncio.TimeoutError:
                    raise AuthError("timed out waiting for the device")

                if not data or data[0] == 0x04:
                    continue  # chunk ack, ignore
                if data[0] != 0x03:
                    continue

                needs_ack, msg = self.decoder.decode(data)
                if needs_ack:
                    await self._send_ack(self.decoder.last_handle, self.decoder.last_count)
                if msg is None:
                    continue
                if msg.endpoint != AUTH_ENDPOINT:
                    continue

                p = msg.payload
                if len(p) >= 3 and p[0] == 0x10 and p[1] == 0x04 and p[2] == 0x01:
                    remote_random = p[3:19]
                    remote_public = p[19:67]
                    shared = generate_shared(private_ec, remote_public)
                    if shared is None:
                        raise AuthError("device public key failed validation")

                    seq_nr = int.from_bytes(shared[0:4], "little")
                    session_key = bytes(shared[i + 8] ^ secret_key[i] for i in range(16))
                    self.session_key = session_key
                    self.encoder.set_encryption(seq_nr, session_key)
                    self.decoder.set_encryption(session_key)

                    enc1 = aes_ecb_encrypt(remote_random, secret_key)
                    enc2 = aes_ecb_encrypt(remote_random, session_key)
                    cmd2 = bytes([0x05]) + enc1 + enc2
                    await self._write_chunks(self.encoder.write(AUTH_ENDPOINT, cmd2,
                                                                extended_flags=True, encrypt=False))

                elif len(p) >= 3 and p[0] == 0x10 and p[1] == 0x05 and p[2] == 0x01:
                    self.authenticated = True
                    return True

                elif len(p) >= 3 and p[0] == 0x10 and p[1] == 0x05 and p[2] == 0x25:
                    raise AuthError("device rejected the auth key")
        finally:
            pass

    # -- post-auth reads -----------------------------------------------------
    async def read_battery(self):
        raw = await self.client.read_gatt_char(BATTERY)
        level = raw[1] if len(raw) > 1 else None
        status = "charging" if len(raw) > 2 and raw[2] != 0 else "normal"
        return {"raw": raw.hex(), "level": level, "status": status}

    async def read_device_info(self):
        info = {}
        for name, uuid in DEVICE_INFO_CHARS.items():
            try:
                val = await self.client.read_gatt_char(uuid)
                info[name] = val.decode("utf-8", "replace").strip("\x00")
            except Exception as exc:  # noqa: BLE001
                info[name] = "-"  # characteristic not exposed by this firmware
        return info

    async def disconnect(self):
        if self.client and self.client.is_connected:
            try:
                await self.client.stop_notify(CHUNKED2021_READ)
            except Exception:
                pass
            await self.client.disconnect()