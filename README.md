# Mi_Band

Talk to Xiaomi bands / watches that use the **Huami "2021" protocol** directly over
Bluetooth Low Energy — no Xiaomi app, no cloud, no account.

Implemented in pure Python (`bleak` + `pycryptodome`).  This is a from-scratch port
of the relevant parts of [Gadgetbridge](https://gadgetbridge.org/) so the same
encrypted handshake can be run from a desktop (this fork was written and verified on
macOS / CoreBluetooth).

## Status

Verified end-to-end against a **Xiaomi Mi Band 6 NFC** (`hmpace.motion.v6nfc`,
firmware `V1.0.6.10`) connected through a rooted Xiaomi Mi 8 UD:

```
[+] AUTH OK — the key is valid, we are authenticated to the band
[+] battery: 51% (charging)
    serial    = 32098/10124408
    hardware  = V0.82.131.19
    software  = V1.0.6.10
```

The band sends/accepts the same `0x0082` ECDH handshake the official app uses.

## Background: why this exists

Newer Huami/Xiaomi wearables no longer use the classic "send key, solve a challenge"
authentication that older Mi Bands used.  Instead they perform an **ECDH key exchange
on the NIST B-163 binary curve**, derive a per-session AES key and then encrypt every
message in a chunked transport layer.

Crucially, the Mi Band 6 firmware we tested **rejects the classic auth path** (the
`00000009` characteristic answers `10 03 07` to every key), so a classic-protocol
client simply cannot connect.  This project implements the newer flow.

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full wire format and notes.

## The auth key

The device keeps a **16-byte auth key** that is created during pairing with the
official app and stored on the vendor servers.  Both this project and Gadgetbridge
need it.  On a **rooted** phone it can be read straight out of the app database:

```sh
# 小米运动健康 / Xiaomi Wear  (com.mi.health)
adb shell su -c 'sqlite3 /data/data/com.mi.health/databases/device_db \
    "select did, detail from device"'
# -> {"auth_key":"...","device_id":"...","mac":"...","sn":"..."}
```

The same value also appears in the app log:

```sh
adb shell su -c 'grep -a huamiAuthKey \
    /sdcard/Android/data/com.mi.health/files/log/XiaomiFit.device.log'
```

> The key is a **secret**.  It is never stored in this repository — pass it via
> `MI_BAND_AUTH_KEY`, `--key-hex`, or a git-ignored `auth_key.txt`.

Tread carefully:

* **Never unpair the device from the official app** — that invalidates the key.
* **A hard reset** changes the Bluetooth address *and* the key.
* Only **one** BLE connection exists at a time: stop the official app / turn the
  phone's Bluetooth off before connecting from your computer.

## Requirements

* Python 3.9+
* `bleak`, `pycryptodome`

```sh
pip install -r requirements.txt
```

## Usage

```sh
# scan for a device whose name contains "Band" and authenticate
python -m miband2021 --key-file auth_key.txt --info

# or point at a known address/UUID
python -m miband2021 --address AA:BB:CC:DD:EE:FF --key-hex 00112233... --info

# or via the environment
MI_BAND_AUTH_KEY=00112233445566778899aabbccddeeff python -m miband2021 --info

# make the band vibrate for 5 seconds ("find device")
python -m miband2021 --key-file auth_key.txt --vibrate --vibrate-seconds 5
```

`MI_BAND_DEBUG=1` prints the raw chunk traffic.

> **macOS scanning note**: CoreBluetooth normally stops reporting a peripheral once
> the system has seen it (it "disappears" until you toggle Bluetooth).  The client
> works around this automatically by enabling the *allow duplicates* scan option,
> so no manual Bluetooth toggling or device reboots are needed.

## Tests

The ECDH and chunked layers have dependency-free self tests (`pip install pycryptodome`
for the chunked one):

```sh
python tests/test_ecdh_b163.py   # curve sanity + ECDH round trip
python tests/test_chunked.py     # chunk encoder/decoder round trip
```

`test_ecdh_b163.py` checks, among other things, that `base_order * G` is the point at
infinity — a strong sanity check that the field/curve arithmetic is correct.

## Layout

```
miband2021/
  ecdh_b163.py   GF(2^163) + NIST B-163 ECDH
  crypto.py      AES-ECB, CRC-32, MTU helpers
  chunked.py     Huami 2021 chunked encoder/decoder
  protocol.py    BLE connection + 2021 authentication + reads + vibrate
  macos_scan.py  CoreBluetooth allow-duplicates workaround (macOS)
  cli.py         command line entry point
docs/PROTOCOL.md protocol notes
tests/           self tests
```

## Credits & license

* Protocol knowledge and reference implementation:
  [Gadgetbridge](https://codeberg.org/Freeyourgadget/Gadgetbridge) (AGPL-3.0).
* `ecdh_b163.py` is a Python port of Gadgetbridge's `ECDH_B163.java`, itself a port
  of [kokke/tiny-ECDH-c](https://github.com/kokke/tiny-ECDH-c).

Because parts of this code are derived from Gadgetbridge, the project is licensed
under the **GNU AGPL-3.0-or-later** (see [`LICENSE`](LICENSE)).

This project is provided for interoperability with hardware you own.  Use it on
your own devices only.