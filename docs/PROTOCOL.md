# Huami "2021" protocol notes

Notes gathered while reverse-engineering a **Xiaomi Mi Band 6 NFC**
(`hmpace.motion.v6nfc`, firmware `V1.0.6.10`) with the official
小米运动健康 app (`com.mi.health`, v3.59.1) on a rooted Xiaomi Mi 8 UD
(Android 10).

Everything below matches Gadgetbridge's implementation; the packet capture that
confirmed it was taken with the phone's Bluetooth HCI snoop log
(`settings put secure bluetooth_hci_log 1`, log at
`/data/misc/bluetooth/logs/btsnoop_hci.log`).

## GATT characteristics

| UUID suffix (`…-0000-3512-2118-0009af100700`) | role | props |
|---|---|---|
| `00000009` | classic auth | write-without-response, read, notify |
| `00000006` | classic battery | read, notify |
| `00000016` | **2021 chunked write** | write-without-response, notify |
| `00000017` | **2021 chunked read** | notify, write-without-response |
| `00000020` | classic chunked transfer | write-without-response, read, notify |

Device info service `0x180A`: `0x2A25` serial, `0x2A27` hardware revision,
`0x2A28` software revision (model `0x2A24` / firmware `0x2A26` are not exposed).
MTU is 247.

## Chunked transport (`0x00000016` →, `0x00000017` ←)

```
byte 0    0x03  chunk marker
byte 1    flags: 0x01 first | 0x02 last | 0x04 ack-requested | 0x08 encrypted
byte 2    0x00  (extended header byte, 2021 protocol)
byte 3    write handle (incremented per message by the sender)
byte 4    chunk counter (0-based, per message)
[first chunk only]
byte 5-8  uint32 LE  plaintext length
byte 9-10 uint16 LE  endpoint
byte 11+  payload slice
```

Non-first chunks use a 5-byte header (`03`, flags, `00`, handle, counter).

When the `0x08` (encrypted) flag is set, the reassembled payload is
`AES-128-ECB`-decrypted with `messageKey = sessionKey XOR handle`, then truncated to
the plaintext length.  On the sending side the plaintext is padded with
`length || uint32 LE sequence` `|| uint32 LE CRC-32(...)` to a multiple of 16 before
encryption.

A receiver that sees `0x04` must reply by **writing** to `0x00000017`:

```
04 00 <handle> 01 <count>
```

Acks from the device look like `04 00 <handle> 01 <count>` and are ignored.

## Authentication (endpoint `0x0082`)

```
1. host  ->  04 02 00 02 || public(48)          (chunked, endpoint 0x0082, unencrypted)
2. dev   ->  10 04 01 || remoteRandom(16) || remotePublic(48)
3. shared        = ECDH_B163(private, remotePublic)        # 48 bytes: x || y
   seqNumber     = uint32 LE(shared[0:4])
   sessionKey[i] = shared[i+8] XOR authKey[i]              # i = 0..15
4. host  ->  05 || AES(authKey, remoteRandom) || AES(sessionKey, remoteRandom)
5. dev   ->  10 05 01   (success)   /   10 05 25   (wrong key)
```

`ECDH_B163` is NIST **B-163** (`y² + xy = x³ + x² + b`):

* reduction polynomial `x^163 + x^7 + x^6 + x^3 + 1`
* scalars are masked to 162 bits (bits ≥ `bitvec_degree(base_order) - 1` cleared)
* values are little-endian integers, a public point is `x(24) || y(24)`

After success the host is authenticated; subsequent messages use the derived
`sessionKey` for the `0x08` encryption.

## Notable finding: the classic auth path is dead on this firmware

The classic authentication (`0x00000009`, opcodes `01`/`02`/`03`, `authFlags` `0x08`)
is answered with a fixed error:

```
01 08 || key        ->  10 01 81     (never 10 01 01)
02 08               ->  10 02 01 || random(16)
03 08 || AES(key, r)->  10 03 07     (for every key / key-order variant)
```

`10 03 07` is returned regardless of the key used, so this is **not** a key mismatch
— the firmware simply does not accept the classic handshake.  The official app never
sends the classic key either; its capture only contains the `0x0082` ECDH exchange.

## References

* Gadgetbridge: `ECDH_B163`, `Huami2021ChunkedEncoder/Decoder`, `InitOperation2021`,
  `HuamiSupport`, `HuamiService`.
* Pairing key extraction: <https://gadgetbridge.org/basics/pairing/huami-xiaomi-server/>