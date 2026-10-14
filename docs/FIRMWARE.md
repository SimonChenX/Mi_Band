# Mi Band 6 firmware notes

Reverse-engineering notes for the Xiaomi Mi Band 6 (Chinese NFC, `hmpace.motion.v6nfc`)
firmware, gathered to understand the "find device" / vibration handling.

## Obtaining the firmware

Version list: <https://schakal.ru/fw/all_versions.json>
(key `211` = *Mi Band 6 Chinese NFC* `PANGU`, key `212` = *Mi Band 6 Global*).

Our band reports `software V1.0.6.10`, which corresponds to:

```
https://schakal.ru/fw/Mi_Band_6_Chinese_NFC_PANGU_211/1.0.6.10_PANGU_202110211347.zip
  PANGU_1.0.6.10.fw   2.2 MB   main firmware
  PANGU_2.ft          7.2 MB   font/table
  PANGU_59.res        2.7 MB   resources
```

(Use the proxy `http://192.168.5.8:7890` if you are outside mainland China.)

## Image layout

* The `.fw` starts with a **0x400-byte container header**, then the image:

  ```
  00000000  51 71 4c 12 23 00 20 f8 b2 9e "1.0.0.1\0" ...        (0x400 bytes)
  00000400  <vector table: SP=0x20034578, reset=0x32d, ...>
  ```

* Therefore **`address = file_offset - 0x400`**.
* The CPU is ARM Cortex-M, **Thumb** instruction set.
* The payload is **not encrypted** — it is full of log format strings and even
  source paths (`projects\huami_project\app\ECDH\ecdh.c`), so it can be read
  with `strings`.

## Tooling

```
python tools/fw_analyze.py PANGU_1.0.6.10.fw info
python tools/fw_analyze.py PANGU_1.0.6.10.fw str motor
python tools/fw_analyze.py PANGU_1.0.6.10.fw refs 0x16feba
python tools/fw_analyze.py PANGU_1.0.6.10.fw func 0xcbf8
```

## The ECF command framework

The firmware has an "ECF" command dispatcher (function at `0xc8e0`) that switches
on `payload[0]` and logs through strings such as `[%u] [BLE]ecf_cp_w %d`.
Handlers seen in its string pool:

```
do_pieces_ecf_write
ecf_set_custom_motor
ecf_set_ad_reminder_data
```

### Command `0x20` = `ecf_set_custom_motor`

Dispatcher case at `0xc948`:

```
payload[0] = 0x20                 command
payload[1] = slot                 0..9 (else error)
payload[2] = flags                bits0-5 = type (step count, <= 0x3c)
                                  bit6    = flag
                                  bit7    = custom
payload[3..] = pattern            count*4 (+2) bytes
```

The pattern is a list of steps, **two little-endian uint16 per step**
(vibration time, pause time).  Total time is capped at 12000 ms (`0x2ee0`).
Ten slots are kept in a 2420-byte buffer (`10 * 242`).

With `flag|custom == 0` the slot is cleared; with the `custom` bit set the
pattern is handed to the motor layer (`bl 0x13d84`).  When only `flag`/`type`
is given, one of several built-in patterns is used (the `tbb` jump table at
`0xd28c` calls `0x13cf8` / `0x13d34` with preset timing constants).

### Motor layer

```
motor_enable          (string ref @0x13bc8)
motor_set_internal    (string ref @0x13bc8+)
motor_set_custom      (string ref @0x13e80)
```

## Observation: find device ACKs but does not vibrate

The official app's 查找设备 ("find device") was captured with an HCI snoop as an
**unencrypted 1-byte** message on 2021 endpoint `0x0032`
(`0x01` capabilities → `0x03` start → `0x05` stop), which we replicate byte for
byte (see `docs/PROTOCOL.md`).  The band **acknowledges** each message
(`04 10 00 00 00 00`) but the motor does not run.

Given `ecf_set_custom_motor` above, the most likely explanation is that the
vibration is driven by a **custom motor pattern** that the app installs into a
slot during its session, which the find-device command then plays — a fresh
session with no pattern installed has nothing to play.

Still open / to verify:

* which transport carries ECF commands (the `ecf_cp_w` log suggests a dedicated
  "command point" — candidate: the encrypted 2021 `0x0090` channel);
* whether `0x0032 0x03` itself plays a pattern, or only sets a flag.

## Disclaimer

Firmware images are © Xiaomi / Anhui Huami and are redistributed here only for
interoperability research on a device we own.