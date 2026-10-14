# Mi Band 6 firmware notes

Reverse-engineering notes for the Xiaomi Mi Band 6 (Chinese NFC, `hmpace.motion.v6nfc`)
firmware, gathered to understand the "find device" / vibration handling.

## TL;DR

* The `2021` find-device command (endpoint `0x0032`, `0x03`/`0x05`, see
  `docs/PROTOCOL.md`) is **acknowledged by the band but does not vibrate**.
* The motor is actually driven through the firmware's **ECF command framework**:
  ECF command `0x20` (`ecf_set_custom_motor`) plays built-in motor patterns or
  stores a custom waveform.
* ECF rides the **encrypted 2021 endpoint `0x0090`** inside a small "OPCM"
  envelope (`byte0=type, byte1, byte2, byte3`, body from byte4; group =
  `byte2 & 0x3f`, ECF = 2).
* We can build those messages ourselves (we hold the session key after auth) -
  see the TODO at the bottom.

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

Tip: linear disassembly of the whole image desyncs on inlined data.  To find
callers reliably, decode **one instruction per 2-byte aligned position** with
capstone and check for `bl`/`blx` (a plain linear sweep misses most calls):

```python
import capstone
md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
for a in range(0x2c0, 0x16e000, 2):
    ins = next(md.disasm(data[a + 0x400:a + 0x404], a), None)
    if ins and ins.mnemonic in ("bl", "blx"):
        target = int(ins.op_str.lstrip("#"), 16)
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

## Call chain for ECF commands

The ECF dispatcher is reachable from the BLE command path:

```
OPCM message receiver        0x140e8   (logs "[OPCM]receiv sz: %d %d")
  -> group dispatcher        0x14374   (tbb jump table on group, 0..9)
       group 2 ->                   ECF dispatcher
  -> ECF dispatcher          0xc8e0    (switch on payload[0])
       case 0x20 ->                ecf_set_custom_motor
       case 0x28 ->                ecf_set_ad_reminder_data
       ...
```

### Transport: encrypted 2021 endpoint `0x0090`

The OPCM receiver is registered by a struct built at `0x14238`; its **first
field is the uint16 `0x0090`** (`movs r3,#0x90; strh r3,[sp]`), and the callback
list holds `0x1404c`, `0x1401c`, `0x14020` and our receiver `0x140e8`.  It sits
right next to the `0x0090` send helpers (`0x51850`, `0x51648`).  Combined with
the fact that the app's `0x0090` traffic is encrypted, ECF commands ride the
**encrypted 2021 endpoint `0x0090`**.

### OPCM envelope (4-byte header)

The receiver parses the message one byte at a time (`0xdfbc8` = init,
`0xdfc0e` = next byte):

```
byte0   message type    only 0 reaches the group dispatch (1 and 3 go elsewhere)
byte1   field 1
byte2   field 2         group = field2 & 0x3f      (ECF = 2)
byte3   field 3
byte4.. body            handed to the group handler; the ECF dispatcher sees
                        this as `payload`, so payload[0] is the ECF command
```

So an ECF custom-motor message would look like:

```
00 ?? 02 ??  20 <slot> <flags> <waveform...>
```

The exact meaning of fields 1/3 is still unknown (to be determined by testing).

### Motor entry points

```
0x13cf8 / 0x13d34   play a pattern with preset timing (r0..r3, extra on stack)
0x13c30             the actual motor layer they funnel into
0x13d84             motor_set_custom - called with &slotbuf for a stored waveform
```

With `flags = 0x80` (custom bit only) the handler jumps through a `tbb` table on
`payload[1]` (0..8) and calls one of the built-in patterns; with
`flags = 0xC0` (flag+custom) it stores the supplied waveform and hands it to
`0x13d84`.

## Next session: TODO

1. Send ECF `0x20` on the encrypted `0x0090` channel and find a payload that
   makes the band vibrate (start with the envelope above; try `flags=0x80` +
   built-in pattern index, then `flags=0xC0` + a short waveform).
2. Statically dig into the `0x0032` (find-device) handler to see whether it
   plays a motor-pattern slot or only sets a flag - this explains why the
   command is acknowledged but silent.
3. Determine OPCM fields 1/3 (and whether type must be 0).

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