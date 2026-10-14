"""Command line entry point.

The auth key is a secret and is never stored in the repository:

* ``--key-hex`` / ``MI_BAND_AUTH_KEY`` environment variable, or
* ``--key-file`` (default ``auth_key.txt``, git-ignored).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .protocol import MiBand2021


def _load_key(args) -> bytes:
    value = args.key_hex or os.environ.get("MI_BAND_AUTH_KEY")
    if not value:
        path = args.key_file
        if path and os.path.exists(path):
            value = open(path).read().strip()
    if not value:
        sys.exit("no auth key given (use --key-hex, MI_BAND_AUTH_KEY or --key-file)")
    value = value.strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    try:
        key = bytes.fromhex(value)
    except ValueError:
        sys.exit("auth key is not valid hex")
    if len(key) != 16:
        sys.exit("auth key must be 16 bytes (32 hex chars), got %d" % len(key))
    return key


async def run(args) -> int:
    key = _load_key(args)
    band = MiBand2021(address=args.address, name_filter=args.name)
    try:
        print("[*] connecting and authenticating ...")
        await band.connect_and_authenticate(key)
        print("[+] AUTH OK — the key is valid, we are authenticated to the band")

        battery = await band.read_battery()
        print("[+] battery: %s%% (%s)  raw=%s"
              % (battery["level"], battery["status"], battery["raw"]))
        if args.info:
            info = await band.read_device_info()
            for k, v in info.items():
                print("    %-9s = %s" % (k, v))
        return 0
    except Exception as exc:  # noqa: BLE001
        print("[-] %s: %s" % (type(exc).__name__, exc))
        return 1
    finally:
        await band.disconnect()


def main() -> int:
    p = argparse.ArgumentParser(
        prog="miband2021",
        description="Authenticate to a Xiaomi band/watch that uses the Huami 2021 protocol.")
    p.add_argument("--address", help="BLE address/UUID (optional, will scan otherwise)")
    p.add_argument("--name", default="Band", help="name substring to look for when scanning")
    p.add_argument("--key-hex", help="auth key as hex (or set MI_BAND_AUTH_KEY)")
    p.add_argument("--key-file", default="auth_key.txt", help="file with the hex auth key")
    p.add_argument("--info", action="store_true", help="also read the device info service")
    return asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())