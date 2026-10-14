"""macOS / CoreBluetooth scan workaround.

On macOS, `CBCentralManager` is started by bleak without the
``CBCentralManagerScanOptionAllowDuplicatesKey`` option.  After the system has
already seen/connected a peripheral, such a scan can silently stop reporting it
again (the device never shows up in ``didDiscover`` even though it is
advertising).  A classic symptom is that a Xiaomi band "disappears" until the
Mac's Bluetooth is toggled off/on.

Enabling the *allow duplicates* option makes every advertisement be reported,
which brings the device back without touching the Bluetooth radio.
"""

from __future__ import annotations

import asyncio
import sys

_patched = False


def enable_allow_duplicates() -> bool:
    """Patch bleak's macOS scanner to enable allow-duplicates. Returns True if active."""
    global _patched
    if _patched:
        return True
    if sys.platform != "darwin":
        return False
    try:
        from CoreBluetooth import CBCentralManagerScanOptionAllowDuplicatesKey, CBUUID
        from Foundation import NSArray
        from objc import python_method

        from bleak.backends.corebluetooth.CentralManagerDelegate import CentralManagerDelegate

        async def start_scan(self, service_uuids):
            _service_uuids = (
                NSArray[CBUUID].alloc().initWithArray_(
                    [CBUUID.UUIDWithString_(u) for u in service_uuids])
                if service_uuids else None
            )
            self.central_manager.scanForPeripheralsWithServices_options_(
                _service_uuids, {CBCentralManagerScanOptionAllowDuplicatesKey: True})
            event = asyncio.Event()
            self._did_start_scanning_event = event
            if not self.central_manager.isScanning():
                await event.wait()

        CentralManagerDelegate.start_scan = python_method(start_scan)
        _patched = True
        return True
    except Exception:
        return False