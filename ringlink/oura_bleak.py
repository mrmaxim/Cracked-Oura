"""Native Windows BLE transport and explicit first-time Oura Ring 4 onboarding.

No reset command is sent by this tool. `scan` never connects to a ring.
Bluetooth bond keys belong to Windows; only the Oura app key is stored here.
"""
from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import os
from pathlib import Path
from queue import Queue
import secrets
import sys
import threading
import time

from oura_protocol import OuraProtocol, EVENTS_FILE, HERE, load_key, native_key_file, frame

SERVICE = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"
PAIR_STATE = HERE / "native_pairing.json"
MEASUREMENT_FEATURES = {2: 'daytime_hr', 3: 'activity_hr', 4: 'spo2'}


async def discover(seconds=10):
    from bleak import BleakScanner
    found = await BleakScanner.discover(timeout=seconds, return_adv=True)
    return [(device, adv) for device, adv in found.values()
            if SERVICE in [u.lower() for u in adv.service_uuids]
            or "oura" in (adv.local_name or device.name or "").lower()]


class NativeOuraRing(OuraProtocol):
    """Synchronous facade so the existing daemon can reuse its protocol loop.

    All Bleak objects live on one persistent asyncio thread. Blocking protocol
    requests wait on a thread-safe queue while notifications continue arriving.
    """
    def __init__(self, address=None, verbose=False):
        self.address = address
        self.verbose = verbose
        self.conn = None
        self.rx = Queue()
        self.client = None
        self.loop = None
        self.thread = None

    def open(self):
        if self.thread is not None:
            raise RuntimeError("Native transport is already open")
        ready = threading.Event()

        def run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            ready.set()
            self.loop.run_forever()
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            if pending:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self.loop.close()

        self.thread = threading.Thread(target=run, name="oura-native-ble", daemon=True)
        self.thread.start()
        if not ready.wait(10):
            raise RuntimeError("BLE event loop did not start")

    def _run(self, coroutine, timeout=30):
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        try:
            return future.result(timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise RuntimeError("Native BLE operation timed out") from None
        except BaseException:
            future.cancel()
            raise

    def scan(self, seconds=10):
        return self._run(discover(seconds), timeout=seconds + 10)

    async def _disconnect(self):
        client, self.client = self.client, None
        self.conn = None
        if client is not None:
            await client.disconnect()

    async def _connect(self, seconds):
        from bleak import BleakClient
        candidates = await discover(seconds)
        if self.address:
            candidates = [(d, a) for d, a in candidates
                          if d.address.lower() == self.address.lower()]
        if not candidates:
            raise RuntimeError("Oura not found. Put it on the charger; disconnect the phone app.")
        if len(candidates) != 1:
            raise RuntimeError("Several Oura rings found. Use scan and specify --address.")
        device, _ = candidates[0]
        client = BleakClient(device, pair=True, timeout=90,
                             disconnected_callback=self._disconnected)
        self.client = client
        try:
            await client.connect()
            # OS performs MTU negotiation; do not copy BlueZ private MTU hacks.
            self.conn = device.address
            await client.start_notify(NOTIFY, self._notification)
            print(f"[ble] Windows/native connected, MTU={client.mtu_size}")
        except BaseException:
            await self._disconnect()
            raise

    def connect(self, name_contains="Oura", seconds=25, attempts=1):
        for attempt in range(attempts):
            try:
                self._run(self._connect(seconds), timeout=seconds + 110)
                return self.conn
            except Exception:
                if attempt + 1 == attempts:
                    raise
                time.sleep(2)

    def _disconnected(self, client):
        if client is self.client:
            self.conn = None

    def _notification(self, characteristic, data):
        self.rx.put(bytes(data))

    def _check_link(self):
        if self.conn is None:
            raise RuntimeError("Native BLE link dropped")

    def _write(self, data):
        self._check_link()
        self._run(self.client.write_gatt_char(WRITE, data, response=False), timeout=15)

    def reconnect(self, name_contains="Oura"):
        self._run(self._disconnect())
        return self.connect(name_contains=name_contains)

    def close(self):
        if self.thread is None:
            return
        try:
            self._run(self._disconnect(), timeout=15)
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=10)
            self.thread = None


def reserve_key(path: Path) -> bytes:
    """Persist before the first BLE connection; never overwrite a previous key.

    If installation succeeds but its acknowledgement is lost, the same key
    remains available for `verify`. It is never printed or committed.
    """
    key = secrets.token_bytes(16)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(key.hex() + "\n")
        f.flush()
        os.fsync(f.fileno())
    return key


def record_stage(stage):
    temp = PAIR_STATE.with_suffix(".tmp")
    temp.write_text(json.dumps({"stage": stage, "updated_at": time.time()}) + "\n")
    os.replace(temp, PAIR_STATE)


def ensure_idle():
    # Refuse even stale locks here: resolve them before a factory reset, not
    # halfway through onboarding. Do not kill the user's processes.
    if (HERE / ".daemon.lock").exists() or (HERE / ".sync.lock").exists():
        raise RuntimeError("Stop the ring daemon/sync and resolve its lock before onboarding.")


def verify_persistence(ring, key):
    ring.reconnect()
    # A reset ring with NO installed key can answer battery without auth.
    # That must never be mistaken for a successful persisted-key pairing.
    replies = ring.request(frame(0x0C),
                           done=lambda t, p: t == 0x0D or (t == 0x2F and p[:1] == b'\x2f'),
                           timeout=5)
    if OuraProtocol.find(replies, 0x0D) is not None:
        raise RuntimeError("Battery accessible without app auth after reconnect; key persistence NOT verified")
    refused = OuraProtocol.find(replies, 0x2F, ext=0x2F)
    if refused != b'\x2f\x01':
        raise RuntimeError("Could not confirm auth is required after reconnect")
    ring.authenticate(key)


def pair_new_ring(ring, key_path=None):
    ensure_idle()
    if key_path is None:
        key_path = native_key_file()
    key = reserve_key(key_path)
    record_stage("key_saved_before_connect")
    print("[pair] Key saved locally. Keep this file even if the connection fails.")
    ring.open()
    try:
        # No preliminary battery/firmware probe and no automatic retry. On
        # Ring 4 this must be the first connection after the manual reset.
        ring.connect(attempts=1)
        ring.set_auth_key(key)
        record_stage("key_install_acknowledged")
        ring.authenticate(key)
        record_stage("authenticated")
        ring.sync_time()
        verify_persistence(ring, key)
        battery = ring.battery()
        if not battery:
            raise RuntimeError("No battery response after reconnect")
        record_stage("verified_after_reconnect")
        print(f"[pair] SUCCESS: key survived reconnect; battery {battery[0]}%.")
    finally:
        ring.close()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--address", help="Target address from scan (only needed with multiple rings)")
    ap.add_argument("--verbose", action="store_true", help="Frame metadata only; no keys or proofs")
    ap.add_argument("command", choices=["scan", "pair", "verify", "battery", "events",
                                       "features", "prepare-offline"])
    ap.add_argument("--factory-reset-done", action="store_true",
                    help="Confirm you manually reset the ring and closed the phone app")
    args = ap.parse_args(argv)
    if args.command == "pair" and not args.factory_reset_done:
        ap.error("pair requires --factory-reset-done; prepare everything BEFORE manually resetting")
    ring = NativeOuraRing(args.address, args.verbose)
    if args.command == "pair":
        pair_new_ring(ring)
        return
    # Fail before connecting when no key exists. A battery check must never
    # accidentally consume the first-connection window after a reset.
    key = None if args.command == "scan" else load_key(native_key_file())
    if args.command != "scan":
        ensure_idle()
    ring.open()
    try:
        if args.command == "scan":
            devices = ring.scan()
            for device, adv in devices:
                print(f"{device.address}  {adv.local_name or device.name or 'Oura'}  RSSI={adv.rssi}")
            print(f"{len(devices)} Oura ring(s); scan only, no connections made.")
            return
        ring.connect()
        ring.authenticate(key)
        if args.command == "verify":
            verify_persistence(ring, key)
        if args.command in ("verify", "battery"):
            battery = ring.battery()
            if not battery:
                raise RuntimeError("No battery response")
            print(f"[auth] OK; battery {battery[0]}%")
            if args.command == "verify":
                record_stage("verified_after_reconnect")
        elif args.command in ("features", "prepare-offline"):
            report = {"time": time.time(), "features": {}}
            if args.command == "prepare-offline":
                ring.sync_time()
                ring.engage_data_plane()
            for feature, name in MEASUREMENT_FEATURES.items():
                before = ring.feature_status(feature)
                print(f"[feature] {name}: {json.dumps(before)}")
                after = before
                if args.command == "prepare-offline" and before['mode'] != 1:
                    after = ring.set_feature_mode(feature, 1)  # AUTOMATIC, not connected-live.
                    print(f"[feature] {name}: automatic mode verified")
                report['features'][name] = {"before": before, "after": after}
            if args.command == "prepare-offline":
                report['battery'] = ring.battery()[0]
                path = HERE / 'offline_preparation.json'
                path.write_text(json.dumps(report, indent=2) + '\n')
                print(f"[offline] Automatic modes verified; battery {report['battery']}%. Disconnecting.")
        elif args.command == "events":
            ring.engage_data_plane()
            ring.data_flush()
            count = 0
            with EVENTS_FILE.open("a", encoding="utf-8") as f:
                for tag, payload, raw in ring.drain_events(0):
                    f.write(json.dumps({"ts": time.time(), "tag": tag, "raw": raw.hex()}) + "\n")
                    f.flush()
                    count += 1
            print(f"Saved {count} raw event frames to events.jsonl")
    finally:
        ring.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped. Any saved auth key is retained.")
        sys.exit(130)
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
