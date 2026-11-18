"""Shared Oura protocol operations, independent of the Bluetooth transport."""
import os
import time
from pathlib import Path
from queue import Empty
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = Path(__file__).resolve().parent
KEY_FILE = HERE / "oura_key.hex"
EVENTS_FILE = HERE / "events.jsonl"
HISTORY_EVENT_PREFIX = 0x41

def encrypt_nonce(key: bytes, nonce: bytes) -> bytes:
    """AES-128/ECB over the PKCS7-padded 15-byte nonce -> 16-byte response."""
    pad = 16 - len(nonce)
    block = nonce + bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def frame(tag: int, payload: bytes = b"") -> bytes:
    return bytes([tag, len(payload)]) + payload


def parse_frame(data: bytes):
    if len(data) < 2:
        return None
    tag, length = data[0], data[1]
    return tag, bytes(data[2 : 2 + length]) if len(data) >= 2 + length else bytes(data[2:])


class OuraProtocol:
    # --- request / response ------------------------------------------------
    def request(self, data: bytes, done=None, timeout: float = 10.0):
        """Write a request frame; collect notification frames.

        `done(tag, payload)` -> True stops collection. Default: stop at first frame,
        then drain anything that arrives within 300ms.
        """
        while not self.rx.empty():
            self.rx.get_nowait()
        if self.verbose:
            print(f">> tag=0x{data[0]:02x} len={len(data)}")
        # ATT Write Command (no response) — what the official app uses
        # (open_ring transport.py: response=False on every write). The ring
        # stops ACKing ATT Write Requests in some states.
        self._check_link()
        self._write(data)
        frames = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                raw = self.rx.get(timeout=max(0.05, deadline - time.monotonic()))
            except Empty:
                break
            parsed = parse_frame(raw)
            if parsed is None:
                continue
            tag, payload = parsed
            if self.verbose:
                print(f"<< tag=0x{tag:02x} len={len(raw)}")
            frames.append((tag, payload, raw))
            if done is not None:
                if done(tag, payload):
                    break
            else:
                # default: single response + 300ms grace drain
                grace = time.monotonic() + 0.3
                while time.monotonic() < grace:
                    try:
                        raw = self.rx.get(timeout=grace - time.monotonic())
                        parsed = parse_frame(raw)
                        if parsed:
                            if self.verbose:
                                print(f"<< tag=0x{tag:02x} len={len(raw)}")
                            frames.append((parsed[0], parsed[1], raw))
                    except Empty:
                        break
                break
        if not frames:
            raise RuntimeError(f"no response to tag 0x{data[0]:02x} within {timeout}s")
        return frames

    @staticmethod
    def find(frames, tag, ext=None):
        for t, p, _ in frames:
            if t != tag:
                continue
            if ext is not None and (not p or p[0] != ext):
                continue
            return p
        return None

    # --- protocol ops ------------------------------------------------------
    def set_auth_key(self, key: bytes):
        frames = self.request(frame(0x24, key), done=lambda t, p: t == 0x25)
        p = self.find(frames, 0x25)
        if not p or p[0] != 0x00:
            raise RuntimeError(f"set_auth_key failed: {p.hex() if p else 'no response'}")

    def authenticate(self, key: bytes):
        # Phone-faithful preamble (open_ring PROTOCOL.md §6.1 full-setup):
        # firmware probe then capability pages 0+1 BEFORE the nonce. Gen 4
        # swallows the auth proof if this negotiation never happened.
        for req, desc in ((bytes([0x08, 0x03, 0x00, 0x00, 0x00]), "fw probe"),
                          (bytes([0x2F, 0x02, 0x01, 0x00]), "caps page 0"),
                          (bytes([0x2F, 0x02, 0x01, 0x01]), "caps page 1")):
            try:
                self.request(req, timeout=4.0)
            except RuntimeError:
                if self.verbose:
                    print(f"[auth] preamble {desc}: no response (continuing)")
        frames = self.request(
            bytes([0x2F, 0x01, 0x2B]), done=lambda t, p: t == 0x2F and p[:1] == b"\x2c"
        )
        p = self.find(frames, 0x2F, ext=0x2C)
        if p is None or len(p) != 16:
            raise RuntimeError("missing or invalid 15-byte auth nonce")
        nonce = p[1:16]
        enc = encrypt_nonce(key, nonce)
        try:
            frames = self.request(
                frame(0x2F, b"\x2d" + enc), done=lambda t, p: t == 0x2F and p[:1] == b"\x2e"
            )
            p = self.find(frames, 0x2F, ext=0x2E)
        except RuntimeError:
            p = None
        if p is None or len(p) < 2:
            # Gen 4 quirk: no 0x2e result frame observed on this ring. Probe a
            # gated command to learn the true auth state.
            probe = self.request(frame(0x0C), timeout=5.0)
            if self.find(probe, 0x0D) is not None:
                print("[auth] no 0x2e result frame, but gated commands work — "
                      "authenticated (Gen 4 quirk)")
                return
            raise RuntimeError("authenticate: no result frame and gated commands "
                               "still refused — auth failed")
        results = {0: "success", 1: "wrong key", 2: "ring in factory reset",
                   3: "not original onboarded device"}
        if p[1] != 0x00:
            raise RuntimeError(f"auth failed: {results.get(p[1], hex(p[1]))}")

    def engage_data_plane(self):
        """Phone steps 12-15 after auth (open_ring §6.1, btsnoop-verified):
        subscribe enable (16 01 02), state_cmd (1c 01 bf — engages the data
        plane), then the capability dance. Without subscribe + state_cmd,
        some event categories drift quiescent and the ring stops emitting
        HR/temp records (§6.6)."""
        for req, desc in ((bytes([0x16, 0x01, 0x02]), "subscribe enable"),
                          (bytes([0x1C, 0x01, 0xBF]), "state_cmd")):
            try:
                self.request(req, timeout=4.0)
            except RuntimeError:
                if self.verbose:
                    print(f"[session] {desc}: no response (continuing)")
        for page in (b"\x2f\x02\x20\x02", b"\x2f\x02\x20\x04",
                     b"\x2f\x02\x03\x01", b"\x2f\x02\x20\x0b",
                     b"\x2f\x02\x20\x0d", b"\x2f\x02\x20\x03",
                     b"\x2f\x02\x20\x10"):
            try:
                self.request(page, timeout=3.0)
            except RuntimeError:
                pass

    def data_flush(self):
        """28 01 00 — release flash-buffered events to the BLE stream
        (open_ring §6.5). Must precede GetEvent in every polling session or
        the freshest samples stay buffered and the drain returns stale data."""
        try:
            self.request(bytes([0x28, 0x01, 0x00]),
                         done=lambda t, p: t == 0x29, timeout=5.0)
        except RuntimeError:
            if self.verbose:
                print("[session] data_flush: no ack (continuing)")

    def firmware_info(self):
        frames = self.request(bytes([0x08, 0x03, 0x00, 0x00, 0x00]),
                              done=lambda t, p: t == 0x09)
        return self.find(frames, 0x09)

    def feature_status(self, feature):
        """Read GetFeatureStatus (0x20); no changes to measurement settings."""
        replies = self.request(bytes([0x2F, 0x02, 0x20, feature]),
                               done=lambda t, p: t == 0x2F and p[:2] == bytes([0x21, feature]))
        p = next((p for t, p, raw in replies
                  if t == 0x2F and p[:2] == bytes([0x21, feature])), None)
        if p is None or len(p) < 6:
            raise RuntimeError(f"Missing feature-status response for 0x{feature:02x}")
        return dict(feature=feature, mode=p[2], status=p[3], state=p[4], subscription=p[5])

    def set_feature_mode(self, feature, mode):
        """Set mode, require a successful acknowledgement AND read-back."""
        replies = self.request(bytes([0x2F, 0x03, 0x22, feature, mode]),
                               done=lambda t, p: t == 0x2F and p[:2] == bytes([0x23, feature]))
        p = next((p for t, p, raw in replies
                  if t == 0x2F and p[:2] == bytes([0x23, feature])), None)
        if p is None or len(p) < 3 or p[2] != 0:
            raise RuntimeError(f"SetFeatureMode rejected or unacknowledged for 0x{feature:02x}")
        status = self.feature_status(feature)
        if status['mode'] != mode:
            raise RuntimeError(f"Feature 0x{feature:02x} did not retain requested mode {mode}")
        return status

    def battery(self):
        frames = self.request(frame(0x0C), done=lambda t, p: t == 0x0D)
        return self.find(frames, 0x0D)

    def serial_number(self):
        frames = self.request(bytes([0x18, 0x03, 0x08, 0x00, 0x10]),
                              done=lambda t, p: t == 0x19)
        p = self.find(frames, 0x19)
        if p and p[0] == 0x00:
            return bytes(b for b in p[1:] if 0x20 <= b < 0x7F).decode(errors="replace")
        return None

    def sync_time(self):
        """Set the ring clock to the REAL current time (0x12).

        Payload per ringverse BLE.md: unix seconds (u64 LE) + timezone
        offset in HALF-HOURS from UTC (signed byte; the official app sends
        getOffset()/1800000). The tz byte matters for the ring's own local
        day boundaries (sleep analysis). Logs the 0x13 echo so a rejected/
        ignored time-sync is visible instead of silent."""
        now = int(time.time())
        offset_s = -(time.altzone if time.localtime().tm_isdst else time.timezone)
        tz_half_hours = int(round(offset_s / 1800)) & 0xFF
        payload = now.to_bytes(8, "little") + bytes([tz_half_hours])
        frames = self.request(frame(0x12, payload), done=lambda t, p: t == 0x13)
        p = self.find(frames, 0x13)
        if p is not None and len(p) >= 4:
            dev_ts = int.from_bytes(p[0:4], "little")
            if abs(dev_ts - now) <= 300:
                print(f"[time] ring clock confirmed (drift {dev_ts - now:+d}s)")
            else:
                # 0x13 may echo an internal counter rather than unix time —
                # informational only; the decode-side anchor validator is
                # the real safety net for a wrong ring clock.
                print(f"[time] ring 0x13 echo: {dev_ts} (host {now})")

    def drain_events(self, start_ds: int = 0, on_batch=None):
        """Fetch history events from cursor (deciseconds). Yields raw event frames."""
        total = 0
        cursor = start_ds
        for _ in range(100_000):
            payload = (cursor.to_bytes(4, "little") + bytes([0xFF])
                       + (0xFFFFFFFF).to_bytes(4, "little"))
            frames = self.request(frame(0x10, payload),
                                  done=lambda t, p: t == 0x11, timeout=30)
            batch, summary = [], None
            for t, p, raw in frames:
                if t == 0x11 and len(p) >= 6:
                    summary = {"events": p[0], "sleep_progress": p[1],
                               "bytes_left": int.from_bytes(p[2:6], "little")}
                elif t >= HISTORY_EVENT_PREFIX:
                    batch.append((t, p, raw))
            max_ts = cursor
            for t, p, raw in batch:
                if len(p) >= 4:
                    max_ts = max(max_ts, int.from_bytes(p[0:4], "little"))
                total += 1
                yield t, p, raw
            nxt = max_ts + 1
            progressed = bool(batch) and nxt > cursor
            if progressed:
                cursor = nxt
                if on_batch:
                    on_batch(cursor)
            if not summary or summary["bytes_left"] == 0 or not progressed:
                break
        # ack-fetch (open_ring §10 step 10, phone-verified): GetEvent with
        # max_events=0 and the final cursor tells the ring the events were
        # consumed — without it, the same events stream again next session.
        try:
            payload = (cursor.to_bytes(4, "little") + bytes([0x00])
                       + (0xFFFFFFFF).to_bytes(4, "little"))
            self.request(frame(0x10, payload), done=lambda t, p: t == 0x11,
                         timeout=10)
        except RuntimeError:
            pass


def native_key_file() -> Path:
    # The checkout may be in OneDrive. Keep newly-created native keys in
    # local application storage rather than an automatically synced folder.
    root = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local/share")))
    return root / "CrackedOura" / "ringlink" / "oura_key.hex"


def load_key(path=None) -> bytes:
    if path is None:
        path = native_key_file() if os.environ.get("OURA_TRANSPORT") == "native" else KEY_FILE
    if not path.exists():
        raise RuntimeError("No auth key. Complete explicit first-time pairing before connecting.")
    key = bytes.fromhex(path.read_text().strip())
    if len(key) != 16:
        raise ValueError("Auth key must contain exactly 16 bytes (32 hex characters)")
    return key
