"""Bounded native BLE experiments. Raw data/reports stay local; restores modes.

Reports distinguish notification delivery from samples packed inside records.
History throughput is NOT the physiological sampling rate.
"""
from collections import Counter, defaultdict
import json
from queue import Empty
import statistics
import time

from oura_bleak import NativeOuraRing, ensure_idle
from oura_protocol import HERE, EVENTS_FILE, load_key, native_key_file, frame
from openring import framing, decoders

OUT = HERE / 'online_probe'
LOCK = HERE / '.online_probe.lock'


def intervals(values):
    # Zero gaps matter: WinRT can deliver several notifications in one burst.
    # Dropping them would disguise batching as regularly spaced delivery.
    gaps = [b - a for a, b in zip(values, values[1:]) if b >= a]
    return None if not gaps else {'median_s': round(statistics.median(gaps), 4),
                                  'min_s': round(min(gaps), 4),
                                  'max_s': round(max(gaps), 4)}


def summarize(rows, duration):
    packets = Counter()
    records = Counter()
    sample_counts = Counter()
    arrivals = defaultdict(list)
    seen = set()
    for row in rows:
        raw, ts = bytes.fromhex(row['raw']), row['mono']
        if not raw:
            continue
        packets[f'0x{raw[0]:02x}'] += 1
        if raw[0] == 0x33:
            # Native real-time ACM: rate byte, sequence byte, then int16 xyz.
            if len(raw) >= 10 and len(raw) >= raw[1] + 2:
                sample_counts['realtime_accelerometer'] += (len(raw) - 4) // 6
                arrivals['realtime_accelerometer'].append(ts)
        elif framing.looks_like_outer_frame(raw):
            for outer in framing.parse_outer_frames(raw):
                p = outer.body
                if outer.opcode in (0x29, 0x11):
                    arrivals[f'control_0x{outer.opcode:02x}'].append(ts)
                if outer.opcode == 0x2f and len(p) >= 8 and p[:2] == b'\x28\x02':
                    ibi = int.from_bytes(p[6:8], 'little')
                    if ibi >> 12 == 1 and 300 <= (ibi & 0xfff) <= 2000:
                        sample_counts['live_hr_valid_ibi'] += 1
                        arrivals['live_hr_valid_ibi'].append(ts)
        else:
            for rec in framing.parse_inner_records(raw):
                key = (rec.type_byte, rec.ring_time, rec.payload)
                if key in seen:
                    continue
                seen.add(key)
                name = decoders.canonical_type(rec.type_byte)
                records[name] += 1
                arrivals[name].append(ts)
                data = decoders.decode(rec.type_byte, rec.payload)
                if rec.type_byte == 0x80:
                    sample_counts['green_ibi_valid'] += sum(
                        s['quality_a'] <= 1 and s['quality_b'] == 0
                        and 300 <= s['value_11bit'] <= 2000
                        for s in data.get('samples', []))
                if rec.type_byte == 0x60:
                    sample_counts['ibi_stream'] += len(data.get('ibi_ms', []))
    return {'duration_s': round(duration, 3), 'notifications': len(rows),
            'notifications_per_s': round(len(rows) / duration, 3),
            'packet_tags': dict(packets), 'unique_inner_records': dict(records),
            'sample_counts': dict(sample_counts),
            'received_samples_per_s': {k: round(n / duration, 3) for k, n in sample_counts.items()},
            'notification_intervals': {k: intervals(v) for k, v in arrivals.items()},
            'note': 'Reception rate; buffered history/batched samples do not imply a live sampling frequency.'}


class ProbeRing(NativeOuraRing):
    def __init__(self):
        super().__init__()
        self.phase = None
        self.rows = []

    def _notification(self, characteristic, data):
        if self.phase is not None:
            self.rows.append({'phase': self.phase, 'ts': time.time(),
                              'mono': time.monotonic(), 'raw': bytes(data).hex()})
        super()._notification(characteristic, data)


def set_dhr_submode(ring, value):
    replies = ring.request(bytes([0x2f, 3, 0x26, 2, value]),
                           done=lambda t, p: t == 0x2f and p[:2] == b'\x27\x02', timeout=5)
    p = ring.find(replies, 0x2f, ext=0x27)
    if p is None or len(p) < 3 or p[1] != 2 or p[2] != 0:
        raise RuntimeError('Daytime HR sub-mode write not acknowledged')
    # Ring 4's 0x26 setter changes parameter BYTE 2 (payload[4]), not
    # BYTE 3. The Rust generic client calls BYTE 3 "subscription".
    if ring.feature_status(2)['state'] != value:
        raise RuntimeError('Daytime HR sub-mode read-back mismatch')


def restore(ring, original, realtime_started):
    errors = []
    if ring.conn is None:
        try:
            ring.connect()
            ring.authenticate(load_key(native_key_file()))
        except Exception as exc:
            return {'verified': False, 'errors': [f'reconnect: {exc}']}
    if realtime_started:
        try:
            ring._write(bytes.fromhex('060400000000'))
        except Exception as exc:
            errors.append(f'realtime off: {exc}')
    for feature, before in original.items():
        try:
            after = ring.feature_status(feature)
            if after['mode'] != before['mode']:
                ring.set_feature_mode(feature, before['mode'])
            if feature == 2 and ring.feature_status(2)['state'] != before['state']:
                set_dhr_submode(ring, before['state'])
            after = ring.feature_status(feature)
            if (after['mode'], after['subscription']) != (before['mode'], before['subscription']):
                raise RuntimeError('read-back mismatch')
        except Exception as exc:
            errors.append(f'feature {feature}: {exc}')
    return {'verified': not errors, 'errors': errors}


def run(live_only=False):
    ensure_idle()
    key = load_key(native_key_file())
    with LOCK.open('x') as f:
        f.write(str(__import__('os').getpid()))
    OUT.mkdir(exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    ring = ProbeRing()
    report = {'started_at': time.time(), 'phases': {}, 'errors': []}
    original = {}
    realtime_started = False
    cursor = 0
    try:
        ring.open()
        ring.connect()
        ring.authenticate(key)
        original = {i: ring.feature_status(i) for i in (2, 3, 4)}
        report['original_features'] = original
        report['battery_before'] = ring.battery()[0]
        ring.engage_data_plane()

        def drain():
            nonlocal cursor
            ring.data_flush()
            def advance(value):
                nonlocal cursor
                cursor = value
            with EVENTS_FILE.open('a', encoding='utf-8') as f:
                for tag, payload, raw in ring.drain_events(cursor, on_batch=advance):
                    f.write(json.dumps({'ts': time.time(), 'tag': tag, 'raw': raw.hex()}) + '\n')
                    f.flush()

        # Exclude initial backlog from rate measurements.
        drain()

        def phase(name, seconds, poll=None):
            print(f'[probe] START {name}: {seconds}s', flush=True)
            ring.phase = name
            start = time.monotonic()
            deadline = start + seconds
            next_poll = start
            while time.monotonic() < deadline:
                ring._check_link()
                if poll and time.monotonic() >= next_poll:
                    drain()
                    next_poll += poll
                # Consume notifications; measurements are captured by the tap.
                try:
                    ring.rx.get(timeout=.1)
                except Empty:
                    pass
            end = time.monotonic()
            ring.phase = None
            rows = [r for r in ring.rows if r['phase'] == name]
            summary = summarize(rows, end - start)
            report['phases'][name] = summary
            print(f'[probe] DONE {name}: {json.dumps(summary)}', flush=True)

        if not live_only:
            phase('automatic_push', 30)
        try:
            ring.set_feature_mode(2, 3)
            if live_only:
                phase('live_hr_mode3', 30)
            set_dhr_submode(ring, 2)
            phase('live_hr_submode2', 45)
        except Exception as exc:
            report['phases']['live_hr'] = {'error': str(exc)}
            print(f'[probe] live_hr unsupported/failed: {exc}', flush=True)
            ring._check_link()
        finally:
            ring.set_feature_mode(2, original[2]['mode'])
            set_dhr_submode(ring, original[2]['state'])

        if not live_only:
            realtime_started = True
            ring._write(frame(6, (0x20).to_bytes(4, 'little') + (1).to_bytes(2, 'little') + b'\0'))
            try:
                phase('realtime_accelerometer', 20)
            finally:
                ring._write(bytes.fromhex('060400000000'))
            phase('history_poll_20s', 45, poll=20)
            phase('history_poll_2s', 30, poll=2)
        report['battery_after'] = ring.battery()[0]
    except BaseException as exc:
        report['errors'].append(f'{type(exc).__name__}: {exc}')
        print(f'[probe] ERROR: {exc}', flush=True)
    finally:
        ring.phase = None
        report['restoration'] = restore(ring, original, realtime_started) if original else {
            'verified': False, 'errors': ['No feature snapshot; no test modes were set.']}
        try:
            ring.close()
        except Exception as exc:
            report['errors'].append(f'close: {exc}')
        report['finished_at'] = time.time()
        (OUT / f'{stamp}-raw.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in ring.rows))
        path = OUT / f'{stamp}-report.json'
        path.write_text(json.dumps(report, indent=2) + '\n')
        LOCK.unlink(missing_ok=True)
        print(f'[probe] RESTORE {json.dumps(report["restoration"])}', flush=True)
        print(f'[probe] Report: {path}', flush=True)
    return 1 if report['errors'] or not report['restoration']['verified'] else 0


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--live-only', action='store_true', help='Only compare live HR modes')
    raise SystemExit(run(live_only=ap.parse_args().live_only))
