"""Durable raw and decoded Ring 4 history in the dashboard's SQLite database."""
import hashlib
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time


def event_id(record):
    # Arrival time and decoded values are intentionally not in the identity:
    # overlapping BLE downloads and decoder improvements must not duplicate it.
    identity = [record.get('generation', 0), record['type'], record['ring_time'],
                record['payload'].hex()]
    return hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()


def init_store(db_path):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path, timeout=30)) as db, db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS ring_raw_frames (
                frame_id TEXT PRIMARY KEY,
                received_at REAL NOT NULL,
                tag INTEGER,
                raw BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ring_events (
                event_id TEXT PRIMARY KEY,
                generation INTEGER NOT NULL,
                ring_time INTEGER,
                type INTEGER,
                name TEXT NOT NULL,
                payload BLOB NOT NULL,
                utc_ms INTEGER,
                utc_source TEXT,
                received_at REAL NOT NULL,
                data_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ring_events_time ON ring_events(utc_ms);
            CREATE INDEX IF NOT EXISTS ring_events_type_time ON ring_events(type, utc_ms);
            CREATE TABLE IF NOT EXISTS ring_imports (
                id INTEGER PRIMARY KEY,
                finished_at REAL NOT NULL,
                frames_added INTEGER NOT NULL,
                events_added INTEGER NOT NULL,
                event_count INTEGER NOT NULL
            );
        ''')


def persist(db_path, events_path, records):
    """Atomic raw+decoded import. Return stable times for existing event IDs.

    Store every raw receipt for audit, but dedupe decoded events by boot lineage,
    ring counter, type and original payload. No raw data or secrets are logged.
    Existing event times stay stable so reimports do not shift dashboard rows.
    All observations remain available for future explicit clock reprocessing.
    """
    init_store(db_path)
    canonical_times = {}
    with closing(sqlite3.connect(db_path, timeout=30)) as db, db:
        before_frames = db.execute('SELECT count(*) FROM ring_raw_frames').fetchone()[0]
        before_events = db.execute('SELECT count(*) FROM ring_events').fetchone()[0]
        with Path(events_path).open(encoding='utf-8') as source:
            for line in source:
                if not line.strip():
                    continue
                row = json.loads(line)
                raw = bytes.fromhex(row['raw'])
                stamp = float(row['ts'])
                key = hashlib.sha256(json.dumps([stamp, raw.hex()]).encode()).hexdigest()
                db.execute('INSERT OR IGNORE INTO ring_raw_frames VALUES (?, ?, ?, ?)',
                           (key, stamp, row.get('tag'), raw))
        for rec in records:
            key = event_id(rec)
            db.execute('''INSERT INTO ring_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    name=excluded.name, data_json=excluded.data_json,
                    utc_ms=coalesce(ring_events.utc_ms, excluded.utc_ms),
                    utc_source=CASE WHEN ring_events.utc_ms IS NULL
                        THEN excluded.utc_source ELSE ring_events.utc_source END''',
                (key, rec.get('generation', 0), rec['ring_time'], rec['type'], rec['name'],
                 rec['payload'], rec.get('utc_ms'), rec.get('utc_source'), rec['host_ts'],
                 json.dumps(rec['data'], separators=(',', ':'))))
            canonical_times[key] = db.execute(
                'SELECT utc_ms, utc_source FROM ring_events WHERE event_id=?', (key,)).fetchone()
        frames = db.execute('SELECT count(*) FROM ring_raw_frames').fetchone()[0]
        events = db.execute('SELECT count(*) FROM ring_events').fetchone()[0]
        stats = {'frames_added': frames - before_frames, 'events_added': events - before_events,
                 'raw_frames': frames, 'events': events}
        db.execute('INSERT INTO ring_imports(finished_at, frames_added, events_added, event_count) VALUES (?, ?, ?, ?)',
                   (time.time(), stats['frames_added'], stats['events_added'], events))
    # Only mutate projections after the transaction has committed successfully.
    for rec in records:
        rec['utc_ms'], rec['utc_source'] = canonical_times[event_id(rec)]
    return stats
