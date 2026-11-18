"""Download buffered history once, disconnect, and import into local SQLite.

Use --import-only to process saved frames without opening any BLE connection.
No daemon, scheduled task, network access or online stream is started.
"""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


def import_saved(events_path):
    from backend.src.database import DB_PATH, SessionLocal, init_db
    from backend.src.ingestion.manager import OuraParser
    import decode_events
    from offline_store import persist

    init_db()
    records = decode_events.cmd_decode(events_path, decode_events.DECODED_FILE)
    stats = persist(DB_PATH, events_path, records)
    # Use the stable canonical event times stored in SQLite for the dashboard.
    decode_events.cmd_export(events_path, min_temp_c=20, records=records)
    with SessionLocal() as session:
        OuraParser(session).parse_zip(str(decode_events.EXPORT_ZIP))
    with closing(sqlite3.connect(DB_PATH)) as db:
        stats['dashboard_rows'] = {table: db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                                   for table in ('heart_rate', 'temperature', 'ring_battery',
                                                 'sleep', 'sleep_session', 'readiness', 'activity')}
    stats['database'] = str(DB_PATH)
    return stats


def main(argv=None):
    from oura_bleak import ensure_idle
    from sync_ring import LOCK_DIR, EVENTS_FILE, write_status, now_iso, run_ring_session, release_sync_lock
    from backend.src.database import DB_PATH, init_db
    # Fail before contacting the ring if database/parser dependencies are absent.
    from backend.src.ingestion.manager import OuraParser
    from offline_store import init_store

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--import-only', action='store_true')
    ap.add_argument('--events', type=Path, default=EVENTS_FILE)
    ap.add_argument('--address', help='Optional address of the intended Oura ring')
    args = ap.parse_args(argv)
    if not args.import_only and args.events.resolve() != EVENTS_FILE.resolve():
        ap.error('--events is only supported together with --import-only')
    ensure_idle()
    init_db()
    init_store(DB_PATH)
    # Use the same lock as the dashboard Sync button and one-shot sync.
    LOCK_DIR.mkdir()
    frames = 0
    try:
        os.environ['OURA_TRANSPORT'] = 'native'
        if args.address:
            os.environ['OURA_ADDRESS'] = args.address
        if not args.import_only:
            write_status('syncing', phase='connecting', last_error=None)
            frames = run_ring_session()  # Always disconnects in finally.
        if not args.events.exists():
            raise RuntimeError('No saved frames; run sync with the ring first')
        write_status('syncing', phase='ingesting', connected=False)
        stats = import_saved(args.events)
        write_status('idle', phase=None, connected=False, last_sync_ok=True,
                     last_sync_time=now_iso(), last_frames=frames, last_error=None,
                     sync_mode='offline', database=stats['database'])
        print('[offline] ' + json.dumps(stats), flush=True)
        return 0
    except BaseException as exc:
        write_status('idle', phase=None, connected=False, last_sync_ok=False,
                     last_error=f'{type(exc).__name__}: {exc}')
        raise
    finally:
        release_sync_lock()


if __name__ == '__main__':
    raise SystemExit(main())
