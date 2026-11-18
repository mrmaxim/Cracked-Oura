import json
from contextlib import closing
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from offline_store import persist, event_id


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.db = self.home / 'ring.db'
        self.raw = self.home / 'events.jsonl'
        self.raw.write_text(json.dumps({'ts': 1700000000, 'tag': 0x46, 'raw': '460401000000'}) + '\n')

    def record(self):
        return {'generation': 0, 'type': 0x46, 'ring_time': 1,
                'payload': b'\x01\x02', 'host_ts': 1700000000,
                'utc_ms': 1700000000000, 'utc_source': 'test',
                'name': 'API_TEMP_EVENT', 'data': {'temp1_c': 33}}

    def test_reimport_updates_decoder_but_preserves_identity_and_time(self):
        first = self.record()
        persist(self.db, self.raw, [first])
        second = self.record()
        second['utc_ms'] += 1000
        second['data']['temp1_c'] = 34
        result = persist(self.db, self.raw, [second])
        self.assertEqual(result['events_added'], 0)
        self.assertEqual(result['frames_added'], 0)
        self.assertEqual(second['utc_ms'], first['utc_ms'])
        with closing(sqlite3.connect(self.db)) as db:
            row = db.execute('SELECT data_json FROM ring_events').fetchone()
        self.assertEqual(json.loads(row[0])['temp1_c'], 34)

    def test_same_wire_record_after_reboot_is_distinct(self):
        a, b = self.record(), self.record()
        b['generation'] = 1
        self.assertNotEqual(event_id(a), event_id(b))
        result = persist(self.db, self.raw, [a, b])
        self.assertEqual(result['events'], 2)

    @unittest.skipUnless(sys.platform == 'win32', 'Windows read-only directory behavior')
    def test_readonly_sync_lock_is_released(self):
        import sync_ring
        lock = self.home / '.sync.lock'
        lock.mkdir()
        os.chmod(lock, stat.S_IREAD)
        with patch.object(sync_ring, 'LOCK_DIR', lock):
            sync_ring.release_sync_lock()
        self.assertFalse(lock.exists())

    def test_malformed_input_rolls_back_import(self):
        self.raw.write_text(self.raw.read_text() + 'not json\n')
        with self.assertRaises(json.JSONDecodeError):
            persist(self.db, self.raw, [self.record()])
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM ring_raw_frames').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT count(*) FROM ring_events').fetchone()[0], 0)

    def test_end_to_end_dashboard_import_twice_without_duplicates(self):
        # Synthetic good-quality IBI and a skin temperature. No personal data.
        def inner(tag, counter, payload):
            body = struct.pack('<I', counter) + payload
            return bytes([tag, len(body)]) + body
        ibi = inner(0x80, 100, bytes.fromhex('7d08') * 7)  # 1000 ms, quality_a=1,b=0
        temp = inner(0x46, 101, struct.pack('<7h', 3300, 3300, 3300, 0, 0, 0, 0))
        self.raw.write_text(json.dumps({'ts': 1700000000, 'tag': 0x80, 'raw': (ibi + temp).hex()}) + '\n')
        code = '''
import sys,json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import decode_events, ring_analysis
from offline_sync import import_saved
home=Path(sys.argv[2])
decode_events.HERE=home
decode_events.DECODED_FILE=home/'decoded.jsonl'
decode_events.EXPORT_DIR=home/'export'
decode_events.EXPORT_ZIP=home/'export.zip'
ring_analysis.PROFILE_FILE=home/'profile.json'
ring_analysis.BASELINES_FILE=home/'baselines.json'
a=import_saved(home/'events.jsonl')
b=import_saved(home/'events.jsonl')
assert a['dashboard_rows']==b['dashboard_rows'], (a,b)
assert b['events_added']==0 and b['frames_added']==0, b
assert b['dashboard_rows']['heart_rate']==1, b
assert b['dashboard_rows']['temperature']==1, b
print('IDEMPOTENT_IMPORT_OK')
'''
        env = dict(os.environ, CRACKED_OURA_DATA_DIR=str(self.home / 'db'))
        result = subprocess.run([sys.executable, '-c', code,
                                 str(Path(__file__).resolve().parent), str(self.home)],
                                env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('IDEMPOTENT_IMPORT_OK', result.stdout)


if __name__ == '__main__':
    unittest.main()
