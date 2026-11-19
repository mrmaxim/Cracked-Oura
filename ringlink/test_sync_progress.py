import asyncio
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import oura_bleak as native
from oura_protocol import OuraProtocol
from sync_progress import Progress


class FakeScanner:
    advertisements = []
    stopped = False

    def __init__(self, detection_callback):
        self.callback = detection_callback

    async def __aenter__(self):
        type(self).stopped = False
        for address in self.advertisements:
            self.callback(SimpleNamespace(address=address, name='Oura Ring 4'),
                          SimpleNamespace(service_uuids=[native.SERVICE], local_name='Oura Ring 4'))
        return self

    async def __aexit__(self, *exc):
        type(self).stopped = True


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_known_identity_stops_without_waiting_for_scan_deadline(self):
        FakeScanner.advertisements = ['OTHER', 'OURS']
        with patch('bleak.BleakScanner', FakeScanner):
            result = await asyncio.wait_for(native.discover_for_connection(30, 'OURS'), timeout=.5)
        self.assertEqual([r[0].address for r in result], ['OURS'])
        self.assertTrue(FakeScanner.stopped)

    async def test_unknown_identity_keeps_all_candidates_for_ambiguity_check(self):
        FakeScanner.advertisements = ['A', 'B']
        with patch('bleak.BleakScanner', FakeScanner):
            result = await native.discover_for_connection(.01)
        self.assertEqual(len(result), 2)
        self.assertTrue(FakeScanner.stopped)

    async def test_explicit_missing_address_never_substitutes_another_ring(self):
        FakeScanner.advertisements = ['OTHER']
        with patch('bleak.BleakScanner', FakeScanner):
            result = await native.discover_for_connection(.01, 'OURS', explicit=True)
        self.assertEqual(result, [])

    async def test_cached_rotated_address_can_fall_back_to_one_candidate(self):
        FakeScanner.advertisements = ['NEW']
        with patch('bleak.BleakScanner', FakeScanner):
            result = await native.discover_for_connection(.01, 'OLD')
        self.assertEqual(result[0][0].address, 'NEW')


class ProgressTests(unittest.TestCase):
    def test_heartbeat_runs_during_wait_and_stops_on_exit(self):
        heartbeat = threading.Event()
        messages = []
        def output(message, **kwargs):
            messages.append(message)
            if '(этап:' in message:
                heartbeat.set()
        with Progress(interval=.02, output=output) as progress:
            progress.set('Ожидание BLE')
            self.assertTrue(heartbeat.wait(.5))
        self.assertFalse(progress.thread.is_alive())
        self.assertTrue(messages[0].startswith('[00:00]'))

    def test_failed_auth_does_not_cache_unverified_address(self):
        with tempfile.TemporaryDirectory() as home:
            target = Path(home) / 'identity.json'
            with patch.object(native, 'identity_file', return_value=target):
                ring = native.NativeOuraRing()
                ring.conn = 'FOREIGN'
                with patch.object(OuraProtocol, 'authenticate', side_effect=RuntimeError('wrong key')):
                    with self.assertRaises(RuntimeError):
                        ring.authenticate(bytes(16))
                self.assertFalse(target.exists())

    def test_successful_auth_caches_address_for_next_run(self):
        with tempfile.TemporaryDirectory() as home:
            target = Path(home) / 'identity.json'
            with patch.object(native, 'identity_file', return_value=target):
                ring = native.NativeOuraRing()
                ring.conn = 'OURS'
                with patch.object(OuraProtocol, 'authenticate'):
                    ring.authenticate(bytes(16))
                self.assertEqual(json.loads(target.read_text())['address'], 'OURS')
                self.assertEqual(native.NativeOuraRing().address, 'OURS')


if __name__ == '__main__':
    unittest.main()
