"""Offline onboarding/transport regression tests; never touch the radio."""
import asyncio
from contextlib import redirect_stdout
import io
from pathlib import Path
from queue import Queue
import tempfile
import unittest
from unittest.mock import patch

import oura_bleak as native
from oura_protocol import OuraProtocol


class FakeRing:
    def __init__(self, key_path, fail_at=None):
        self.path = key_path
        self.fail_at = fail_at
        self.calls = []

    def step(self, name):
        self.calls.append(name)
        if self.fail_at == name:
            raise RuntimeError("simulated failure")

    def open(self):
        self.step('open')

    def close(self):
        self.step('close')

    def connect(self, attempts):
        assert attempts == 1
        assert len(bytes.fromhex(self.path.read_text().strip())) == 16
        self.step('connect')

    def set_auth_key(self, key):
        assert key == bytes.fromhex(self.path.read_text().strip())
        self.step('install')

    def authenticate(self, key):
        self.step('auth')

    def sync_time(self):
        self.step('time')

    def reconnect(self):
        self.step('reconnect')

    def battery(self):
        self.step('battery')
        return b'\x55'

    def request(self, data, **kwargs):
        self.step('auth_gate')
        return [(0x2f, b'\x2f\x01', b'')]


class PairingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Path(self.temp.name) / 'key.hex'
        self.home_patch = patch.object(native, 'HERE', Path(self.temp.name))
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.stage_patch = patch.object(native, 'record_stage')
        self.stage = self.stage_patch.start()
        self.addCleanup(self.stage_patch.stop)

    def pair(self, ring):
        with redirect_stdout(io.StringIO()) as output:
            native.pair_new_ring(ring, self.key)
        return output.getvalue()

    def test_key_saved_before_connection_and_rechecked_after_reconnect(self):
        ring = FakeRing(self.key)
        output = self.pair(ring)
        self.assertEqual(ring.calls, ['open', 'connect', 'install', 'auth', 'time',
                                      'reconnect', 'auth_gate', 'auth', 'battery', 'close'])
        self.stage.assert_called_with('verified_after_reconnect')
        self.assertNotIn(self.key.read_text().strip(), output)

    def test_existing_key_is_not_overwritten_or_connected(self):
        self.key.write_text('01' * 16)
        ring = FakeRing(self.key)
        with self.assertRaises(FileExistsError):
            self.pair(ring)
        self.assertEqual(self.key.read_text(), '01' * 16)
        self.assertEqual(ring.calls, [])

    def test_uncertain_install_keeps_key_and_does_not_retry(self):
        ring = FakeRing(self.key, fail_at='install')
        with self.assertRaises(RuntimeError):
            self.pair(ring)
        self.assertEqual(len(bytes.fromhex(self.key.read_text().strip())), 16)
        self.assertEqual(ring.calls.count('connect'), 1)
        self.assertEqual(ring.calls[-1], 'close')
        self.assertNotIn('reconnect', ring.calls)

    def test_failed_reconnect_is_not_reported_as_success(self):
        ring = FakeRing(self.key, fail_at='reconnect')
        with self.assertRaises(RuntimeError):
            self.pair(ring)
        self.assertTrue(self.key.exists())
        self.assertNotIn(unittest.mock.call('verified_after_reconnect'), self.stage.call_args_list)

    def test_unprotected_battery_after_reconnect_is_not_success(self):
        ring = FakeRing(self.key)
        ring.request = lambda *a, **kw: [(0x0d, b'\x55', b'')]
        with self.assertRaisesRegex(RuntimeError, 'key persistence NOT verified'):
            self.pair(ring)
        self.assertTrue(self.key.exists())
        self.assertNotIn(unittest.mock.call('verified_after_reconnect'), self.stage.call_args_list)

    def test_daemon_lock_prevents_key_creation(self):
        (native.HERE / '.daemon.lock').write_text('123')
        ring = FakeRing(self.key)
        with self.assertRaises(RuntimeError):
            self.pair(ring)
        self.assertFalse(self.key.exists())
        self.assertEqual(ring.calls, [])

    def test_pair_requires_explicit_manual_reset_flag(self):
        with patch.object(native, 'NativeOuraRing') as factory:
            with redirect_stdout(io.StringIO()), patch('sys.stderr', io.StringIO()):
                with self.assertRaises(SystemExit):
                    native.main(['pair'])
            factory.assert_not_called()

    def test_missing_key_refuses_before_radio_open(self):
        with patch.object(native, 'load_key', side_effect=RuntimeError('no key')):
            with patch.object(native, 'NativeOuraRing') as factory:
                with self.assertRaises(RuntimeError):
                    native.main(['battery'])
                factory.return_value.open.assert_not_called()


class NativeTransportTests(unittest.TestCase):
    def test_one_loop_keeps_servicing_callbacks_between_sync_calls(self):
        ring = native.NativeOuraRing()
        ring.open()
        try:
            async def schedule_notification():
                asyncio.get_running_loop().call_later(.01, ring._notification, None, b'abc')
            ring._run(schedule_notification())
            self.assertEqual(ring.rx.get(timeout=1), b'abc')
        finally:
            ring.close()
        self.assertIsNone(ring.thread)

    def test_multiple_rings_refuse_before_connect(self):
        async def several(*args):
            return [(object(), object()), (object(), object())]
        ring = native.NativeOuraRing()
        with patch.object(native, 'discover_for_connection', several), patch('bleak.BleakClient') as client:
            with self.assertRaisesRegex(RuntimeError, 'Several'):
                asyncio.run(ring._connect(1))
            client.assert_not_called()

    def test_native_selection_does_not_import_nordic_driver(self):
        import ring_transport
        with patch.dict('os.environ', {'OURA_TRANSPORT': 'native'}):
            self.assertIsInstance(ring_transport.create_ring(), native.NativeOuraRing)


class ProtocolTests(unittest.TestCase):
    def test_feature_mode_requires_ack_and_readback(self):
        class Ring(OuraProtocol):
            def request(self, data, **kwargs):
                if data == bytes.fromhex('2f03220401'):
                    return [(0x2f, bytes.fromhex('230400'), b'')]
                if data == bytes.fromhex('2f022004'):
                    return [(0x2f, bytes.fromhex('210401000000'), b'')]
                raise AssertionError(data)
        self.assertEqual(Ring().set_feature_mode(4, 1)['mode'], 1)

    def test_rejected_measurement_mode_is_not_success(self):
        ring = OuraProtocol()
        ring.request = lambda *a, **kw: [(0x2f, bytes.fromhex('230401'), b'')]
        with self.assertRaisesRegex(RuntimeError, 'rejected'):
            ring.set_feature_mode(4, 1)

    def test_feature_readback_mismatch_is_not_success(self):
        ring = OuraProtocol()
        ring.request = lambda *a, **kw: [(0x2f, bytes.fromhex('230400'), b'')]
        ring.feature_status = lambda feature: {'mode': 0}
        with self.assertRaisesRegex(RuntimeError, 'did not retain'):
            ring.set_feature_mode(4, 1)

    def test_auth_proof_uses_nonce_and_wrong_key_is_rejected(self):
        class Ring(OuraProtocol):
            verbose = False
            def __init__(self):
                self.sent = []
            def request(self, data, **kwargs):
                self.sent.append(data)
                if data == b'\x2f\x01\x2b':
                    return [(0x2f, b'\x2c' + bytes(15), b'')]
                if data[:3] == b'\x2f\x11\x2d':
                    return [(0x2f, b'\x2e\x01', b'')]
                return []
        ring = Ring()
        with self.assertRaisesRegex(RuntimeError, 'wrong key'):
            ring.authenticate(bytes(16))
        # AES-128 zero key, a 15-byte zero nonce + PKCS7 0x01.
        self.assertEqual(ring.sent[-1].hex(), '2f112d58e2fccefa7e3061367f1d57a4e7455a')

    def test_verbose_request_does_not_print_auth_key(self):
        class Ring(OuraProtocol):
            verbose = True
            def __init__(self):
                self.rx = Queue()
            def _check_link(self):
                pass
            def _write(self, data):
                self.rx.put(b'\x25\x01\x00')
        with redirect_stdout(io.StringIO()) as output:
            Ring().set_auth_key(bytes.fromhex('12' * 16))
        self.assertNotIn('12' * 16, output.getvalue())


if __name__ == '__main__':
    unittest.main()
