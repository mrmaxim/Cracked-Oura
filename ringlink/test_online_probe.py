import unittest
import struct
from online_probe import summarize, restore, set_dhr_submode, intervals


class ProbeTests(unittest.TestCase):
    def test_bursty_arrivals_do_not_look_uniform(self):
        gaps = intervals([0, 0, 0, 1, 1, 1, 2])
        self.assertEqual(gaps['median_s'], 0)
        self.assertEqual(gaps['max_s'], 1)

    def test_ring4_submode_is_byte2_not_subscription_byte3(self):
        class Ring:
            def request(self, *a, **kw):
                return [(0x2f, bytes.fromhex('270200'), b'')]
            def find(self, replies, *a, **kw):
                return replies[0][1]
            def feature_status(self, feature):
                return {'state': 2, 'subscription': 0}
        set_dhr_submode(Ring(), 2)

    def test_batched_motion_samples_are_not_counted_as_notifications(self):
        raw = bytes.fromhex('330e2001') + struct.pack('<6h', 1, 2, 3, 4, 5, 6)
        result = summarize([{'raw': raw.hex(), 'mono': 1}], 1)
        self.assertEqual(result['notifications'], 1)
        self.assertEqual(result['sample_counts']['realtime_accelerometer'], 2)
        self.assertIsNone(result['notification_intervals']['realtime_accelerometer'])

    def test_live_hr_validity_bit_filters_invalid_samples(self):
        valid = '2f08280200000000e813'
        invalid = '2f08280200000000e803'
        rows = [{'raw': raw, 'mono': t} for raw, t in [(valid, 1), (invalid, 1.2), (valid, 1.5)]]
        result = summarize(rows, 2)
        self.assertEqual(result['sample_counts']['live_hr_valid_ibi'], 2)
        self.assertEqual(result['notification_intervals']['live_hr_valid_ibi']['median_s'], .5)

    def test_repeated_history_is_deduplicated_within_phase(self):
        raw = '460a01000000c40900000000'
        result = summarize([{'raw': raw, 'mono': 1}, {'raw': raw, 'mono': 2}], 3)
        self.assertEqual(result['notifications'], 2)
        self.assertEqual(sum(result['unique_inner_records'].values()), 1)

    def test_restore_switches_back_even_after_test_exception(self):
        class Ring:
            conn = 'connected'
            modes = {2: 3, 3: 1, 4: 1}
            sent = []
            def _write(self, data):
                self.sent.append(data)
            def feature_status(self, feature):
                return {'mode': self.modes[feature], 'subscription': 0, 'state': 0}
            def set_feature_mode(self, feature, mode):
                self.modes[feature] = mode
        ring = Ring()
        original = {i: {'mode': 1, 'subscription': 0, 'state': 0} for i in (2, 3, 4)}
        result = restore(ring, original, True)
        self.assertTrue(result['verified'])
        self.assertEqual(ring.modes[2], 1)
        self.assertIn(bytes.fromhex('060400000000'), ring.sent)


if __name__ == '__main__':
    unittest.main()
