import base64
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import run


class EvidenceTests(unittest.TestCase):
    def test_ids_are_exact_and_reject_zero(self):
        raw = bytes.fromhex('1020304050607080')
        self.assertEqual(run.normalize(raw.hex(),8),raw.hex())
        self.assertEqual(run.normalize('123',8),'0000000000000123')
        self.assertEqual(run.normalize(base64.b64encode(raw).decode(),8),raw.hex())
        for invalid in ['00'*8,'11'*16,'invalid']:
            with self.assertRaises(ValueError):
                run.normalize(invalid,8)

    def test_cpu_accounting_and_overlap(self):
        payload={'flamegraph':{'names':['root','a','b'],'total':'30',
            'levels':[{'values':[0,30,0,0]},{'values':[0,10,10,1,0,20,20,2]}]}}
        with patch('run.request',return_value=payload):
            _, summary=run.profile(1,2,['1020304050607080'])
        self.assertEqual(summary['total_ns'],30)
        self.assertEqual(sum(x['self_ns'] for x in summary['functions']),30)
        self.assertEqual(sum(x['cumulative_ns'] for x in summary['functions']),60)
        payload['flamegraph']['total']='31'
        with patch('run.request',return_value=payload),self.assertRaises(ValueError):
            run.profile(1,2)

    def test_empty_samples_preserve_zero_and_backend_errors(self):
        with patch('run.request',return_value={}):
            _, result=run.profile(1,2)
            self.assertEqual(result['total_ns'],0)
        with patch('run.request',side_effect=OSError('backend unavailable')),self.assertRaises(OSError):
            run.profile(1,2)

    def test_export_visibility_retries_and_preserves_incompleteness(self):
        partial={'aggregate':{'total_ns':10},'cohorts':{'ordinary':{'traces_available':0}}}
        complete={'aggregate':{'total_ns':10},'cohorts':{'ordinary':{'traces_available':1}}}
        rows=[{'path':'/work','status':200,'start_ms':10,'end_ms':20}]
        with tempfile.TemporaryDirectory() as tmp, patch('run.collect',side_effect=[partial,complete]) as query, patch('run.time.sleep'):
            result=run.collect_until_visible(Path(tmp),'combined',10,20,rows)
            self.assertEqual(query.call_count,2)
            self.assertEqual(result['visibility']['state'],'available')
        with tempfile.TemporaryDirectory() as tmp, patch('run.collect',return_value=partial), patch('run.time.monotonic',side_effect=[0,100]):
            result=run.collect_until_visible(Path(tmp),'combined',10,20,rows)
            self.assertEqual(result['visibility']['state'],'incomplete')
            self.assertEqual(result['visibility']['target_traces'],0)

    def test_exact_span_link(self):
        link=run.profile_link(10,20,'1020304050607080')
        self.assertIn('var-spanSelector=1020304050607080',link)
        self.assertIn('from=10',link)
        self.assertIn('to=20',link)


if __name__=='__main__':
    unittest.main()
