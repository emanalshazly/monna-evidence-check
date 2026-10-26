import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from monna_evidence_check.checker import (
    InputError, MAX_FILE_BYTES, MAX_MANIFEST_BYTES, check_manifest, load_manifest, render_markdown,
)


class CheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        raw = b'{"synthetic":true,"output":"example"}\n'
        (self.root/'output.json').write_bytes(raw)
        self.data = {
            'schema_version': 1, 'label': 'Synthetic test', 'synthetic': True,
            'plan': {'case_ids':['A'], 'repetitions':1},
            'summary': {'planned':1,'attempted':1,'completed':1,'scored':1,'successful':1},
            'attempts':[{'attempt_id':'A1','case_id':'A','repetition':1,'status':'success','scored':True,'evidence_ids':['E1']}],
            'evidence':[{'evidence_id':'E1','path':'output.json','sha256':hashlib.sha256(raw).hexdigest()}],
            'claims':[],
        }

    def report(self):
        return check_manifest(self.data, self.root)

    def codes(self):
        return {f['code'] for f in self.report()['findings']}

    def test_clean_manifest_passes_without_certifying_truth(self):
        result = self.report()
        self.assertEqual(result['check_status'], 'PASS')
        self.assertFalse(result['claim_truth_assessed'])
        self.assertIn('Does not authenticate execution', result['scope'])

    def test_laundered_summary_fails(self):
        self.data['attempts'][0].update(status='error', scored=False)
        self.assertEqual(self.report()['check_status'], 'FAIL')
        self.assertIn('COUNT_MISMATCH', self.codes())

    def test_missing_planned_slot_fails(self):
        self.data['plan']['case_ids'].append('B')
        self.data['summary']['planned'] = 2
        self.assertIn('MISSING_PLANNED_SLOTS', self.codes())

    def test_explicit_not_run_is_structurally_valid(self):
        self.data['attempts'][0].update(status='not_run', scored=False, evidence_ids=[])
        self.data['summary'].update(attempted=0, completed=0, scored=0, successful=0)
        self.assertEqual(self.report()['check_status'], 'PASS')

    def test_failed_run_can_have_structural_pass(self):
        self.data['attempts'][0]['status'] = 'failure'
        self.data['summary']['successful'] = 0
        self.assertEqual(self.report()['check_status'], 'PASS')

    def test_retry_retains_original_error_and_denominators(self):
        self.data['attempts'][0].update(status='error', scored=False)
        self.data['attempts'].append({'attempt_id':'A2','case_id':'A','repetition':1,
            'status':'success','scored':True,'evidence_ids':['E1'],'retry_of':'A1'})
        self.data['summary']['attempted'] = 2
        result = self.report()
        self.assertEqual(result['check_status'], 'PASS')
        self.assertEqual(result['unscored_attempted'], 1)

    def test_duplicate_attempt_id_fails(self):
        self.data['attempts'].append(copy.deepcopy(self.data['attempts'][0]))
        self.assertIn('DUPLICATE_ATTEMPT', self.codes())

    def test_unlinked_retry_fails(self):
        row = copy.deepcopy(self.data['attempts'][0]); row['attempt_id'] = 'A2'
        self.data['attempts'].append(row)
        self.assertIn('MISSING_RETRY_LINK', self.codes())

    def test_retry_forward_reference_fails(self):
        self.data['attempts'][0]['retry_of'] = 'FUTURE'
        self.assertIn('INVALID_RETRY', self.codes())

    def test_retry_wrong_case_fails(self):
        self.data['plan']['case_ids'].append('B')
        row = copy.deepcopy(self.data['attempts'][0]); row.update(attempt_id='B1', case_id='B', retry_of='A1')
        self.data['attempts'].append(row)
        self.assertIn('INVALID_RETRY', self.codes())

    def test_retry_branch_fails(self):
        for aid in ('A2', 'A3'):
            row = copy.deepcopy(self.data['attempts'][0]); row.update(attempt_id=aid, retry_of='A1')
            self.data['attempts'].append(row)
        self.assertIn('INVALID_RETRY', self.codes())

    def test_not_run_cannot_be_retry_parent(self):
        self.data['attempts'][0].update(status='not_run', scored=False)
        row = copy.deepcopy(self.data['attempts'][0]); row.update(attempt_id='A2',status='success',scored=True,retry_of='A1')
        self.data['attempts'].append(row)
        self.assertIn('INVALID_RETRY', self.codes())

    def test_scored_error_fails(self):
        self.data['attempts'][0]['status'] = 'error'
        self.assertIn('INVALID_SCORED_STATE', self.codes())

    def test_unplanned_attempt_fails(self):
        self.data['attempts'][0]['case_id'] = 'B'
        self.assertIn('UNPLANNED_ATTEMPT', self.codes())

    def test_missing_claim_attachment_is_unresolved(self):
        self.data['claims']=[{'claim_id':'C1','kind':'publication','statement':'Published','evidence_ids':[]}]
        self.assertEqual(self.report()['check_status'], 'UNRESOLVED')

    def test_attachment_does_not_certify_claim(self):
        self.data['claims']=[{'claim_id':'C1','kind':'publication','statement':'Published','evidence_ids':['E1']}]
        result = self.report()
        self.assertFalse(result['claim_truth_assessed'])
        self.assertIn('claim truth is not assessed', result['findings'][-1]['message'])

    def test_unknown_evidence_reference_fails(self):
        self.data['attempts'][0]['evidence_ids']=['MISSING']
        self.assertIn('UNKNOWN_EVIDENCE', self.codes())

    def test_missing_run_evidence_is_unresolved(self):
        self.data['attempts'][0]['evidence_ids']=[]
        self.assertEqual(self.report()['check_status'], 'UNRESOLVED')

    def test_missing_file_is_unresolved(self):
        (self.root/'output.json').unlink()
        self.assertEqual(self.report()['check_status'], 'UNRESOLVED')

    def test_tampered_file_fails(self):
        (self.root/'output.json').write_text('changed', encoding='utf-8')
        self.assertIn('HASH_MISMATCH', self.codes())

    def test_duplicate_evidence_id_fails(self):
        self.data['evidence'].append(copy.deepcopy(self.data['evidence'][0]))
        self.assertIn('DUPLICATE_EVIDENCE', self.codes())

    def test_duplicate_path_fails(self):
        row = copy.deepcopy(self.data['evidence'][0]); row['evidence_id']='E2'
        self.data['evidence'].append(row)
        self.assertIn('DUPLICATE_PATH', self.codes())

    def test_duplicate_claim_fails(self):
        row={'claim_id':'C1','kind':'other','statement':'Claim','evidence_ids':['E1']}
        self.data['claims']=[row, copy.deepcopy(row)]
        self.assertIn('DUPLICATE_CLAIM', self.codes())

    def test_path_traversal_and_platform_paths_fail(self):
        for path in ('../outside.txt','/etc/passwd','C:/private.txt','C:\\private.txt',
                     '//host/share','output.json:stream','./output.json','folder//file','NUL','CON.txt','file.','file '):
            with self.subTest(path=path):
                self.data['evidence'][0]['path']=path
                self.assertIn('UNSAFE_EVIDENCE', self.codes())

    def test_directory_is_not_evidence(self):
        (self.root/'folder').mkdir()
        self.data['evidence'][0]['path']='folder'
        self.assertIn('UNSAFE_EVIDENCE', self.codes())

    def test_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            target=Path(outside)/'private.txt'; target.write_text('private')
            try:
                (self.root/'link.txt').symlink_to(target)
            except OSError:
                self.skipTest('OS does not permit creating symlinks for this user')
            self.data['evidence'][0]['path']='link.txt'
            self.assertIn('UNSAFE_EVIDENCE', self.codes())

    def test_linked_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as outer:
            link=Path(outer)/'link'
            try:
                link.symlink_to(self.root, target_is_directory=True)
            except OSError:
                self.skipTest('OS does not permit creating symlinks for this user')
            with self.assertRaises(InputError):
                check_manifest(self.data, link)

    def test_oversized_file_is_rejected(self):
        with (self.root/'output.json').open('wb') as handle:
            handle.truncate(MAX_FILE_BYTES+1)
        self.assertIn('EVIDENCE_LIMIT', self.codes())

    def test_boolean_count_rejected(self):
        self.data['summary']['successful']=True
        with self.assertRaises(InputError): self.report()

    def test_unknown_fields_rejected(self):
        self.data['secret_extra']='not checked'
        with self.assertRaises(InputError): self.report()

    def test_unknown_version_rejected(self):
        self.data['schema_version']=2
        with self.assertRaises(InputError): self.report()

    def test_duplicate_cases_rejected(self):
        self.data['plan']['case_ids']=['A','A']
        with self.assertRaises(InputError): self.report()

    def test_unknown_status_rejected(self):
        self.data['attempts'][0]['status']='published'
        with self.assertRaises(InputError): self.report()

    def test_unsafe_identifier_rejected(self):
        self.data['attempts'][0]['attempt_id']='A\x1b[31m'
        with self.assertRaises(InputError): self.report()

    def test_duplicate_json_keys_rejected(self):
        file=self.root/'bad.json'; file.write_text('{"a":1,"a":2}')
        with self.assertRaises(InputError): load_manifest(file)

    def test_nonfinite_json_rejected(self):
        file=self.root/'bad.json'; file.write_text('{"a":NaN}')
        with self.assertRaises(InputError): load_manifest(file)

    def test_oversized_manifest_rejected(self):
        file=self.root/'bad.json'; file.write_bytes(b' '*(MAX_MANIFEST_BYTES+1))
        with self.assertRaises(InputError): load_manifest(file)

    def test_bad_encoding_and_json_rejected(self):
        for raw in (b'\xff', b'{', b'[]'):
            file=self.root/'bad.json'; file.write_bytes(raw)
            with self.assertRaises(InputError): load_manifest(file)

    def test_markdown_does_not_render_supplied_html_or_link(self):
        self.data['label']='<script>alert(1)</script> [open](https://example.com)'
        text=render_markdown(self.report())
        self.assertNotIn('<script>', text)
        self.assertNotIn('[open](https://example.com)', text)

    def test_nonexistent_root_rejected(self):
        with self.assertRaises(InputError): check_manifest(self.data, self.root/'missing')

    def test_total_evidence_budget_is_enforced(self):
        self.data['evidence']=[]
        block=b'x'*(1024*1024)
        for index in range(6):
            path=self.root/f'large-{index}.bin'
            with path.open('wb') as handle:
                for _ in range(10): handle.write(block)
            self.data['evidence'].append({'evidence_id':f'L{index}','path':path.name,
                'sha256':hashlib.sha256(block*10).hexdigest()})
        self.data['attempts'][0]['evidence_ids']=['L0']
        self.assertIn('EVIDENCE_LIMIT',self.codes())

    def test_missing_repetition_is_reported(self):
        self.data['plan']['repetitions']=2
        self.data['summary']['planned']=2
        self.assertIn('MISSING_PLANNED_SLOTS',self.codes())

    def test_fail_has_precedence_over_missing_evidence(self):
        self.data['summary']['successful']=0
        self.data['attempts'][0]['evidence_ids']=[]
        result=self.report()
        self.assertEqual(result['check_status'],'FAIL')
        self.assertTrue(any(f['status']=='UNRESOLVED' for f in result['findings']))

    def test_evidence_content_is_never_executed(self):
        marker=self.root/'should-not-exist.txt'
        raw=b'raise RuntimeError("This is data, not executable code")\n'
        (self.root/'output.json').write_bytes(raw)
        self.data['evidence'][0]['sha256']=hashlib.sha256(raw).hexdigest()
        self.assertEqual(self.report()['check_status'],'PASS')
        self.assertFalse(marker.exists())

    def test_valid_manifest_loads_and_inputs_are_not_changed(self):
        file=self.root/'manifest.json'
        file.write_text(json.dumps(self.data),encoding='utf-8')
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        result=check_manifest(load_manifest(file),self.root)
        self.assertEqual(result['check_status'],'PASS')
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.root.iterdir()})

    def test_deeply_nested_json_is_input_error(self):
        file=self.root/'bad.json'; file.write_text('['*3000+'0'+']'*3000)
        with self.assertRaises(InputError): load_manifest(file)

    def test_cli_exit_codes_and_machine_output(self):
        file=self.root/'manifest.json'
        for expected, change in ((0,None),(2,'missing_claim'),(1,'bad_count'),(3,'bad_input')):
            data=copy.deepcopy(self.data)
            if change=='missing_claim':
                data['claims']=[{'claim_id':'C1','kind':'other','statement':'Claim','evidence_ids':[]}]
            if change=='bad_count': data['summary']['successful']=0
            if change=='bad_input': data['schema_version']=7
            file.write_text(json.dumps(data), encoding='utf-8')
            run=subprocess.run([sys.executable,'-m','monna_evidence_check',str(file),'--evidence-root',str(self.root),'--format','json'],capture_output=True,text=True)
            self.assertEqual(run.returncode,expected,run.stderr)
            parsed=json.loads(run.stderr if expected==3 else run.stdout)
            self.assertIn('check_status',parsed)

    def test_cli_missing_arguments_exit_three(self):
        run=subprocess.run([sys.executable,'-m','monna_evidence_check'],capture_output=True,text=True)
        self.assertEqual(run.returncode,3)


if __name__=='__main__':
    unittest.main()
