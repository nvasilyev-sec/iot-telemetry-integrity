import base64
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from integrity.merkle import MerkleTree, verify_path
from integrity.core import (read_records, make_manifest, matches, build_proof, check_proof,
                            generate_keys, json_bytes, sign_manifest, authenticated_manifest, parse_json)
from integrity.__main__ import synthetic


class MerkleTests(unittest.TestCase):
    def test_every_index_many_sizes(self):
        for n in [1,2,3,5,8,9,17,32,63,100]:
            rows = synthetic(n); tree = MerkleTree(rows)
            for i in range(n):
                with self.subTest(n=n, i=i):
                    self.assertTrue(verify_path(rows[i], i, n, tree.proof(i), tree.root))

    def test_single_record(self):
        rows = synthetic(1); tree = MerkleTree(rows)
        self.assertEqual(tree.proof(0), [])
        self.assertTrue(verify_path(rows[0], 0, 1, [], tree.root))

    def test_empty(self):
        with self.assertRaises(ValueError): MerkleTree([])

    def test_invalid_index(self):
        tree = MerkleTree(synthetic(3))
        for i in [-1,3,True]:
            with self.assertRaises(ValueError): tree.proof(i)

    def test_edit(self):
        rows = synthetic(7); m = make_manifest(rows)
        rows[3] = b'{"temperature_c":99}'
        self.assertFalse(matches(rows,m))

    def test_reorder(self):
        rows = synthetic(7); m = make_manifest(rows)
        rows[0],rows[1] = rows[1],rows[0]
        self.assertFalse(matches(rows,m))

    def test_delete_and_append(self):
        rows = synthetic(7); m = make_manifest(rows)
        self.assertFalse(matches(rows[:-1],m)); self.assertFalse(matches(rows+[rows[0]],m))

    def test_tampered_record(self):
        rows = synthetic(17); p = build_proof(rows, 4)
        p['record_b64'] = base64.b64encode(b'{"temperature_c":99}').decode()
        self.assertFalse(check_proof(p,make_manifest(rows),4))

    def test_wrong_requested_index(self):
        rows = synthetic(9); p = build_proof(rows, 2)
        self.assertFalse(check_proof(p,make_manifest(rows),3))

    def test_modified_sibling(self):
        rows = synthetic(9); p = build_proof(rows, 2); p['siblings'][0] = '00'*32
        self.assertFalse(check_proof(p,make_manifest(rows),2))

    def test_extra_sibling(self):
        rows = synthetic(9); p = build_proof(rows, 2); p['siblings'].append('00'*32)
        self.assertFalse(check_proof(p,make_manifest(rows),2))

    def test_missing_sibling(self):
        rows = synthetic(9); p = build_proof(rows, 2); p['siblings'].pop()
        with self.assertRaises(ValueError): check_proof(p,make_manifest(rows),2)

    def test_invalid_digest(self):
        rows = synthetic(9); p = build_proof(rows, 2); p['siblings'][0] = 'bad'
        with self.assertRaises(ValueError): check_proof(p,make_manifest(rows),2)

    def test_invalid_base64(self):
        rows = synthetic(9); p = build_proof(rows, 2); p['record_b64'] = '***'
        with self.assertRaises(ValueError): check_proof(p,make_manifest(rows),2)

    def test_duplicate_keys(self):
        with self.assertRaises(ValueError): parse_json(b'{"x":1,"x":2}')

    def test_jsonl_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'data'
            for raw in [b'',b'[]\n',b'{}\n\n',b'{}\r\n',b'{"x":NaN}\n',b'\xff']:
                p.write_bytes(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError): read_records(p)
            p.write_bytes(b'{"x":1}\n{"x":2}')
            self.assertEqual(len(read_records(p)),2)


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required')
class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.tmp.cleanup)
        cls.path = Path(cls.tmp.name)
        cls.private = cls.path/'private.pem'; cls.public = cls.path/'public.pem'
        generate_keys(cls.private,cls.public)
        cls.other_private = cls.path/'other-private.pem'; cls.other_public = cls.path/'other-public.pem'
        generate_keys(cls.other_private,cls.other_public)
        cls.rows = synthetic(17); cls.raw = json_bytes(make_manifest(cls.rows))
        cls.sig = cls.path/'manifest.sig'; cls.sig.write_bytes(sign_manifest(cls.raw,cls.private))

    def manifest(self, raw):
        p = self.path/'manifest.json'; p.write_bytes(raw); return p

    def test_valid_signature(self):
        self.assertEqual(authenticated_manifest(self.manifest(self.raw),self.sig,self.public),make_manifest(self.rows))

    def test_modified_count(self):
        obj = json.loads(self.raw); obj['count'] += 1
        with self.assertRaises(ValueError): authenticated_manifest(self.manifest(json_bytes(obj)),self.sig,self.public)

    def test_modified_root(self):
        obj = json.loads(self.raw); obj['root'] = '00'*32
        with self.assertRaises(ValueError): authenticated_manifest(self.manifest(json_bytes(obj)),self.sig,self.public)

    def test_wrong_key(self):
        with self.assertRaises(ValueError): authenticated_manifest(self.manifest(self.raw),self.sig,self.other_public)

    def test_bad_signature(self):
        sig = self.path/'bad.sig'; sig.write_bytes(b'bad')
        with self.assertRaises(ValueError): authenticated_manifest(self.manifest(self.raw),sig,self.public)

    def test_signed_unsupported_version(self):
        obj = json.loads(self.raw); obj['version'] = 2; raw = json_bytes(obj)
        sig = self.path/'unsupported.sig'; sig.write_bytes(sign_manifest(raw,self.private))
        with self.assertRaises(ValueError): authenticated_manifest(self.manifest(raw),sig,self.public)
