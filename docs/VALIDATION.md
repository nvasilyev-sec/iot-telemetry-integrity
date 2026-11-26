# Local validation

Linux, Python 3.13.5, OpenSSL 3.5.5. Synthetic data only.

## Unit tests

```text
test_delete_and_append (test_integrity.MerkleTests.test_delete_and_append) ... ok
test_duplicate_keys (test_integrity.MerkleTests.test_duplicate_keys) ... ok
test_edit (test_integrity.MerkleTests.test_edit) ... ok
test_empty (test_integrity.MerkleTests.test_empty) ... ok
test_every_index_many_sizes (test_integrity.MerkleTests.test_every_index_many_sizes) ... ok
test_extra_sibling (test_integrity.MerkleTests.test_extra_sibling) ... ok
test_invalid_base64 (test_integrity.MerkleTests.test_invalid_base64) ... ok
test_invalid_digest (test_integrity.MerkleTests.test_invalid_digest) ... ok
test_invalid_index (test_integrity.MerkleTests.test_invalid_index) ... ok
test_jsonl_validation (test_integrity.MerkleTests.test_jsonl_validation) ... ok
test_missing_sibling (test_integrity.MerkleTests.test_missing_sibling) ... ok
test_modified_sibling (test_integrity.MerkleTests.test_modified_sibling) ... ok
test_reorder (test_integrity.MerkleTests.test_reorder) ... ok
test_single_record (test_integrity.MerkleTests.test_single_record) ... ok
test_tampered_record (test_integrity.MerkleTests.test_tampered_record) ... ok
test_wrong_requested_index (test_integrity.MerkleTests.test_wrong_requested_index) ... ok
test_bad_signature (test_integrity.SignatureTests.test_bad_signature) ... ok
test_modified_count (test_integrity.SignatureTests.test_modified_count) ... ok
test_modified_root (test_integrity.SignatureTests.test_modified_root) ... ok
test_signed_unsupported_version (test_integrity.SignatureTests.test_signed_unsupported_version) ... ok
test_valid_signature (test_integrity.SignatureTests.test_valid_signature) ... ok
test_wrong_key (test_integrity.SignatureTests.test_wrong_key) ... ok

----------------------------------------------------------------------
Ran 22 tests in 0.468s

OK
```

## CLI demo

```text
PASS | Generate 17 synthetic records | {"count": 17, "status": "OK"}
PASS | Generate temporary keypair | {"algorithm": "RSA-3072", "status": "OK"}
PASS | Seal dataset | {"count": 17, "root": "fb89b960274f6d396f97cd51a36ffe05e5163c720b135352feca74ab18a3ae25", "status": "OK"}
PASS | Verify original | {"count": 17, "root": "fb89b960274f6d396f97cd51a36ffe05e5163c720b135352feca74ab18a3ae25", "status": "VERIFIED"}
PASS | Prove arbitrary index 12 | {"index": 12, "siblings": 5, "status": "OK"}
PASS | Verify inclusion without dataset | {"count": 17, "index": 12, "status": "VERIFIED"}
PASS | Reject edited dataset | {"status": "FAILED", "reason": "dataset differs from authenticated manifest"}
PASS | Reject reordered dataset | {"status": "FAILED", "reason": "dataset differs from authenticated manifest"}
PASS | Reject deleted dataset | {"status": "FAILED", "reason": "dataset differs from authenticated manifest"}
PASS | Reject appended dataset | {"status": "FAILED", "reason": "dataset differs from authenticated manifest"}
PASS | Reject altered proof | {"status": "FAILED", "reason": "proof does not match authenticated manifest or requested index"}
PASS | Reject wrong requested index | {"status": "FAILED", "reason": "proof does not match authenticated manifest or requested index"}
PASS | Reject changed signed manifest | {"status": "FAILED", "reason": "OpenSSL operation failed: [signature rejected]"}
13/13 demo checks passed
```

OpenSSL diagnostic detail shortened for readability.

## Benchmark

```jsonl
{"build_ms": 0.155, "proof_verify_ms": 0.032, "records": 100, "siblings": 7, "status": "OK"}
{"build_ms": 1.079, "proof_verify_ms": 0.036, "records": 1000, "siblings": 10, "status": "OK"}
{"build_ms": 9.979, "proof_verify_ms": 0.051, "records": 10000, "siblings": 14, "status": "OK"}
{"build_ms": 98.409, "proof_verify_ms": 0.063, "records": 100000, "siblings": 17, "status": "OK"}
```

Single-run timing for hashing only. No live MQTT or GitHub-hosted CI run was performed.
