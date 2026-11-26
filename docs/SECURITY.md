# Security model

## Trust boundary

The signer is trusted to obtain the intended records and protect the private key. A verifier must obtain the correct public key independently, know the expected snapshot and request the intended record position. An attacker may alter stored records, reorder or delete them, or modify manifests, signatures and proofs. SHA-256 collision/second-preimage resistance and signature unforgeability are assumed. Compromised signing keys or an untrusted signing process invalidate these guarantees.

## Design decisions

- Hash exact UTF-8 JSON object bytes, excluding LF delimiters. A final LF is optional; CRLF, blank lines, duplicate JSON keys and nonstandard constants are rejected. Reformatting a record changes its hash. Identical records are not distinguishable by content alone.
- Domain separation distinguishes leaves and branches. Unpaired nodes are promoted, and signed count/version/format constrain verification. A proof must supply exactly the siblings implied by the count and index.
- The entire exact manifest byte string is signed and verified before parsing. OpenSSL handles signature operations rather than custom RSA arithmetic. The generated demo key is RSA-3072 and the CLI uses OpenSSL's default RSA PKCS#1 v1.5 SHA-256 signing mode. Use a trusted RSA public key; algorithm/key policy enforcement is not a production feature.
- Key generation writes the private key with mode 0600. Demo keys are unencrypted, temporary and unsuitable for production. Keep real key material outside repositories; use encrypted storage or managed signing services in real deployments.
- Verification returns exit code 0 on success and 1 on failure. Invalid CLI usage uses argparse exit code 2. JSON proof records are disclosed in base64, not encrypted.

## Not covered

No assurance of sensor correctness, authenticated capture provenance, freshness or rollback resistance, timestamping, append-only consistency across snapshots, confidentiality, access control, resource limits for hostile huge inputs, hardware key management, or production availability. The implementation loads batches and tree layers in memory. A valid old manifest and corresponding old data can still verify. To handle rollback, bind a trusted snapshot identifier or monotonic sequence to an externally maintained reference. MQTT transport security depends on broker configuration and certificate validation; QoS 1 does not guarantee exactly-once delivery. Live broker operation was not tested here.

Never publish private keys, real customer data, secret-bearing logs, or unrestricted institutional coursework. Inspect all staged files before pushing. Git ignore rules are a convenience, not a security boundary.
