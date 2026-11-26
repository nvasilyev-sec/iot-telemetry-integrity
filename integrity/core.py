"""Exact-byte JSONL records and signed, versioned integrity manifests."""
import base64
import binascii
import json
import subprocess
from pathlib import Path
from .merkle import MerkleTree, decode_digest, verify_path

SCHEME = 'sha256-domain-separated-promote-odd-v1'
FORMAT = 'utf8-jsonl-lf-v1'


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f'nonstandard JSON constant: {value}')


def parse_json(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                      parse_constant=_reject_constant)


def read_records(path):
    raw = Path(path).read_bytes()
    if b'\r' in raw:
        raise ValueError('only LF line endings supported')
    records = raw.split(b'\n')
    if records[-1] == b'':
        records.pop()
    if not records:
        raise ValueError('empty dataset')
    for record in records:
        if not isinstance(parse_json(record), dict):
            raise ValueError('each JSONL record must be a JSON object')
    return records


def json_bytes(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def make_manifest(records):
    return {'version': 1, 'scheme': SCHEME, 'format': FORMAT,
            'count': len(records), 'root': MerkleTree(records).root}


def validate_manifest(raw):
    obj = parse_json(raw)
    if not isinstance(obj, dict) or set(obj) != {'version','scheme','format','count','root'}:
        raise ValueError('invalid manifest fields')
    if type(obj['version']) is not int or obj['version'] != 1 or obj['scheme'] != SCHEME or obj['format'] != FORMAT:
        raise ValueError('unsupported manifest version or scheme')
    if type(obj['count']) is not int or obj['count'] < 1:
        raise ValueError('invalid record count')
    decode_digest(obj['root'])
    return obj


def _openssl(args, data=None):
    result = subprocess.run(['openssl', *map(str, args)], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise ValueError('OpenSSL operation failed: ' + result.stderr.decode(errors='replace').strip())
    return result.stdout


def generate_keys(private, public):
    private, public = Path(private), Path(public)
    if private.resolve() == public.resolve() or private.exists() or public.exists():
        raise ValueError('key output paths must be distinct and must not exist')
    # Exclusive creation with restrictive permissions before any private material is written.
    import os
    with os.fdopen(os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as handle:
        handle.write(_openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072']))
    with public.open('xb') as handle:
        handle.write(_openssl(['pkey', '-in', private, '-pubout']))


def sign_manifest(raw, private):
    return _openssl(['dgst', '-sha256', '-sign', private], raw)


def authenticated_manifest(manifest, signature, public):
    raw = Path(manifest).read_bytes()
    # Verify the exact bytes that will be parsed, rather than reopening the manifest.
    _openssl(['dgst', '-sha256', '-verify', public, '-signature', signature], raw)
    return validate_manifest(raw)


def matches(records, manifest):
    return make_manifest(records) == manifest


def build_proof(records, index):
    tree = MerkleTree(records)
    siblings = tree.proof(index)
    return {'version': 1, 'index': index,
            'record_b64': base64.b64encode(records[index]).decode('ascii'), 'siblings': siblings}


def check_proof(proof, manifest, expected_index=None):
    if not isinstance(proof, dict) or set(proof) != {'version','index','record_b64','siblings'}:
        raise ValueError('invalid proof fields')
    if type(proof['version']) is not int or proof['version'] != 1:
        raise ValueError('unsupported proof version')
    if type(proof['index']) is not int:
        raise ValueError('invalid proof index')
    if expected_index is not None and proof['index'] != expected_index:
        return False
    if not isinstance(proof['record_b64'], str):
        raise ValueError('invalid proof record')
    try:
        record = base64.b64decode(proof['record_b64'], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError('invalid base64 record') from exc
    if b'\r' in record or b'\n' in record or not isinstance(parse_json(record), dict):
        raise ValueError('invalid JSONL proof record')
    return verify_path(record, proof['index'], manifest['count'], proof['siblings'], manifest['root'])
