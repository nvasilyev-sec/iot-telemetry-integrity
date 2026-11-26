"""Command-line entry point. Verification fails closed with a nonzero exit."""
import argparse
import json
import sys
import time
from pathlib import Path
from .core import (authenticated_manifest, build_proof, check_proof, generate_keys,
                   json_bytes, make_manifest, matches, parse_json, read_records, sign_manifest)
from .merkle import MerkleTree, verify_path


def synthetic(count):
    if count < 1:
        raise ValueError('count must be positive')
    return [json_bytes({'sequence': i+1, 'sensor': 'demo-01',
                        'temperature_c': round(21 + (i % 50) / 10, 1),
                        'humidity_pct': 42 + i % 12}).rstrip(b'\n') for i in range(count)]


def new_file(path, data):
    with Path(path).open('xb') as out:
        out.write(data)


def report(status, **fields):
    print(json.dumps({'status': status, **fields}, sort_keys=True))


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    q = sub.add_parser('generate', help='create synthetic telemetry JSONL')
    q.add_argument('output'); q.add_argument('--count', type=int, default=17)
    q = sub.add_parser('keygen', help='generate a demo RSA-3072 keypair')
    q.add_argument('private'); q.add_argument('public')
    q = sub.add_parser('seal', help='create and sign a manifest')
    q.add_argument('dataset'); q.add_argument('--private', required=True)
    q.add_argument('--manifest', required=True); q.add_argument('--signature', required=True)
    for cmd in ['verify','prove','verify-proof']:
        q = sub.add_parser(cmd)
        q.add_argument('proof' if cmd == 'verify-proof' else 'dataset')
        q.add_argument('--manifest', required=True); q.add_argument('--signature', required=True)
        q.add_argument('--public', required=True)
        if cmd == 'prove':
            q.add_argument('--index', type=int, required=True); q.add_argument('--output', required=True)
        if cmd == 'verify-proof':
            q.add_argument('--index', type=int, required=True, help='expected zero-based record position')
    q = sub.add_parser('benchmark', help='time hashing and inclusion verification on synthetic records')
    q.add_argument('--sizes', nargs='+', type=int, default=[100,1000,10000])
    return p


def run(a):
    if a.command == 'generate':
        new_file(a.output, b'\n'.join(synthetic(a.count)) + b'\n')
        report('OK', count=a.count)
    elif a.command == 'keygen':
        generate_keys(a.private, a.public); report('OK', algorithm='RSA-3072')
    elif a.command == 'seal':
        records = read_records(a.dataset)
        manifest = make_manifest(records); raw = json_bytes(manifest)
        sig = sign_manifest(raw, a.private)
        if Path(a.manifest).resolve() == Path(a.signature).resolve() or Path(a.manifest).exists() or Path(a.signature).exists():
            raise ValueError('output paths must be distinct and must not exist')
        new_file(a.manifest, raw); new_file(a.signature, sig)
        report('OK', count=manifest['count'], root=manifest['root'])
    elif a.command in ('verify','prove','verify-proof'):
        manifest = authenticated_manifest(a.manifest, a.signature, a.public)
        if a.command == 'verify-proof':
            if not check_proof(parse_json(Path(a.proof).read_bytes()), manifest, a.index):
                raise ValueError('proof does not match authenticated manifest or requested index')
            report('VERIFIED', index=a.index, count=manifest['count'])
        else:
            records = read_records(a.dataset)
            if not matches(records, manifest):
                raise ValueError('dataset differs from authenticated manifest')
            if a.command == 'verify':
                report('VERIFIED', count=len(records), root=manifest['root'])
            else:
                proof = build_proof(records, a.index)
                new_file(a.output, json_bytes(proof))
                report('OK', index=a.index, siblings=len(proof['siblings']))
    else:
        for count in a.sizes:
            records = synthetic(count)
            start = time.perf_counter(); tree = MerkleTree(records); build = time.perf_counter()-start
            index = count//2; path = tree.proof(index)
            start = time.perf_counter(); valid = verify_path(records[index], index, count, path, tree.root)
            verify = time.perf_counter()-start
            if not valid:
                raise ValueError('benchmark proof failed')
            report('OK', records=count, build_ms=round(build*1000,3), proof_verify_ms=round(verify*1000,3), siblings=len(path))


def main():
    args = parser().parse_args()
    try:
        run(args)
        return 0
    except (ValueError, OSError, TypeError) as exc:
        print(json.dumps({'status':'FAILED','reason':str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
