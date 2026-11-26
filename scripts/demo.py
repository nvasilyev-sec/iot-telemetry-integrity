"""End-to-end CLI exercise; all generated data and keys are temporary."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='integrity-demo-') as tmp:
        d = Path(tmp)
        def path(name): return str(d/name)
        auth = ['--manifest',path('manifest.json'),'--signature',path('manifest.sig'),'--public',path('public.pem')]
        checks = 0
        def call(label, *args, fail=False):
            nonlocal checks
            r = subprocess.run([sys.executable,'-m','integrity',*args],cwd=ROOT,capture_output=True,text=True)
            if r.returncode != (1 if fail else 0):
                raise RuntimeError(f'{label}: unexpected exit {r.returncode}: {r.stdout} {r.stderr}')
            print(f'PASS | {label} | {(r.stderr if fail else r.stdout).strip()}')
            checks += 1
        call('Generate 17 synthetic records','generate',path('original.jsonl'),'--count','17')
        call('Generate temporary keypair','keygen',path('private.pem'),path('public.pem'))
        call('Seal dataset','seal',path('original.jsonl'),'--private',path('private.pem'),'--manifest',path('manifest.json'),'--signature',path('manifest.sig'))
        call('Verify original','verify',path('original.jsonl'),*auth)
        call('Prove arbitrary index 12','prove',path('original.jsonl'),*auth,'--index','12','--output',path('proof.json'))
        call('Verify inclusion without dataset','verify-proof',path('proof.json'),*auth,'--index','12')
        rows = (d/'original.jsonl').read_bytes().splitlines()
        variants = {'edited': rows[:3]+[b'{"temperature_c":99}']+rows[4:], 'reordered': [rows[1],rows[0]]+rows[2:], 'deleted':rows[:-1], 'appended':rows+[rows[0]]}
        for name, variant in variants.items():
            (d/f'{name}.jsonl').write_bytes(b'\n'.join(variant)+b'\n')
            call(f'Reject {name} dataset','verify',path(f'{name}.jsonl'),*auth,fail=True)
        p=json.loads((d/'proof.json').read_text()); p['siblings'][0]='00'*32
        (d/'bad-proof.json').write_text(json.dumps(p))
        call('Reject altered proof','verify-proof',path('bad-proof.json'),*auth,'--index','12',fail=True)
        call('Reject wrong requested index','verify-proof',path('proof.json'),*auth,'--index','13',fail=True)
        m=json.loads((d/'manifest.json').read_text()); m['count']+=1
        (d/'manifest.json').write_text(json.dumps(m))
        call('Reject changed signed manifest','verify',path('original.jsonl'),*auth,fail=True)
        print(f'{checks}/{checks} demo checks passed')

if __name__ == '__main__': main()
