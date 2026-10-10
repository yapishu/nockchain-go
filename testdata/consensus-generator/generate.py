#!/usr/bin/env python3
"""Run the canonical Nockchain Hoon engine against the public transaction corpus."""
import json
import pathlib
import subprocess
import sys
import tempfile

if len(sys.argv) != 2:
    raise SystemExit('usage: generate.py NOCKCHAIN_ROOT')
source = pathlib.Path(sys.argv[1]).expanduser().resolve()
root = pathlib.Path(__file__).resolve().parents[2]
commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
corpus = json.loads((root / 'testdata/reference.json').read_text())


def decimal(n):
    return format(n, ',').replace(',', '.')


def jam_atom(encoded):
    raw = format(int.from_bytes(bytes.fromhex(encoded), 'little'), 'x')
    return '0x' + '.'.join([raw[max(0, i - 4):i] for i in range(len(raw), 0, -4)][::-1])


def digest(values):
    return '[' + ' '.join(map(decimal, values)) + ']'


lines = [
    '/=  v  /common/tx-engine-1',
    '/=  tx  /common/tx-engine',
    '/=  zo  /common/zoon',
    '=/  t  ~(. tx *blockchain-constants:tx)',
    ':~',
]
for fixture in corpus['transactions'] + corpus['multisig']:
    lines += [
        '  =/  raw=raw-tx:v',
        '    ;;(raw-tx:v (cue ' + jam_atom(fixture['jam']) + '))',
        '  :*  (compute-id:raw-tx:v raw)',
        '      (calculate-min-fee:spends:t [spends.raw 100.000])',
        '      (validate:raw-tx:v raw)',
        '      :~',
    ]
    plans = fixture.get('plans', [{'note': fixture.get('note')}])
    for plan in plans:
        note = plan['note']
        name = '[' + digest(note['name']['first']) + ' ' + digest(note['name']['last']) + ' ~]'
        note_literal = '[%1 ' + decimal(note['originPage']) + ' ' + name + ' ~ ' + decimal(note['nicks']) + ']'
        lines += [
            '        =/  note=nnote-1:v  ;;(nnote-1:v ' + note_literal + ')',
            '        =/  sp=spend:v  (~(got z-by:zo spends.raw) name.note)',
            '        ?>  ?=(%1 -.sp)',
            '        :*  (hash:nnote-1:v note)',
            '            (verify:spend-1:v +.sp note)',
            '            (check-gifts-and-fee:spend:v sp note)',
            # Synthetic fixture heights with current full-proof rules active.
            '            (check:check-context:v [105 origin-page.note (sig-hash:spend-1:v +.sp) witness.+.sp 0] -.name.note)',
            '        ==',
        ]
    lines += ['      ==', '  ==']
lines += ['==']

with tempfile.TemporaryDirectory(prefix='nockchain-go-consensus-') as tmp:
    folder = pathlib.Path(tmp)
    script = folder / 'verify.hoon'
    script.write_text('\n'.join(lines) + '\n')
    subprocess.run(['hoon', str(script), str(source / 'hoon'), '--out-dir', tmp], cwd=tmp, check=True)
    output = subprocess.check_output([
        'go', 'run', str(pathlib.Path(__file__).with_name('decode.go')),
        str(folder / 'verify.jam'), commit,
    ], cwd=root)
    decoded = json.loads(output)
    expected = [v['id'] for v in corpus['transactions'] + corpus['multisig']]
    assert [v['id'] for v in decoded['transactions']] == expected, 'Hoon IDs differ from the signed corpus'
    (root / 'testdata/consensus.json').write_bytes(output)
