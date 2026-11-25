# MEASUREMENT PROTOTYPE, NOT FOR MERGE (#86, #87).
# Summarizes one case: python3 summ.py CASE_DIR
# CASE_DIR holds srv.log (blocksrv), zz.jsonl (proxy), report/report.json,
# scan.log, meta (KEY=VALUE lines: after, until, secs, exit).
import json, os, re, sys, collections

d = sys.argv[1]
case = os.path.basename(d.rstrip('/'))
mp = os.path.join(d, 'meta')
meta = dict(l.strip().split('=', 1) for l in open(mp) if '=' in l) if os.path.exists(mp) else {'exit': 'NO META'}
after, until = int(meta.get('after', -1)), int(meta.get('until', -1))

def hms(s):
    h, m, x = s.split(':')
    return int(h) * 3600 + int(m) * 60 + float(x)

srv = []
p = os.path.join(d, 'srv.log')
if os.path.exists(p):
    for l in open(p):
        m = re.match(r'(\S+) (\d+) (\S+) (\S+) (-?\d+) hdr=(\S+) ua="([^"]*)', l)
        if m:
            srv.append(dict(t=hms(m.group(1)), i=int(m.group(2)), path=m.group(4), code=int(m.group(5)), hdr=m.group(6), ua=m.group(7)))
onset = next((r for r in srv if after > 0 and r['i'] >= after), None)
end = next((r for r in srv if until > 0 and r['i'] >= until), None)

zz = [json.loads(l) for l in open(os.path.join(d, 'zz.jsonl'))] if os.path.exists(os.path.join(d, 'zz.jsonl')) else []
stops = collections.defaultdict(list)
for e in zz:
    if e.get('ev') == 'would-stop':
        stops[e['detector']].append(e)
canaries = collections.Counter()
for e in zz:
    if e.get('ev') == 'final':
        canaries.update(e.get('canaries', {}))

out = {'case': case, 'exit': meta.get('exit'), 'secs': meta.get('secs'), 'enforce': meta.get('enforce', ''), 'f': meta.get('f', ''),
       'refused_header_reached_app': sum(1 for l in open(p) if l.rstrip().endswith('rh=yes')) if os.path.exists(p) else None,
       'requests_at_server': len(srv), 'onset_index': onset and onset['i'], 'block_end_index': end and end['i']}
det = {}
for dname in ['d1', 'd2', 'd3', 'd4']:
    ev = stops.get(dname, [])
    if not ev:
        det[dname] = 'never fired' if onset else 'no false stop'
        continue
    first = ev[0]
    t = hms(first['t'][11:26])
    if not onset:
        det[dname] = f"FALSE STOP x{len(ev)} (first at forwarded {first['forwarded']}: {first['why'][:120]})"
        continue
    after_onset = sum(1 for r in srv if r['i'] >= onset['i'] and r['t'] <= t and 'canary' not in r['ua'])
    det[dname] = f"fired x{len(ev)}; tool requests answered after the block began and before the stop: {after_onset}"
    if t < onset['t']:
        det[dname] += ' (FIRED BEFORE ONSET)'
out['detectors'] = det
out['canary_requests'] = dict(canaries)

rp = os.path.join(d, 'report', 'report.json')
if os.path.exists(rp):
    r = json.load(open(rp))
    out['plugins'] = {p['id']: {k: p.get(k) for k in ('status', 'findings', 'requests', 'stop', 'reason') if p.get(k) not in (None, '')} for p in r.get('plugins', [])}
    for p in out['plugins'].values():
        if 'reason' in p:
            p['reason'] = p['reason'][:500]
    byplug = collections.defaultdict(collections.Counter)
    for f in r.get('findings', []):
        src = (f.get('sources') or [{}])[0].get('plugin', '?')
        byplug[src][f.get('ruleId', '?')] += 1
    out['findings_by_rule'] = {k: dict(v.most_common(15)) for k, v in byplug.items()}
    out['ffuf_block_page_findings'] = sum(1 for f in r.get('findings', []) if '(24670 bytes' in f.get('message', ''))

# Header cases: requests with and without the header, by user agent.
hdr = collections.Counter()
for r in srv:
    if r['hdr'] != '-':
        hdr[(r['ua'].split(' ')[0][:20], r['hdr'], r['code'])] += 1
if hdr:
    out['header_by_tool'] = {f'{a} hdr={b} code={c}': n for (a, b, c), n in sorted(hdr.items())}
print(json.dumps(out, indent=1))
