"""Fixed read-only firewall commands, isolated from the HTTP service."""
import json
import shutil
import subprocess
import time
from backend.config import settings
from backend.models.store import Store


def inspect():
    observed = []
    errors = []
    if shutil.which('nft'):
        result = subprocess.run(['nft', '-j', 'list', 'ruleset'], capture_output=True, text=True, timeout=8)
        if result.returncode == 0:
            entries = json.loads(result.stdout).get('nftables', [])
            chains = [x['chain'] for x in entries if 'chain' in x and x['chain'].get('hook') == 'input']
            rules = [x['rule'] for x in entries if 'rule' in x]
            # Any configured input rules or non-accept policy means configured,
            # not proof that every service or IP family is protected.
            configured = any(c.get('policy') == 'drop' or any(r.get('chain') == c['name'] and r.get('table') == c['table'] and r.get('family') == c.get('family') for r in rules) for c in chains)
            observed.append(configured)
        else:
            errors.append('nftables inspection failed')
    for command in ('iptables-save', 'ip6tables-save'):
        if shutil.which(command):
            result = subprocess.run([command], capture_output=True, text=True, timeout=8)
            if result.returncode == 0:
                observed.append(any(line.startswith('-A INPUT ') or line.startswith(':INPUT DROP ') for line in result.stdout.splitlines()))
            else:
                errors.append(command + ' inspection failed')
    if any(observed):
        return {'state': 'active', 'message': 'Input firewall configuration detected; effectiveness is not assessed'}
    if observed and not errors:
        return {'state': 'inactive', 'message': 'No input firewall rules or drop policy detected'}
    return {'state': 'unknown', 'message': '; '.join(errors) or 'No supported firewall inspection tools available'}


def main():
    store = Store(settings.data_dir)
    try:
        status = inspect()
    except Exception as exc:
        status = {'state': 'unknown', 'message': str(exc)[:180]}
    store.set('firewall_status', {**status, 'updated': time.time()})

if __name__ == '__main__':
    main()
