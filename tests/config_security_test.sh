#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
INST_DIR="$WORK/inst"
ALL_TYPES="gre icmp udp hysteria tcp fou"
functions="$(python3 - "$ROOT/omnitunnel.sh" <<'PY'
import pathlib,re,sys
s=pathlib.Path(sys.argv[1]).read_text()
for name in ('create_inst','load_inst','require_supported_transport','validate_inst_name','inst_path','inst_conf','inst_pf','inst_exists','list_instances'):
    m=re.search(r'^'+name+r'\(\)\s*\{[^\n]*\}',s,re.M) or re.search(r'^'+name+r'\(\)\s*\{.*?^}',s,re.M|re.S)
    if not m: raise SystemExit('missing function '+name)
    print(m.group())
PY
)"
eval "$functions"
die() { echo "$*" >&2; exit 1; }
key="$(printf 'a%.0s' {1..64})"
create_inst safe tcp client 192.0.2.1 192.0.2.2 443 "$key" 10.0.0.1 10.0.0.2
[[ "$(stat -c %a "$INST_DIR/safe")" == 700 ]]
[[ "$(stat -c %a "$INST_DIR/safe/instance.conf")" == 600 ]]
load_inst safe
[[ "$TYPE" == tcp && "$KEY" == "$key" ]]
if (create_inst bad tcp client '192.0.2.1;id' 192.0.2.2 443 "$key" 10.0.0.1 10.0.0.2); then
    die 'shell injection accepted during creation'
fi
[[ ! -d "$INST_DIR/bad" ]]
printf 'KEY=$(touch %s)\n' "$WORK/executed" >> "$INST_DIR/safe/instance.conf"
if (load_inst safe); then die 'shell-bearing config accepted'; fi
[[ ! -e "$WORK/executed" ]]
echo 'PASS: private config permissions and config/creation shell injection rejection'
