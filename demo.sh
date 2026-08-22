#!/usr/bin/env bash
# agent-guard 60-second demo: quarantine -> inspect -> restore.
# Zero dependencies beyond python3 and git. Leaves nothing behind.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
S="$HERE/skills/delete-guard/scripts"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT   # demo scratch discards itself; the guard never runs here

export AGENT_GUARD_WORKSPACE="$WORK"
cd "$WORK"

echo "== 1/5 create a scratch project =="
git init -q && git config user.email demo@local && git config user.name demo
printf 'quarterly numbers\n' > report.txt && git add -A && git commit -qm init

echo "== 2/5 delete it through the guard (safe_delete) =="
python3 "$S/safe_delete.py" --json --reason demo report.txt | python3 -c \
  "import json,sys;d=json.load(sys.stdin);print('  verdict:',d['verdict']['decision'],'|',d['outcome']);open('.txid','w').write(d['txid'])"

echo "== 3/5 gone from the workspace... =="
[ ! -e report.txt ] && echo "  report.txt: absent ✓"

echo "== 4/5 ...alive in quarantine =="
TXID="$(cat .txid)"
python3 "$S/restore.py" list | sed 's/^/  /'

echo "== 5/5 restore =="
python3 "$S/restore.py" "$TXID" | sed 's/^/  /'
echo "  content recovered: $(cat report.txt)"
echo
echo "Demo complete. The deletion never happened."
