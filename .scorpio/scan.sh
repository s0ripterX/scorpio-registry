#!/usr/bin/env bash
# Deep scan. Package files are DATA: unpacked in a locked-down container, scanned by tools, never executed.
set -uo pipefail
PENDING=$1; OUT=$2
echo '[]' > "$OUT"
n=$(jq length "$PENDING")
for i in $(seq 0 $((n - 1))); do
  name=$(jq -r ".[$i].name" "$PENDING"); ver=$(jq -r ".[$i].version" "$PENDING")
  file=$(jq -r ".[$i].file" "$PENDING"); src=$(jq -r ".[$i].path" "$PENDING")
  work=$(mktemp -d); mkdir -p "$work/x"; chmod 777 "$work/x"; F="$work/findings.jsonl"; : > "$F"
  add() { jq -nc --arg tool "$1" --arg sev "$2" --arg id "$3" --arg title "$4" '{tool:$tool,severity:$sev,id:$id,title:$title}' >> "$F"; }
  echo "::group::$name@$ver"

  # 1. isolated sandbox extraction: no network, read-only rootfs, unprivileged user, no caps, CPU/mem/pids limits, timeout
  if ! timeout 120 docker run --rm --network none --read-only --user 65534:65534 --cap-drop ALL \
      --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64 --tmpfs /tmp:rw,size=64m \
      -v "$PWD/$src:/in/pkg:ro" -v "$work/x:/out:rw" alpine:3.20 sh -c '
        cd /out || exit 1
        case "$1" in
          *.zip|*.whl) unzip -q /in/pkg ;;
          *.tar.gz|*.tgz) tar -xzof /in/pkg ;;
          *.tar) tar -xof /in/pkg ;;
          *) cp /in/pkg "./$1" ;;
        esac || exit 8
        [ -z "$(find . \( -type l -o -type b -o -type c -o -type p \) | head -1)" ] || exit 9
        [ "$(du -sm . | cut -f1)" -lt 300 ] || exit 10' _ "$file"; then
    add sandbox high sandbox-extract "Package failed isolated extraction (links, devices, bomb or corrupt archive)"
  fi

  # 2. malware
  clamscan -r --infected --no-summary "$work/x" > "$work/clam.txt" 2>/dev/null
  [ $? -eq 1 ] && add clamav high malware "ClamAV: $(head -1 "$work/clam.txt" | sed 's/.*: //')"
  yara -r -w .scorpio/rules.yar "$work/x" 2>/dev/null | cut -d' ' -f1 | sort -u | while read -r r; do [ -n "$r" ] && add yara high "yara-$r" "YARA rule matched: $r"; done

  # 3. secrets
  timeout 300 gitleaks detect --no-git --no-banner -s "$work/x" --exit-code 3 -r "$work/gl.json" >/dev/null 2>&1
  [ $? -eq 3 ] && add gitleaks high secret "Gitleaks: $(jq -r '.[0].Description // "secret found"' "$work/gl.json")"
  timeout 300 trivy fs -q --scanners secret --exit-code 5 "$work/x" >/dev/null 2>&1
  [ $? -eq 5 ] && add trivy high secret "Trivy found embedded secrets"

  # 4. dependencies
  timeout 300 trivy fs -q --scanners vuln --severity CRITICAL --exit-code 5 "$work/x" >/dev/null 2>&1
  [ $? -eq 5 ] && add trivy medium vuln "Dependencies with CRITICAL known vulnerabilities"
  req=$(find "$work/x" -maxdepth 3 -name requirements.txt | head -1)
  if [ -n "$req" ]; then timeout 300 pip-audit -r "$req" --no-deps --disable-pip --progress-spinner off >/dev/null 2>&1 || add pip-audit medium vuln "pip-audit reported vulnerable or unresolvable requirements"; fi
  lock=$(find "$work/x" -maxdepth 3 -name package-lock.json | head -1)
  if [ -n "$lock" ]; then (cd "$(dirname "$lock")" && timeout 300 npm audit --package-lock-only --audit-level=critical >/dev/null 2>&1) || add npm-audit medium vuln "npm audit reported critical vulnerabilities"; fi

  # 5. static analysis
  timeout 600 semgrep scan --config p/default --metrics off --severity ERROR --json -q "$work/x" > "$work/sg.json" 2>/dev/null
  c=$(jq '.results | length' "$work/sg.json" 2>/dev/null || echo 0)
  [ "${c:-0}" -gt 0 ] && add semgrep medium static "Semgrep: $c high-severity code findings"
  timeout 300 bandit -r -q -lll -iii -f json "$work/x" > "$work/bd.json" 2>/dev/null
  c=$(jq '.results | length' "$work/bd.json" 2>/dev/null || echo 0)
  [ "${c:-0}" -gt 0 ] && add bandit medium static "Bandit: $c high-severity Python issues"

  verdict=approved; grep -q '"severity":"high"' "$F" && verdict=quarantined
  jq --arg n "$name" --arg v "$ver" --arg verdict "$verdict" --slurpfile f "$F" \
    '. + [{name:$n, version:$v, verdict:$verdict, findings:$f}]' "$OUT" > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
  echo "$name@$ver -> $verdict"; cat "$F"
  rm -rf "$work"
  echo "::endgroup::"
done
cat "$OUT"
