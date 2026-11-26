#!/bin/sh
# Root-owned redeploy for the Forge guest. Install as /usr/local/sbin/prometheus-redeploy (0755 root:root).
# Fast-forwards the checkout to origin/main, refreshes the Forge venv, rebuilds the Apprentice baseline,
# restarts the service and runs the smoke test against a disposable copy of the state.
set -eu
STATE=/var/lib/prometheus-forge
REPO=/opt/prometheus
VENV=/opt/prometheus-forge-venv
git -C "$REPO" fetch origin main
git -C "$REPO" merge-base --is-ancestor HEAD origin/main
git -C "$REPO" checkout --detach origin/main
cd "$REPO"
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --quiet --require-hashes --no-deps --only-binary=:all: -r deploy/forge-requirements.txt
install -m 0644 deploy/prometheus-forge.service /etc/systemd/system/prometheus-forge.service
systemctl daemon-reload
sudo -u prometheus -g www-data env STATIC_RE_STATE_DIR="$STATE" python3 -m re_harness.cli provision --engine linux
systemctl restart prometheus-forge
sleep 2
systemctl is-active prometheus-forge
TMP=$(sudo -u prometheus mktemp -d)
sudo -u prometheus cp "$STATE/baseline.json" "$TMP/"
sudo -u prometheus -g www-data env STATIC_RE_STATE_DIR="$TMP" PYTHONDONTWRITEBYTECODE=1 "$VENV/bin/python" -m tests.smoke
sudo -u prometheus rm -rf "$TMP"
git -C "$REPO" log --oneline -1
