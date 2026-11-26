# Deploy the Prometheus Forge

Run one dedicated amd64 Linux VM. Allocate at least 8 GiB RAM, four virtual CPUs and 40 GiB of disk for a small lab. Add storage for retained evidence. Keep case archives and certificates in private operator storage.

## Initialize the VM

For Proxmox, use a verified Ubuntu 24.04 amd64 cloud image and cloud-init with a per-VM SSH public key. Set the hostname to `prometheus`. Choose the VLAN and storage appropriate for the analysis lab. Run the following on the guest after installing Docker Engine with Buildx and Python 3.10 or newer. Install NGINX, `python3-venv` and your VPN client when deploying the web interface.

```bash
sudo git clone https://github.com/nullvaluefound/prometheus.git /opt/prometheus
sudo useradd --system --home-dir /var/lib/prometheus-forge --shell /usr/sbin/nologin prometheus
sudo usermod -aG docker prometheus
sudo install -d -m 0700 -o prometheus -g www-data /var/lib/prometheus-forge
sudo install -d -m 0750 -o root -g www-data /etc/prometheus-forge
cd /opt/prometheus
sudo -u prometheus -g www-data env STATIC_RE_STATE_DIR=/var/lib/prometheus-forge \
  python3 -m re_harness.cli provision --engine linux
sudo -u prometheus -g www-data env STATIC_RE_STATE_DIR=/var/lib/prometheus-forge \
  python3 -m re_harness.cli blank
```

The `prometheus` service account has Docker-socket access inside the dedicated guest. Keep `/opt/prometheus` root-owned. Run case lifecycle commands as the same service user with the same state directory. Configure a fresh case ID to begin with empty evidence. Provisioning and the smoke test are usable without deploying the web frontend.

## Configure the Forge and its VPN ingress

1. Enroll Prometheus as a new VPN peer with its own credentials and stable tunnel address. Set the VPN and guest firewall to allow TCP 443 to the guest VPN address from the VPS's tunnel address. Keep guest administration on the existing trusted management route. Verify the guest route and confirm that the proxy backend cannot be reached from a different peer.
2. Create the Forge service environment with `sudo python3 -m venv /opt/prometheus-forge-venv` and `sudo /opt/prometheus-forge-venv/bin/python -m pip install --require-hashes --no-deps --only-binary=:all: -r deploy/forge-requirements.txt`. It adds only the official Anthropic SDK and its pinned dependencies. Copy `deploy/forge.env.example` to `/etc/prometheus-forge/forge.env`, set the public HTTPS origin and choose a path prefix. Install `deploy/prometheus-forge.service` into `/etc/systemd/system/`. Use `systemctl daemon-reload` and `systemctl enable --now prometheus-forge`. The service listens on a group-restricted Unix socket. To limit browser access to specific cases, add `--case CASE_ID` to the service command once per allowed case.
3. Issue a backend TLS certificate for the guest's internal TLS name. Keep the key on the guest and install the issuing CA certificate on the VPS. Create each operator's Forge account as the service user with `python3 -m re_harness.cli forge-user add NAME --code-file PATH`. The command stores no password. It writes a one-time setup code, valid for 24 hours, to a new mode-0600 file. Hand the code to the operator out of band. They open `<prefix>setup`, enter the username and code, and choose their own password of 12 to 72 bytes. Use `forge-user reset NAME` for a forgotten password, `forge-user signout NAME` to end every session and `forge-user remove NAME` to delete the account.
4. Install `deploy/nginx-guest.conf.example` as a guest NGINX site. Replace both documentation IP addresses and the backend name. Adjust the base path to match the service. Verify `nginx -t` and reload. Start NGINX after the VPN interface is ready because the guest listener binds the VPN address explicitly.
5. Install `deploy/nginx-vps-http.conf.example` at VPS HTTP scope and `deploy/nginx-vps-https-location.conf.example` inside the existing public HTTPS server. Replace the example addresses and TLS name. Set the CA path, use the same base path and leave existing site locations in place. Test `nginx -t` before reload.

The guest accepts only the VPS VPN source. The Forge authenticates operators itself. Passwords are stored as salted scrypt hashes in `forge/accounts.json` under the state directory, mode 0600. Sign-in issues an HMAC-signed session cookie, scoped to the base path and marked `Secure`, `HttpOnly` and `SameSite=Strict`. It lasts 12 hours. Every form, sign-in included, must carry the Forge's own `Origin`. Operators change their password from the Account page by re-entering the current one. That change, sign-out and an operator reset end every existing session. Failed sign-ins and setup attempts are capped at 30 per 10 minutes across all clients, on top of the VPS's per-address request limit. Both NGINX layers clear any `X-Forge-Operator` header, and the Forge ignores it. The signed-in app is described in [Forge app](#forge-app). [NGINX proxy TLS verification](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify).

## Forge app

The base path serves a React app (built into `re_harness/forge_web/` from `web/`) over the JSON API in [FORGE_API.md](FORGE_API.md). Operators can:

- **Cases:** create cases, upload samples (up to 128 MiB, streamed into the case's offline evidence volume and never served back), run any broker tool as an audited operator inspection, generate the report, pause and resume.
- **Grants:** issue and revoke excerpt grants.
- **Chat:** chat with a model about a case. The model runs through the same broker, with the case's role and tool allowlist, and every call is audited before dispatch.
- **Models:** register model endpoints: Ollama, any OpenAI-compatible server, or Anthropic. API keys are stored mode 0600 under the state directory and never returned to the browser. A case must opt in before a cloud model (Anthropic, a public endpoint, or an Ollama `:cloud` model) may see its projected evidence. Local models use the `local` grant audience; cloud models use `mcp`.
- **Tasks:** watch the queue. Docker work runs one task at a time in the order submitted.

The app polls while tasks run, so the VPS limit in `deploy/nginx-vps-http.conf.example` allows 240 requests a minute per client with a burst of 120. Upload routes allow 128 MiB bodies on both NGINX layers. Every other route stays at 64 KiB.

Redeploy with `deploy/prometheus-redeploy.sh`, installed root-owned as `/usr/local/sbin/prometheus-redeploy`. It fast-forwards `/opt/prometheus` to `origin/main`, refreshes the venv, provisions, restarts the service and runs the smoke test.

## Verify the route before use

- From the VPS, connect over the tunnel and validate the guest's TLS name using the pinned CA. Expect a 303 redirect to the sign-in page without a session.
- From an independent client, expect the same redirect through the public HTTPS URL and a successful page load after signing in. Verify that a caller-supplied `X-Forge-Operator` header does not bypass sign-in.
- Run `python3 -m tests.smoke` with the same state directory and service user. It serves the Forge on a private Unix socket against a disposable benign case and checks that the Forge redirects without a session, signs in a disposable account, then checks the sample-free landing page, a browser inspection, a browser pause recorded in the case audit with the operator name and `via=forge`, and rejection of inspection after the pause. It does not exercise NGINX, so confirm manually that the public ingress exposes the expected Forge path and does not cache or rewrite the session cookie.
