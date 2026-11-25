# Deploy the Prometheus Forge

Run one dedicated amd64 Linux VM. Allocate at least 8 GiB RAM, four virtual CPUs and 40 GiB of disk for a small lab. Add storage for retained evidence. Keep case archives and certificates in private operator storage.

## Initialize the VM

For Proxmox, use a verified Ubuntu 24.04 amd64 cloud image and cloud-init with a per-VM SSH public key. Set the hostname to `prometheus`. Choose the VLAN and storage appropriate for the analysis lab. Run the following on the guest after installing Docker Engine with Buildx and Python 3.10 or newer. Install NGINX, `apache2-utils` and your VPN client when deploying the web interface.

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
2. Copy `deploy/forge.env.example` to `/etc/prometheus-forge/forge.env`, set the public HTTPS origin and choose a path prefix. Install `deploy/prometheus-forge.service` into `/etc/systemd/system/`. Use `systemctl daemon-reload` and `systemctl enable --now prometheus-forge`. The service listens on a group-restricted Unix socket. To limit browser access to specific cases, add `--case CASE_ID` to the service command once per allowed case.
3. Issue a backend TLS certificate for the guest's internal TLS name. Keep the key on the guest and install the issuing CA certificate on the VPS. Create the guest's operator file interactively with `sudo htpasswd -cB /etc/prometheus-forge/operators.htpasswd OPERATOR`. Set that file's group to `www-data` and permissions to `0640`. On subsequent changes use `htpasswd -B` to preserve other accounts.
4. Install `deploy/nginx-guest.conf.example` as a guest NGINX site. Replace both documentation IP addresses and the backend name. Adjust the base path to match the service. Verify `nginx -t` and reload. Start NGINX after the VPN interface is ready because the guest listener binds the VPN address explicitly.
5. Install `deploy/nginx-vps-http.conf.example` at VPS HTTP scope and `deploy/nginx-vps-https-location.conf.example` inside the existing public HTTPS server. Replace the example addresses and TLS name. Set the CA path, use the same base path and leave existing site locations in place. Test `nginx -t` before reload.

The guest requires both the VPS VPN source and valid operator credentials. NGINX sets the identity presented to the Forge, and the Forge rejects requests missing that identity. The browser lists cases and opens a page per case with its scope, evidence ledger, active excerpt grants and the newest audit decisions. It can request an artifact summary through the existing broker and pause a case. Pausing is one-way in the browser. Resume, intake, grants, exports and advanced analysis stay with the CLI and MCP. [NGINX authentication](https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html) · [NGINX proxy TLS verification](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify).

## Verify the route before use

- From the VPS, connect over the tunnel and validate the guest's TLS name using the pinned CA. Expect HTTP 401 without operator credentials.
- From an independent client, expect the same authentication challenge through the public HTTPS URL and a successful page load after signing in. Verify that a caller-supplied `X-Forge-Operator` header does not bypass the challenge.
- Run `python3 -m tests.smoke` with the same state directory and service user. Verify the sample-free Forge landing page, a browser inspection against a benign case, a browser pause recorded in the case audit with the operator name, and rejection of inspection after the pause. Check that the public ingress exposes the expected Forge path.
