# Network scanning providers

The **Network** module (`Network/network_scanner_api.py`) checks which ports
each vendor subdomain exposes, maps every open port to a severity and
produces the "Network" score shown in the dashboard. It does **not** contain
a scanner of its own: it delegates the "what is listening on this host?"
question to a *provider*, and you choose which provider to run.

```
subdomain ──resolve──▶ IP ──▶ NetworkScanProvider.scan_host(ip) ──▶ HostScanResult
                                                                        │
                                   PORT_SEVERITY_MAPPING + unified scoring ◀┘
```

## Choosing a provider

Set `NETWORK_SCAN_PROVIDER` in `.env` (or the container environment):

| Value | What it does | Needs |
|-------|--------------|-------|
| `socket` (default) | Built-in TCP connect scan with banner grabbing, 43 common ports | nothing |
| `nmap` | Runs the local `nmap -sV -Pn --open` and parses its XML | `nmap` on `PATH` |
| `module.path:ClassName` | Any class you write that implements the provider contract | your code |

### `socket` options

| Variable | Default | Meaning |
|----------|---------|---------|
| `NETWORK_SCAN_PORTS` | the list in `Network/providers/base.py` | Comma list, ranges allowed (`22,80,443,8000-8100`) |
| `NETWORK_SCAN_TIMEOUT` | `1.5` | Connect timeout per port, seconds |
| `NETWORK_SCAN_WORKERS` | `32` | Parallel connections per host |

The socket scanner is fast and dependency-free, but product/version data is
best-effort (parsed from the banner). Use `nmap` or a dedicated tool when
you need reliable version detection or CVE hints.

### `nmap` options

| Variable | Default | Meaning |
|----------|---------|---------|
| `NMAP_PATH` | `nmap` | Executable path |
| `NMAP_PORTS` | same as socket list | Port spec passed to `-p` |
| `NMAP_ARGS` | *(empty)* | Extra arguments, e.g. `-T4 --version-light` or `--script vulners` |
| `NMAP_TIMEOUT` | `300` | Seconds per host |

If you add `--script vulners` (needs the nmap vulners script installed) the
CVE identifiers it reports are attached to each service and picked up by
`Vulnerabilities/vulnerability.py`.

Install nmap with `apt-get install nmap`, `brew install nmap`, or add it to
`Dashboard/Dockerfile` next to the other apt packages.

## Writing your own provider

Create a module anywhere importable (for example
`Network/providers/my_scanner.py`) and subclass `NetworkScanProvider`:

```python
from providers.base import (
    HostScanResult, NetworkScanAuthError, NetworkScanError,
    NetworkScanNoDataError, NetworkScanProvider, ServiceInfo,
)

class MyScanner(NetworkScanProvider):
    name = "my-scanner"                 # shown in logs and alerts
    request_interval_seconds = 1.0      # pause between hosts (rate limits)

    def validate_config(self):
        # Raise NetworkScanError / NetworkScanAuthError if you cannot run.
        ...

    def scan_host(self, ip, hostname=None) -> HostScanResult:
        # Ask your tool about `ip` (or `hostname`) and translate the answer.
        return HostScanResult(
            ip=ip,
            ports=[22, 443],
            services=[
                ServiceInfo(port=22, product="OpenSSH", version="9.4",
                            banner="SSH-2.0-OpenSSH_9.4", vulns=["CVE-2024-6387"]),
                ServiceInfo(port=443, product="nginx", version="1.25"),
            ],
        )
```

Then point the scanner at it:

```bash
NETWORK_SCAN_PROVIDER=Network.providers.my_scanner:MyScanner
```

Both `Network.providers.x:Class` (repo root on `sys.path`) and
`providers.x:Class` (when `Network/` is on `sys.path`, as the dashboard
does) resolve.

### The contract

| Member | Required | Purpose |
|--------|----------|---------|
| `name` | yes | Label used in logs and Slack failure alerts |
| `request_interval_seconds` | no | Sleep after each host; `0` for local tools |
| `validate_config()` | no | Called once per scan; raise to abort with an alert |
| `scan_host(ip, hostname)` | yes | Return a `HostScanResult` |

`HostScanResult` fields:

- `ip` – the address scanned
- `ports` – list of open port numbers (this drives scoring)
- `services` – optional list of `ServiceInfo(port, transport, product, version, banner, vulns)`
- `raw` – optional provider payload, for debugging only

### Error semantics

Raise the right exception so the dashboard reacts correctly:

| Exception | Meaning | Effect |
|-----------|---------|--------|
| `NetworkScanNoDataError` | Tool knows nothing about this host | Host recorded with no ports, **no alert** |
| `NetworkScanAuthError` | Credentials missing/rejected | Host skipped, Slack alert tagged as auth failure |
| `NetworkScanError` | Anything else (timeout, bad response, tool crashed) | Host skipped, Slack alert |

Anything else that escapes is caught and logged, but you lose the
classification.

### Wrapping a hosted scanning API

`Network/providers/custom_provider_example.py` is a complete example that
calls a hypothetical `GET /host/<ip>` endpoint with a bearer token, maps
HTTP 401/404/429 to the exceptions above and honours a one-request-per-
second limit. Copy it, change the request and the field mapping, and you
have a drop-in for most commercial internet-scanning services.

## Running a scan by hand

```bash
# whole domain, subdomains taken from the arguments (or just the apex)
NETWORK_SCAN_PROVIDER=nmap python Network/network_scanner_api.py example.com www.example.com mail.example.com

# single-host CVE lookup
python Vulnerabilities/vulnerability.py mail.example.com
```

## Severity mapping

`PORT_SEVERITY_MAPPING` in `Network/network_scanner_api.py` decides how bad
an open port is (Telnet, SMB, RDP, MySQL are *Critical*; SSH, FTP, databases
are *High*; HTTPS is *Info*; unknown ports are *Info*). Edit that table to
match your own policy. Weights per severity come from
`Dashboard/unified_scoring_config.py`.
