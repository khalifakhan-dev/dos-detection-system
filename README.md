# Real-Time Threshold-Based DoS Detection and Mitigation System

This is a defensive final-year project for an isolated VMware laboratory. It detects TCP SYN, UDP, ICMP, and HTTP Slowloris indicators in one-second traffic windows and applies configurable source-IP mitigation through Linux nftables.

## Architecture

- **Ubuntu Server:** Apache2/DVWA, Scapy detector, SQLite database, FastAPI API, and nftables mitigation.
- **Kali Linux:** controlled testing VM only.
- **Windows 11:** VS Code development environment and CustomTkinter dashboard.
- **VMware Host-only network:** isolated test path between Kali and Ubuntu.

The dashboard does not execute Linux commands. It communicates with the authenticated FastAPI service on Ubuntu. Detection incidents are deduplicated by source IP and attack type only while an occurrence is active: repeated windows update `last_seen` and do not create another alert or repeat/escalate the firewall action. A failed mitigation may be retried after `mitigation_retry_cooldown_seconds`. A normal window resolves active incidents for sources present in that window; otherwise silent incidents resolve after `incident_inactivity_timeout_seconds`. Unrelated sources do not resolve one another, and a later recurrence creates a new incident and alert. `GET /api/incidents?active_only=true` is the dashboard's active view; without that parameter it includes resolved history, while `/api/alerts` remains historical alert records.

## Safety

Use this software only against virtual machines and networks you own or are explicitly authorised to test. Keep testing on the VMware host-only network. The default configuration uses `dry_run: true`, so nftables is not modified until you deliberately change that setting on the Ubuntu lab VM. Dry-run operations return `success: true` because the requested operation was accepted by the simulator, but also return `dry_run: true`, `simulated: true`, and `outcome: simulated`; storage and events preserve that distinction. Failed real nftables commands are recorded as `mitigation_failed` and are not stored as active blocks.

## Repository layout

```text
detector/       Packet capture, feature extraction, rules, service loop
mitigation/     nftables adapter, block policy, expiry scheduler
storage/        SQLite schema and repositories
api/            FastAPI service
 dashboard/     Windows CustomTkinter client
configuration/ YAML settings and thresholds
tests/          Unit tests
scripts/        Ubuntu helper scripts
```

## Development setup on Windows

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest
python -m dashboard.main --api-url http://UBUNTU_HOST_ONLY_IP:8000 --token change-this-lab-token
```

CustomTkinter requires a graphical Windows session. Do not install a desktop environment on Ubuntu just to run the dashboard.

## Ubuntu setup

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip libpcap-dev apache2 git sqlite3
# Clone this repository, then:
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp configuration/settings.yaml configuration/settings.local.yaml  # optional local override
```

Edit the YAML configuration. Set the host-only capture interface, protected IP, API token, and thresholds. Start the detector/API from the repository root:

```bash
sudo -E .venv/bin/python run_detector.py --config configuration/settings.yaml
```

The API is then available at `http://UBUNTU_HOST_ONLY_IP:8000`. The detector requires packet-capture privileges. In a production design, grant only the required capabilities to the Python interpreter or run a dedicated least-privilege service account; for the student lab, `sudo` is the simpler first test.

## Apache/DVWA

Install and configure Apache2 and DVWA separately according to the official DVWA documentation and your university laboratory policy. Verify that DVWA is reachable from Kali before running the detector. Do not expose DVWA or the API to the public Internet.

## API examples

- `GET /api/status`
- `GET /api/metrics`
- `GET /api/alerts?limit=50`
- `GET /api/blocks`
- `GET /api/events?limit=100`
- `GET /api/incidents?active_only=true` (current) or `/api/incidents` (historical/current)
- `POST /api/blocks/{ip}/unblock`
- `POST /api/blocks/{ip}/permanent`
- `POST /api/blocks/unblock-all`

Send `Authorization: Bearer change-this-lab-token` for API requests.

## Testing

The unit tests use synthetic packet objects and dry-run mitigation. First validate the code with `pytest` and `python -m compileall .`; only then perform authorised traffic tests on the VMware host-only network. Establish a normal-traffic baseline before changing thresholds.

## Behavior and limitations

Initial SYN counts exclude SYN-ACK packets. The SYN ACK/completion ratio is only a rough heuristic: it counts initial SYNs and observed ACK-bearing packets in a window and is not a TCP handshake verifier. Windows retain aggregate protocol metrics plus JSON-serializable per-source packet, byte, SYN, UDP, ICMP, and tracked HTTP counters. Protocol-specific rules run before generic per-source packet flood, and attribution uses the highest-rate source for the protocol that triggered the rule; aggregate-only callers remain compatible. HTTP Slowloris attribution uses the tracked source of incomplete/long-lived tuples when one source is clearly dominant; ties or missing per-source state intentionally produce `source_ip: null` rather than blaming the overall top source. HTTP detection is deliberately heuristic: it tracks TCP tuples involving ports 80/443, treats request-header terminators as a completion proxy, and estimates age from observed packets. It does not parse HTTP semantics, distinguish keep-alive/application behavior, validate response progress, or see connections hidden behind reverse proxies, NAT, TLS termination, load balancers, or encrypted payloads. Consequently it can produce false positives for legitimate slow clients and false negatives when the relevant state is not visible to the capture point; use it as an indicator rather than proof of an HTTP attack.

Automatic mitigation is temporary by default and idempotent within one active source/attack incident. Trusted and protected addresses are never automatically blocked. In real mode, startup checks every ruleset command; a failed check is exposed in `/api/status` as `mitigation_ready: false` and automatic real mitigation is not reported ready. Expiry changes a block to `expired` only after successful removal. The system is intentionally a threshold-based laboratory MVP, IPv4-only for nftables, and does not replace IDS/IPS validation or a production firewall change process.

## GitHub workflow

```bash
git init
git add .
git commit -m "Initial modular DoS detection system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

On Ubuntu:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Edit configuration/settings.yaml, then run the detector as documented above.
```

Never commit passwords, API tokens, private keys, packet captures containing sensitive data, or the runtime SQLite database.
