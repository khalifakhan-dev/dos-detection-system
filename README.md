# Real-Time Threshold-Based DoS Detection and Mitigation System

This is a defensive final-year project for an isolated VMware laboratory. It detects TCP SYN, UDP, ICMP, and HTTP Slowloris indicators in one-second traffic windows and applies configurable source-IP mitigation through Linux nftables.

## Architecture

- **Ubuntu Server:** Apache2/DVWA, Scapy detector, SQLite database, FastAPI API, and nftables mitigation.
- **Kali Linux:** controlled testing VM only.
- **Windows 11:** VS Code development environment and CustomTkinter dashboard.
- **VMware Host-only network:** isolated test path between Kali and Ubuntu.

The dashboard does not execute Linux commands. It communicates with the authenticated FastAPI service on Ubuntu.

## Safety

Use this software only against virtual machines and networks you own or are explicitly authorised to test. Keep testing on the VMware host-only network. The default configuration uses `dry_run: true`, so nftables is not modified until you deliberately change that setting on the Ubuntu lab VM.

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
- `POST /api/blocks/{ip}/unblock`
- `POST /api/blocks/{ip}/permanent`
- `POST /api/blocks/unblock-all`

Send `Authorization: Bearer change-this-lab-token` for API requests.

## Testing

The unit tests use synthetic packet objects and dry-run mitigation. First validate the code with `pytest`; only then perform authorised traffic tests on the VMware host-only network. Establish a normal-traffic baseline before changing thresholds.

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
