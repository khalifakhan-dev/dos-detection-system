#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y python3-venv python3-pip libpcap-dev apache2 git sqlite3
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
printf '\nInstallation complete. Edit configuration/settings.yaml before starting the detector.\n'
