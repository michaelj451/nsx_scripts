# NSX Scripts – Export, Audit, and Import Guide

This repository provides CLI tooling to **export**, **audit**, and **import (push)** NSX Policy objects and inventory across:

- **Local Managers (LM)**
- **Global Manager (GM / Federation)**

The tooling is designed for **safe, auditable migrations**, with a strong emphasis on:
- readable exports
  - exports json & yaml
- deterministic imports
- dry-run first workflows

---

## 1) Clone the repository

```bash
git clone <YOUR_REPO_URL> nsx_scripts
cd nsx_scripts
```

---

## 2) Create and activate a virtual environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

---

## 3) Upgrade pip tooling

```bash
pip install --upgrade pip setuptools wheel
```

---

## 4) Install Python dependencies

```bash
pip install -r docker/requirements-pip.txt
```

---

## 5) Create the `.env` file

```bash
cp .env.example .env
```

### Example `.env`

```bash
# Local Managers
NSX_LM1=https://nsx-lm1.lab.local
NSX_LM2=https://nsx-lm2.lab.local
NSX_LM3=https://nsx-lm3.lab.local
NSX_LM4=https://nsx-lm4.lab.local

# Global Manager
NSX_GM1=https://nsx-gm1.lab.local
```

---

## 6) Ensure required directories exist

```bash
mkdir -p app/frontendFastapi/static
```

---

## CLI Execution Requirements

All CLI scripts **must be run from the repo root** with:

```bash
PYTHONPATH=app
```

You may export this once per shell session:

```bash
export PYTHONPATH="$PWD/app"
```

---

# Federation vs Local Policy (CRITICAL)

Understanding **which policy API you are targeting** is essential.

---

## Local Manager (LM) Policy

- **API Root**
  ```
  /policy/api/v1/infra
  ```
- Objects are local to a single NSX Manager

---

## Global Manager / Federation Policy

- **API Root**
  ```
  /policy/api/v1/global-infra
  ```

---

## The `--federation-global` Flag

Use this flag when interacting with **Global Manager** policy.

```bash
--federation-global
```

---

# Export Commands

## Local Manager export

```bash
PYTHONPATH=app python tools/nsx/export_nsx1_objects.py --manager nsx-lm1
```

---

## Global Manager export (all domains)

```bash
PYTHONPATH=app python tools/nsx/export_nsx1_objects.py   --manager nsx-gm1   --all-domains   --federation-global
```

---

# Import / Push Commands

## DRY-RUN (default)

```bash
PYTHONPATH=app python tools/nsx/push_nsx_objects.py
```

## APPLY (explicit)

```bash
PYTHONPATH=app python tools/nsx/push_nsx_objects.py --apply
```

---

## Reference: Federation domains

```bash
curl -k -u 'admin:*'   "https://nsx-gm1.lab.local/policy/api/v1/global-infra/domains"
```

export PYTHONPATH="$PWD/app"
python tools/nsx/export_nsx_objects.py --federation-global --output-format both --all-domains --manager nsx-gm1
python tools/nsx/create_new_groups.py --csv data/subnet_map.csv
python tools/nsx/create_new_groups.py --csv data/subnet_map.csv --new-domain-path nsx-lm4.lab.local