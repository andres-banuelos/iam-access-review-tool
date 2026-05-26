# IAM Access Review Automation Tool

> **Automated access review for Microsoft Azure Entra ID** — surfaces overprivileged accounts, orphaned users, stale permissions, and excessive service principal permissions via Microsoft Graph API. Outputs a professional HTML or Markdown audit report suitable for client delivery.

[![CI](https://github.com/andres-banuelos/iam-access-review-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/andres-banuelos/iam-access-review-tool/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What It Does

| Check | Risk | Description |
|---|---|---|
| Overprivileged inactive accounts | 🔴 High | Users with privileged directory roles who have not signed in within the configured inactivity threshold |
| Elevated guest accounts | 🔴 High | External guest users holding directory roles |
| Excessive service principal permissions | 🔴 High | Service principals or managed identities holding privileged directory roles |
| Orphaned accounts | 🟡 Medium | Enabled users with no recent sign-in or no sign-in history beyond a grace period |
| Stale role assignments | 🟢 Low | Non-privileged role holders whose sign-in activity suggests unused access |

---

## Why This Repo Looks Professional

This project is intentionally structured like a production-grade security engineering repo rather than a one-off demo script:

- Typed, modular Python with clear separation between collection, analysis, and reporting layers.
- Logging-based CLI execution instead of `print()`-driven flow.
- Centralized configuration and environment validation.
- Unit-tested analyzer logic decoupled from live Graph API calls.
- `pyproject.toml`-based tooling for Ruff, mypy, and pytest.
- GitHub Actions CI for linting, type checking, formatting, and tests.
- Pre-commit hooks to keep quality gates local before pushing.

That combination makes it much stronger as a cloud security portfolio project because it demonstrates both IAM knowledge and software engineering discipline.

---

## Project Structure

```text
iam-access-review-tool/
├── main.py
├── requirements.txt
├── pyproject.toml
├── .pre-commit-config.yaml
├── .env.example
├── src/
│   ├── config.py
│   ├── collectors/
│   │   ├── graph_client.py
│   │   ├── users.py
│   │   └── roles.py
│   ├── analyzers/
│   │   ├── findings.py
│   │   └── access_analyzer.py
│   └── reporters/
│       ├── html_reporter.py
│       └── markdown_reporter.py
├── templates/
│   └── report.html.j2
├── tests/
│   └── test_analyzers.py
└── .github/workflows/ci.yml
```

---

## Prerequisites

- Python 3.10+
- An Azure account with permissions to create App Registrations
- Entra ID P1 or P2 licensing if you want sign-in activity fields exposed through Microsoft Graph

---

## Step 1 — Azure App Registration (Read-Only, CLI)

```bash
az login

az ad app create \
  --display-name "IAM-Access-Review-Automation" \
  --sign-in-audience AzureADMyOrg

APP_ID=$(az ad app list \
  --display-name "IAM-Access-Review-Automation" \
  --query "[0].appId" -o tsv)
echo "Client ID: $APP_ID"

az ad sp create --id $APP_ID

az ad app credential reset --id $APP_ID --years 1

az account show --query tenantId -o tsv

az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions df021288-bdef-4463-88db-98f22de89214=Role

az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions b0afded3-3588-46d8-8b3d-9842eff778da=Role

az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

az ad app permission admin-consent --id $APP_ID
```

> **Work tenant note:** Admin consent typically requires a Global Administrator or Privileged Role Administrator. If you are using a corporate tenant, ask your identity team to approve the application permissions for `User.Read.All`, `AuditLog.Read.All`, and `Directory.Read.All`.

---

## Step 2 — Local Setup

```bash
git clone https://github.com/andres-banuelos/iam-access-review-tool.git
cd iam-access-review-tool

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

Populate `.env` with:

```env
AZURE_TENANT_ID=<your-tenant-id>
AZURE_CLIENT_ID=<your-client-id>
AZURE_CLIENT_SECRET=<your-client-secret>
INACTIVE_USER_DAYS=90
STALE_ROLE_DAYS=90
NEW_ACCOUNT_GRACE_DAYS=14
OUTPUT_DIR=./output
```

---

## Step 3 — Run the Tool

```bash
python main.py --tenant-name "Contoso Ltd"
python main.py --tenant-name "Contoso Ltd" --format html
python main.py --tenant-name "Contoso Ltd" --output-dir ./reports/q2-review
python main.py --tenant-name "Contoso Ltd" --verbose
```

Reports are written to timestamped files in the configured output directory.

---

## Step 4 — Run Quality Checks

```bash
pip install .[dev]
ruff check .
ruff format --check .
mypy main.py src tests
pytest -v
```

If you want the same checks to run before each commit:

```bash
pip install pre-commit
pre-commit install
```

---

## Security Notes

- The tool is designed for **read-only audit scope**.
- It uses **application permissions** for collection and does not modify tenant configuration.
- Do not commit `.env`, generated reports, or secrets.
- For production hardening, prefer **Managed Identity** or **Azure Key Vault** over long-lived client secrets.

---

## Roadmap

- Add AWS IAM collectors and reuse the same finding/reporting model.
- Support CSV or JSON evidence export for audit workpapers.
- Add configurable severity thresholds by environment.
- Add manager/department enrichment for tighter orphaned-account workflows.

---

## License

MIT
