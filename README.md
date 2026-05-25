# IAM Access Review Automation Tool

> **Automated access review for Microsoft Azure Entra ID** — surfaces overprivileged accounts, orphaned users, stale permissions, and excessive service principal permissions via Microsoft Graph API. Outputs a professional HTML or Markdown audit report suitable for client delivery.

[![CI](https://github.com/andres-banuelos/iam-access-review-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/andres-banuelos/iam-access-review-tool/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What It Does

| Check | Risk | Description |
|---|---|---|
| Overprivileged inactive accounts | 🔴 High | Users with Global Admin / Owner roles not signed in within 90 days |
| Elevated guest accounts | 🔴 High | External (B2B Guest) users holding any directory role |
| Excessive service principal permissions | 🔴 High | App registrations / managed identities with privileged directory roles |
| Orphaned accounts | 🟡 Medium | Enabled users with no sign-in within 90 days or who have never signed in |
| Stale role assignments | 🟢 Low | Non-privileged role holders who are inactive, suggesting unused permissions |

---

## Project Structure

```
iam-access-review-tool/
├── main.py                        # Entry point
├── requirements.txt
├── .env.example                   # Copy to .env and fill in credentials
├── src/
│   ├── config.py
│   ├── collectors/
│   │   ├── graph_client.py        # Azure auth + Graph SDK factory
│   │   ├── users.py               # Pull users + sign-in activity
│   │   └── roles.py               # Directory roles + service principals
│   ├── analyzers/
│   │   ├── findings.py            # Finding dataclass + RiskLevel enum
│   │   └── access_analyzer.py     # All 5 risk checks
│   └── reporters/
│       ├── html_reporter.py       # Jinja2 HTML report renderer
│       └── markdown_reporter.py   # Markdown report renderer
├── templates/
│   └── report.html.j2             # Professional HTML audit template
├── tests/
│   └── test_analyzers.py          # Unit tests (no Graph API calls needed)
└── .github/workflows/ci.yml       # GitHub Actions CI
```

---

## Prerequisites

- Python 3.10+
- An Azure account with permissions to create App Registrations
- Entra ID P1 or P2 licence (required for sign-in activity via `AuditLog.Read.All`)

---

## Step 1 — Azure App Registration (Read-Only, CLI)

```bash
# 1. Log in
az login

# 2. Create the app registration
az ad app create \
  --display-name "IAM-Access-Review-Automation" \
  --sign-in-audience AzureADMyOrg

# 3. Capture the Client ID
APP_ID=$(az ad app list \
  --display-name "IAM-Access-Review-Automation" \
  --query "[0].appId" -o tsv)
echo "Client ID: $APP_ID"

# 4. Create service principal
az ad sp create --id $APP_ID

# 5. Generate client secret (copy 'value' — shown ONCE)
az ad app credential reset --id $APP_ID --years 1

# 6. Get Tenant ID
az account show --query tenantId -o tsv

# 7. Add read-only Graph permissions
# User.Read.All
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions df021288-bdef-4463-88db-98f22de89214=Role

# AuditLog.Read.All
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions b0afded3-3588-46d8-8b3d-9842eff778da=Role

# Directory.Read.All
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

# 8. Grant admin consent (requires Global Admin or Privileged Role Admin)
az ad app permission admin-consent --id $APP_ID
```

> **Work tenant note:** Step 8 requires a Global Administrator. Ask your Identity/IT team to grant consent for `IAM-Access-Review-Automation` (`$APP_ID`) for `User.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`.

---

## Step 2 — Local Setup

```bash
git clone https://github.com/andres-banuelos/iam-access-review-tool.git
cd iam-access-review-tool

python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env: set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
```

---

## Step 3 — Run

```bash
python main.py --tenant-name "Contoso Ltd"

# HTML only
python main.py --tenant-name "Contoso Ltd" --format html

# Custom output dir
python main.py --tenant-name "Contoso Ltd" --output-dir ./reports/Q1-2025
```

Reports are written to `./output/iam_review_YYYYMMDD_HHMMSS.html` and `.md`.

---

## Step 4 — Unit Tests

```bash
python -m pytest tests/ -v
```

Tests run without any Azure credentials — the analyzer logic is fully decoupled from the Graph API.

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `AZURE_TENANT_ID` | ✅ | — | Azure Directory (Tenant) ID |
| `AZURE_CLIENT_ID` | ✅ | — | App Registration Client ID |
| `AZURE_CLIENT_SECRET` | ✅ | — | Client secret value |
| `INACTIVE_USER_DAYS` | No | `90` | Days of inactivity before flagging |
| `STALE_ROLE_DAYS` | No | `90` | Days before flagging a role as stale |
| `OUTPUT_DIR` | No | `./output` | Directory for generated reports |

---

## Security Notes

- **Credentials are never committed** — `.env` and `output/` are in `.gitignore`
- The service principal uses **application-only, read-only permissions** — cannot modify any resources
- Rotate the client secret every 12 months
- In production, replace the client secret with a **Managed Identity** or **Azure Key Vault** reference

---

## License

MIT
