# Azure federated identity for GitHub Actions ([DEMO])

**Do not use these UUIDs.** They are nil / sequential placeholders.

## Federated credential (portal / Graph mental model)

| Field | DEMO value |
|-------|------------|
| Issuer | `https://token.actions.githubusercontent.com` |
| Subject | `repo:EXAMPLE-ORG/EXAMPLE-REPO:environment:lab` |
| Audience | `api://AzureADTokenExchange` |
| Application (client) ID | `00000000-0000-0000-0000-000000000000` |
| Tenant ID | `11111111-1111-1111-1111-111111111111` |
| Subscription ID | `22222222-2222-2222-2222-222222222222` |

Prefer `environment:<name>` or `ref:refs/heads/main` over `repo:EXAMPLE-ORG/EXAMPLE-REPO:*`.

## Example HCL (azurerm / azuread sketch)

```hcl
# [DEMO] — not applied in this repository
resource "azuread_application_federated_identity_credential" "gha_lab" {
  application_id = "/applications/00000000-0000-0000-0000-000000000000"
  display_name   = "github-EXAMPLE-REPO-lab"
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = "repo:EXAMPLE-ORG/EXAMPLE-REPO:environment:lab"
}
```

## Example login step

```yaml
# [DEMO]
- uses: azure/login@v2 # production: pin to commit SHA
  with:
    client-id: 00000000-0000-0000-0000-000000000000
    tenant-id: 11111111-1111-1111-1111-111111111111
    subscription-id: 22222222-2222-2222-2222-222222222222
```

RBAC: grant the app **Reader** (plan) or a custom deploy role (apply) on one resource group — not Owner on the tenant.
