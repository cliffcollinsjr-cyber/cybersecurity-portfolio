# GitHub Actions OIDC → Cloud IAM ([DEMO])

**Classification:** `[DEMO]` / `[TEMPLATE]`

Replace every `EXAMPLE-*` value. Do **not** paste real account, tenant, or subscription IDs into a public fork.

Goal: deploy or plan Terraform **without** long-lived cloud access keys stored as GitHub secrets.

```
GitHub Actions job
    │  (permissions: id-token: write)
    ▼
token.actions.githubusercontent.com  (OIDC)
    │  aud + sub conditions
    ▼
AWS IAM role  /  Azure federated credential  /  GCP WIF
    │  least-privilege IAM
    ▼
terraform plan | apply  (environment: production → required reviewers)
```

## AWS — IAM role trust (OIDC)

1. Create the GitHub OIDC provider once per account (`token.actions.githubusercontent.com`).
2. Trust a **role** (not a user access key) with a `sub` condition scoped to repo + environment.
3. Attach a **least-privilege** deploy policy (state bucket + target resources only).

See [`examples/github-oidc-aws-trust-policy.json`](./examples/github-oidc-aws-trust-policy.json).

### Example job (YAML, not wired in this repo)

```yaml
# [DEMO] — do not copy account IDs. Production: pin actions to commit SHAs.
jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # OIDC only; no AWS_ACCESS_KEY_ID
    environment: lab    # required reviewers in production
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/example-gha-terraform-lab
          aws-region: us-east-1
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
      - run: terraform plan -input=false
```

### Example HCL (role + OIDC provider sketch)

```hcl
# [DEMO] placeholders only
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # thumbprint rotates — fetch current from GitHub / AWS docs in a real account
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]
}

resource "aws_iam_role" "gha_terraform_lab" {
  name               = "example-gha-terraform-lab"
  assume_role_policy = file("${path.module}/github-oidc-aws-trust-policy.json")
}
```

`sub` must be **narrow**: `repo:EXAMPLE-ORG/EXAMPLE-REPO:environment:lab` (or `:ref:refs/heads/main`). Avoid `repo:ORG/*` and avoid `:*` unless you have a documented exception.

## Azure — federated credential (no client secret)

1. App registration (or user-assigned managed identity) in the lab tenant.
2. Federated credential: issuer `https://token.actions.githubusercontent.com`, subject `repo:EXAMPLE-ORG/EXAMPLE-REPO:environment:lab`.
3. Grant the identity **RBAC on the target subscription / resource group only**.

See [`examples/azure-federated-identity-notes.md`](./examples/azure-federated-identity-notes.md).

```yaml
# [DEMO]
jobs:
  plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    environment: lab
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2
        with:
          client-id: 00000000-0000-0000-0000-000000000000
          tenant-id: 11111111-1111-1111-1111-111111111111
          subscription-id: 22222222-2222-2222-2222-222222222222
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init && terraform plan -input=false
```

## What this repo does *not* do

- The live [`../.github/workflows/security-gates.yml`](../.github/workflows/security-gates.yml) **does not** assume a cloud role and **does not** set `id-token: write`.
- `terraform init` in CI uses `-backend=false` so fmt/validate/scan need **no secrets**.
