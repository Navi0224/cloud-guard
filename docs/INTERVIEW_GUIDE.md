# cloud-guard: Interview Guide

This guide is for you, the author. It explains every part of the project in plain English so you can talk about it confidently. Read it alongside the code, and if anything here doesn't match what you see in the code, trust the code and fix this guide.

---

## 1. The 30-second pitch

> "cloud-guard is a Python tool I built that finds security misconfigurations in AWS. It does two things. First, it scans a live AWS account with read-only API calls: IAM, S3, CloudTrail and security groups. Second, it scans Terraform code *before* deployment, which is the shift-left part. Findings from both are mapped to the CIS AWS Foundations Benchmark and output as a table, JSON, Markdown or HTML. The exit code can fail a CI pipeline. I tested everything against moto, a library that fakes AWS in memory, so there are 112 tests and a demo that run without an AWS account."

## 2. Key concepts you must be able to explain

### Shared responsibility model
AWS is responsible for security **of** the cloud: data centres, hardware, the hypervisor, and the managed services themselves. The customer is responsible for security **in** the cloud: IAM, data, network rules, encryption settings and logging. Almost every famous cloud breach (public S3 buckets, leaked access keys) falls on the customer's side. cloud-guard only checks customer-side configuration.

### IAM and least privilege
IAM decides *who* (a principal: user, role) can do *what* (actions such as `s3:GetObject`) on *which* resource (an ARN), under which conditions. Least privilege means granting only the permissions a job needs. `"Action": "*", "Resource": "*"` is the opposite: full admin. Users are worse than roles because their credentials are long-lived. Roles give temporary credentials through STS.

### CIS Benchmarks
The Center for Internet Security publishes free, consensus-based configuration baselines. The *CIS AWS Foundations Benchmark* covers IAM, storage, logging, monitoring and networking. Auditors and tools such as Security Hub, Prowler and AWS Config conformance packs use it as a common language. I mapped to v3.0.0, and I marked mappings I wasn't sure about as "approx." instead of inventing control numbers. That is worth saying in an interview: it shows integrity.

### CSPM (Cloud Security Posture Management)
CSPM tools continuously enumerate cloud resources through APIs and compare their configuration to a policy (CIS, PCI-DSS, internal rules). Examples are AWS Security Hub, Prowler, Wiz and Orca. `cloud-guard scan-aws` is a tiny CSPM.

### IaC scanning and shift-left
Infrastructure as Code (Terraform, CloudFormation) means infrastructure is defined in text files and reviewed like code. "Shift-left" means moving security checks earlier in the lifecycle (to the left on a timeline). Catching `acl = "public-read"` in a pull request costs a one-line fix. Catching it in production might cost a data breach. `cloud-guard scan-terraform` is a tiny version of Checkov or tfsec.

### Why both?
IaC scanning only sees what is in code. Live scanning catches **drift** (someone clicked in the console) and resources that were never in Terraform. Real teams run both.

---

## 3. Module-by-module walkthrough

Read the modules in this order.

### `models.py`: the shared vocabulary
- `Severity` is an enum with integer values, so severities can be compared (`HIGH >= MEDIUM`). `--fail-on` depends on this.
- `Finding` is a frozen dataclass. It is immutable because a finding is a fact about a scan and shouldn't be edited after it's created.
- `SkippedCheck` exists because **silently skipping a check is dangerous**. If the scanner lacks permission to read CloudTrail and says nothing, you would think CloudTrail is fine.
- `ScanResult` holds findings, skipped checks, counts by severity and sorting.

### `cis.py`: benchmark references
These are constants such as `USER_MFA = "CIS 1.10"`. Keeping them in one place means that if the benchmark is renumbered, there is one file to update. The docstring states how confident each mapping is.

### `policy.py`: "is this policy dangerous?"
- `is_admin_statement` returns True when Effect is Allow, Action is `*` or `*:*`, and Resource is `*`. Deny statements are ignored because a Deny on everything is a guard rail, not a risk.
- `public_statements` looks for Allow statements with `Principal: "*"` and no Condition.
- **Design choice:** both the AWS checks and the Terraform rules import these functions, so there is one definition of "admin" and "public".

### `netrules.py`: "does this rule expose SSH or RDP?"
`covers_port(protocol, from_port, to_port, port)` handles protocol `-1`/`all` (everything) and port ranges (for example, 20 to 25 includes 22). If a value can't be interpreted, such as a Terraform variable, it returns False. The README lists that as a known limitation.

### `aws/context.py`: `AwsContext`
This object holds everything a check needs: the boto3 session, the region, a client cache, the account id (fetched once from STS), a list of partial skips, and **`now`**.
- **Why inject `now`?** moto creates access keys with today's date. To test "older than 90 days", the tests create a context where `now` is 100 days in the future. This is called dependency injection of the clock, a standard testing technique.

### `aws/errors.py`: classifying failures
This module maps AWS error codes to readable reasons: `AccessDenied` becomes "permission denied", `NotImplementedError` from moto becomes "API not implemented", and so on.

### `aws/checks/*.py`: the actual checks
Each check is a function `check_x(ctx) -> list[Finding]`. They are registered in `aws/checks/__init__.py` in the `ALL_CHECKS` tuple.

- **`iam.py`**
  - *Root*: reads the IAM credential report (a CSV). If it has no `<root_account>` row (moto doesn't add one), the check falls back to `GetAccountSummary` (`AccountMFAEnabled`, `AccountAccessKeysPresent`).
  - *User MFA*: only users with a console password (a login profile) are flagged. This matches CIS 1.10.
  - *Key age*: active keys with `CreateDate` before `now - 90 days`. Key ids are masked in output.
  - *Admin managed policies*: only customer-managed policies (`Scope=Local`) are checked. AWS's own `AdministratorAccess` is expected to exist. Severity is HIGH if the policy is attached, MEDIUM if not.
  - *Inline admin policies on users*: two problems in one, because it is admin access and it bypasses groups (CIS 1.15).
- **`s3.py`**: the most interesting module to discuss.
  - A bucket can be public through an **ACL** or through a **bucket policy**.
  - **Block Public Access (BPA)** has four switches (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) at the account level and the bucket level.
  - cloud-guard computes the *effective* BPA (account OR bucket). A public ACL is only reported if `IgnorePublicAcls` is off, and a public policy only if `RestrictPublicBuckets` is off. This avoids false positives. Too many false positives make engineers ignore a security tool.
  - Errors are handled per bucket: one locked-down bucket is recorded as a skip, and the other buckets are still scanned.
- **`cloudtrail.py`**: no trail (CT-001), trail not logging (CT-004), no active multi-region trail (CT-002), log file validation off (CT-003). `includeShadowTrails=True` ensures a multi-region trail created in another region still counts.
- **`ec2.py`**: security groups open to `0.0.0.0/0` or `::/0` on 22 or 3389, and EBS encryption-by-default (a per-region account setting).

### `aws/scanner.py`: the runner
This loops over `ALL_CHECKS`, and each check runs in its own try/except, so **one failing check never stops the others**. Missing credentials are the exception: if there are none, nothing can run, so the scanner fails fast with a helpful message ("try `cloud-guard demo`").

### `terraform/parser.py`
This uses `python-hcl2` to turn `.tf` files into dicts and wraps each `resource` / `data` block in a `TerraformBlock` (type, name, body, file). It skips `.terraform/` (downloaded modules). A syntax error in one file is recorded and the other files are still scanned.

### `terraform/rules.py`
Each rule receives **all** blocks, not one at a time, because some rules span several resources:
- *Encryption*: in AWS provider v4 and later, encryption is a **separate** resource (`aws_s3_bucket_server_side_encryption_configuration`) that references the bucket with `aws_s3_bucket.NAME.id`. The rule collects those references first.
- *CloudTrail missing*: the rule needs to know if a trail exists **anywhere**.
- *Security groups*: there are three different ways to write an ingress rule in Terraform. `_ingress_rules` normalises them into one shape, and the shared `covers_port` checks it.
- *IAM*: policies can be heredoc JSON, `jsonencode({...})`, or a `data "aws_iam_policy_document"`. For `jsonencode`, the HCL object text is converted to JSON (`Key =` becomes `"Key":`). If that fails because of references like `aws_s3_bucket.b.arn`, a regex fallback is used.

### `reporting/`
- `console.py`: an ASCII table, so it works in PowerShell, cmd and CI logs.
- `json_report.py`: for machines (pipelines, dashboards, `jq`).
- `documents.py`: Markdown (for PR comments and GitHub job summaries) and self-contained HTML. **Every value is HTML-escaped**, because resource names are chosen by whoever created the resource and could contain `<script>`. A test proves this.

### `cli.py`
Built with `argparse`. Exit codes: **0** means passed, **1** means findings at or above `--fail-on`, **2** means the scan could not run. Keeping "found problems" (1) separate from "broken" (2) lets a CI system tell the two apart.

### `demo.py`
This starts `moto.mock_aws()`, creates fake users, buckets, a trail and security groups (both insecure and secure ones), and scans them. The tests use the same seed functions, so the demo and the tests can't drift apart.

---

## 4. Design choices you can defend

| Choice | Why |
|---|---|
| Read-only API calls only | A security tool must never become the incident. It can run with a tightly scoped audit role (`docs/iam-readonly-policy.json`). |
| moto for tests | Fast, free, deterministic, and no risk of touching a real account. The trade-off is that moto is not 100% faithful to AWS (see the limitations in the README). |
| Plain functions plus a registry instead of classes | Easier to read, test and extend. A new check is one function and one line. |
| Report skips explicitly | A false sense of security is worse than a known gap. |
| Effective-BPA logic | Fewer false positives, so engineers trust the findings. |
| Shared `policy.py` / `netrules.py` | Live scanning and IaC scanning agree on what "bad" means. |
| Exit codes 0/1/2 | Standard CI contract, so the tool can block merges. |
| ASCII output, `pathlib` | Works the same on Windows and Linux. |

---

## 5. Ten likely interview questions, with model answers

**1. "Walk me through what happens when I run `cloud-guard scan-aws`."**
> "The CLI builds a boto3 session from the standard credential chain and wraps it in an AwsContext with the region and current time. The scanner first calls `sts:GetCallerIdentity` to confirm the credentials work and get the account id. Then it runs each registered check: IAM, S3, CloudTrail, EC2. Each check makes read-only List/Get/Describe calls and returns Finding objects. Each check runs in its own try/except, so an AccessDenied on CloudTrail becomes a 'skipped' entry and doesn't crash the IAM checks. Finally, the results are rendered and the exit code is set based on `--fail-on`."

**2. "How do you determine whether an S3 bucket is public?"**
> "A bucket can be made public in two ways: an ACL grant to the AllUsers or AuthenticatedUsers group, or a bucket policy with Principal `*`. But Block Public Access can override both. IgnorePublicAcls makes public ACLs ineffective, and RestrictPublicBuckets neutralises public policies. BPA can be set at the account or bucket level, so I compute the effective setting as account OR bucket, and only report public access that is actually in effect. My version simplifies things: I treat any policy with a Condition as non-public. AWS's own policy-status API and Access Analyzer do proper reasoning on conditions."

**3. "Why is `Action: *` on `Resource: *` dangerous, and what would you do instead?"**
> "It grants every API call on every resource, including `iam:CreateUser`, `iam:AttachUserPolicy` and `kms:ScheduleKeyDeletion`. Anyone holding it can escalate, persist and destroy. Instead, apply least privilege: list the specific actions and resource ARNs, use IAM Access Analyzer to generate a policy from CloudTrail activity, add permission boundaries, and use SCPs at the organisation level as guard rails. My check has limits. For example, `NotAction: iam:*` is nearly admin, and I don't catch it yet."

**4. "What's the difference between CSPM and IaC scanning? Why do both?"**
> "IaC scanning checks the *intended* state in code before deployment. It's cheap to fix and runs in the pull request. CSPM checks the *actual* state in the account. It catches drift, console changes and resources that were never in code. Doing only IaC misses drift. Doing only CSPM means problems are already live before you find them."

**5. "How did you test this without an AWS account?"**
> "With moto, which intercepts boto3 calls and keeps an in-memory model of AWS. Every check has an insecure test and a fixed test. For example, one test creates a public-read bucket and expects CG-S3-001, and another adds Block Public Access and expects that finding to disappear. For things moto can't simulate, I used other techniques: I inject the clock to test key age, and I monkeypatch the credential report to test the root-account path. I also ran the suite on Python 3.10 and 3.13."

**6. "What happens if the scanning role is missing a permission?"**
> "The check is reported as skipped with the reason 'permission denied (AccessDenied)', and the scan continues. For S3, it's handled per bucket, so one bucket with a restrictive policy doesn't hide the others. Skips appear in every report format, because silently passing a check you couldn't run gives a false sense of security."

**7. "How would you use this in a CI/CD pipeline?"**
> "Run `cloud-guard scan-terraform ./infra --fail-on high` as a required check on pull requests. Exit code 1 blocks the merge. The included GitHub Actions workflow also writes a Markdown report to the job summary and uploads an HTML artifact. The workflow token only has `contents: read`, which is least privilege for the pipeline itself. In production I would add a suppression file with mandatory justifications, so accepted risks don't block every build."

**8. "What are the limitations of static Terraform analysis?"**
> "It can't see values that are only known at plan time, such as variables, module outputs or `count`/`for_each` expansions. If the SSH port is `var.ssh_port`, I can't tell it's 22. The fix is to scan the JSON plan (`terraform show -json plan.out`), where values are resolved. That's what mature tools such as Checkov support. Static scanning is still valuable because it's fast and needs no credentials."

**9. "Why do the CIS references say 'approx.' in some places?"**
> "I mapped to CIS AWS Foundations v3.0.0 from my knowledge of the benchmark, without copying the licensed text. Where my check is related to a control but not identical to it, for example 'bucket is public via ACL' versus the control 'Block Public Access enabled', I mark it approx. S3 default encryption has no v3.0.0 control because AWS now encrypts new objects by default, so I say that instead of making up a number. In compliance work, a wrong control reference is worse than none."

**10. "If you had another month, what would you add?"**
> "First, plan-JSON scanning for Terraform, to fix the biggest accuracy gap. Then multi-region scanning, SARIF output so findings appear in GitHub code scanning, and more CIS controls: password policy, unused credentials, KMS rotation, VPC flow logs. Longer term, I'd make it event-driven: trigger checks from CloudTrail events through EventBridge and Lambda, so a bucket made public is detected in seconds, not at the next scheduled scan."

### Bonus quick-fire questions
- *What does CloudTrail log file validation do?* It writes hourly digest files signed with SHA-256 hashing and RSA signatures, so you can prove log files weren't modified or deleted.
- *Why multi-region trails?* Attackers use regions you don't watch, for example to run crypto-miners.
- *Why are access keys worse than roles?* Keys are long-lived and get leaked (Git commits, laptops). Roles issue short-lived STS credentials automatically.
- *SSH alternative to opening port 22?* AWS Systems Manager Session Manager. It needs no inbound ports, uses IAM for authentication, and sessions are logged.
- *Why mask access key ids?* Key ids aren't secret on their own, but reports get shared widely. Showing less is defence in depth.

---

## 6. How to demo in 2 minutes

Before the interview, open a terminal in the project with the venv activated, and run each command once so nothing is slow.

1. **(15 s) Frame it.** "Misconfiguration is the top cause of cloud breaches. This tool finds it in live AWS and in Terraform, mapped to CIS."
2. **(35 s) Live scan, without an account.**
   ```
   cloud-guard demo
   ```
   Point out: "This is a fake AWS account in memory, using moto. No credentials needed. CRITICAL: a public bucket and no root MFA. HIGH: SSH and RDP open to the internet, and an admin policy. Each finding has the ARN, the CIS control and a fix." Mention that `bob` and `cg-demo-secure` are *not* flagged, which shows there are no false positives on good configuration.
3. **(35 s) Shift-left.**
   ```
   cloud-guard scan-terraform examples/terraform/insecure
   echo $?            # PowerShell: $LASTEXITCODE
   cloud-guard scan-terraform examples/terraform/secure
   ```
   "Same kind of rules, but on code before deployment. Exit code 1 fails a pipeline. The secure version passes with 0."
4. **(20 s) Report.**
   ```
   cloud-guard demo --format html -o report.html
   ```
   Open it in a browser and show the summary cards.
5. **(15 s) Quality.**
   ```
   python -m pytest -q
   ```
   "112 tests, an insecure case and a fixed case for every check, all against mocked AWS."

Close with one honest limitation and its fix, for example: "Terraform scanning is static, so variables aren't resolved. Next I'd scan plan JSON." Interviewers value self-awareness more than feature count.

---

## 7. Things to practise saying out loud

- "Shared responsibility: AWS secures the cloud, we secure what we put in it."
- "Least privilege: start from zero and add only what's needed."
- "Defence in depth: BPA at account level *and* bucket level."
- "Fail loudly: report what you couldn't check."
- "Shift-left: the cheapest place to fix a misconfiguration is the pull request."
