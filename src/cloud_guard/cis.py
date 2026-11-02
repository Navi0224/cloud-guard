"""CIS AWS Foundations Benchmark references used by the checks.

We map to **CIS Amazon Web Services Foundations Benchmark v3.0.0**.

Honesty note: these control numbers were written from the author's knowledge of
the benchmark, not copied from the licensed PDF. Where we are confident, the
reference is given plainly. Where the mapping is loose (our check is related to,
but not identical to, the CIS control) it is prefixed with "approx.". Where no
v3.0.0 control exists, we say so. Always verify against the official document
(free download from cisecurity.org) before quoting numbers in an audit.
"""

BENCHMARK = "CIS AWS Foundations Benchmark v3.0.0"

# Identity and Access Management (section 1)
ROOT_ACCESS_KEYS = "CIS 1.4"          # No root user access keys exist
ROOT_MFA = "CIS 1.5"                  # MFA enabled for the root user
USER_MFA = "CIS 1.10"                 # MFA for all IAM users with a console password
KEY_ROTATION = "CIS 1.14"             # Access keys rotated every 90 days or less
PERMISSIONS_VIA_GROUPS = "CIS 1.15"   # Users get permissions only through groups
NO_FULL_ADMIN_POLICIES = "CIS 1.16"   # No policies allowing full "*:*" admin

# Storage (section 2)
S3_BLOCK_PUBLIC_ACCESS = "CIS 2.1.4"  # S3 Block Public Access (bucket settings)
S3_PUBLIC = "approx. CIS 2.1.4"       # Public ACL/policy - closest control is BPA
S3_ENCRYPTION = "No v3.0.0 control (was 2.1.1 in v1.5.0; AWS now encrypts new buckets by default)"
EBS_DEFAULT_ENCRYPTION = "CIS 2.2.1"  # EBS volume encryption enabled by default

# Logging (section 3)
CLOUDTRAIL_MULTI_REGION = "CIS 3.1"   # CloudTrail enabled in all regions
CLOUDTRAIL_LOG_VALIDATION = "CIS 3.2" # CloudTrail log file validation enabled

# Networking (section 5)
SG_ADMIN_PORTS = "CIS 5.2"            # No SG ingress from 0.0.0.0/0 to admin ports
SG_ADMIN_PORTS_IPV6 = "CIS 5.3"       # Same for ::/0
