"""Stage 5: Regex Pattern Matching — 50+ detection rules."""

import re

from ..models import ScanContext
from ..utils import is_placeholder

RULES = [
    {"name": "AWS Access Key ID", "pattern": r"(AKIA[0-9A-Z]{16})", "base_score": 95, "fix": "Use IAM roles, environment variables, or AWS Secrets Manager.", "category": "cloud"},
    {"name": "AWS Secret Access Key", "pattern": r"(?:aws_secret_access_key|aws_secret_key|AWS_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "base_score": 95, "fix": "Use ~/.aws/credentials, environment variables, or IAM roles.", "category": "cloud", "needs_entropy": True},
    {"name": "AWS MWS Key", "pattern": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "base_score": 90, "fix": "Store MWS keys in a secrets manager.", "category": "cloud"},
    {"name": "Google API Key", "pattern": r"(AIza[0-9A-Za-z_-]{35})", "base_score": 90, "fix": "Restrict the key in GCP Console and use environment variables.", "category": "cloud"},
    {"name": "Google OAuth Client Secret", "pattern": r"(?:client_secret)\s*[=:]\s*['\"]([A-Za-z0-9_-]{24,})['\"]", "base_score": 85, "fix": "Use OAuth flow with server-side token exchange.", "category": "cloud", "needs_entropy": True},
    {"name": "GCP Service Account Key", "pattern": r"\"type\"\s*:\s*\"service_account\"", "base_score": 90, "fix": "Use Workload Identity Federation instead of key files.", "category": "cloud"},
    {"name": "Azure Storage Account Key", "pattern": r"(?:AccountKey|azure_storage_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{86,88})['\"]?", "base_score": 90, "fix": "Use Azure Managed Identity or Key Vault.", "category": "cloud"},
    {"name": "Azure Connection String", "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+", "base_score": 90, "fix": "Store in Azure Key Vault or app settings.", "category": "cloud"},
    {"name": "GitHub Personal Access Token", "pattern": r"(ghp_[A-Za-z0-9_]{36,})", "base_score": 95, "fix": "Use GITHUB_TOKEN in CI or environment variables.", "category": "vcs"},
    {"name": "GitHub OAuth Token", "pattern": r"(gho_[A-Za-z0-9_]{36,})", "base_score": 90, "fix": "Use GitHub App tokens or environment variables.", "category": "vcs"},
    {"name": "GitHub App Token", "pattern": r"(ghu_[A-Za-z0-9_]{36,}|ghs_[A-Za-z0-9_]{36,}|ghr_[A-Za-z0-9_]{36,})", "base_score": 90, "fix": "Rotate and store in environment variables.", "category": "vcs"},
    {"name": "GitLab Token", "pattern": r"(glpat-[A-Za-z0-9_-]{20,})", "base_score": 90, "fix": "Use CI/CD variables or environment variables.", "category": "vcs"},
    {"name": "Stripe Live Secret Key", "pattern": r"(sk_live_[A-Za-z0-9]{20,})", "base_score": 95, "fix": "Use environment variables. Use sk_test_ for development.", "category": "payment"},
    {"name": "Stripe Restricted Key", "pattern": r"(rk_live_[A-Za-z0-9]{20,})", "base_score": 90, "fix": "Store restricted keys in environment variables.", "category": "payment"},
    {"name": "PayPal Braintree Token", "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "base_score": 90, "fix": "Use server-side environment variables.", "category": "payment"},
    {"name": "Square Access Token", "pattern": r"sq0atp-[0-9A-Za-z_-]{22,}", "base_score": 90, "fix": "Store Square tokens in environment variables.", "category": "payment"},
    {"name": "Slack Webhook URL", "pattern": r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)", "base_score": 85, "fix": "Store webhook URLs in environment variables.", "category": "communication"},
    {"name": "Slack Bot Token", "pattern": r"(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})", "base_score": 90, "fix": "Use environment variables for Slack bot tokens.", "category": "communication"},
    {"name": "Discord Webhook URL", "pattern": r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+)", "base_score": 85, "fix": "Store webhook URLs in environment variables.", "category": "communication"},
    {"name": "Twilio API Key", "pattern": r"(SK[0-9a-fA-F]{32})", "base_score": 75, "fix": "Store Twilio credentials in environment variables.", "category": "communication", "needs_entropy": True},
    {"name": "SendGrid API Key", "pattern": r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})", "base_score": 95, "fix": "Use environment variables for SendGrid API keys.", "category": "communication"},
    {"name": "Mailgun API Key", "pattern": r"key-[0-9a-zA-Z]{32}", "base_score": 85, "fix": "Store Mailgun keys in environment variables.", "category": "communication"},
    {"name": "Datadog API Key", "pattern": r"(?:datadog_api_key|DD_API_KEY)\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?", "base_score": 80, "fix": "Use environment variables for Datadog keys.", "category": "monitoring", "needs_entropy": True},
    {"name": "New Relic License Key", "pattern": r"(?:NEW_RELIC_LICENSE_KEY|newrelic_key)\s*[=:]\s*['\"]?([A-Za-z0-9]{40})['\"]?", "base_score": 80, "fix": "Use environment variables for New Relic keys.", "category": "monitoring", "needs_entropy": True},
    {"name": "Sentry DSN", "pattern": r"https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/\d+", "base_score": 60, "fix": "Sentry DSNs are semi-public but best kept in env config.", "category": "monitoring"},
    {"name": "Database Connection String", "pattern": r"((?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql|mariadb)://[^\s'\"]{10,})", "base_score": 85, "fix": "Use environment variables for connection strings.", "category": "database"},
    {"name": "JDBC Connection with Password", "pattern": r"(jdbc:[a-z]+://[^\s'\"]*(?:password|pwd)=[^\s&'\"]+)", "base_score": 90, "fix": "Use a connection pool config with externalized credentials.", "category": "database"},
    {"name": "RSA Private Key", "pattern": r"-----BEGIN RSA PRIVATE KEY-----", "base_score": 98, "fix": "Store private keys in a vault or HSM.", "category": "crypto"},
    {"name": "EC Private Key", "pattern": r"-----BEGIN EC PRIVATE KEY-----", "base_score": 98, "fix": "Store private keys in a vault or HSM.", "category": "crypto"},
    {"name": "OpenSSH Private Key", "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----", "base_score": 98, "fix": "Never commit SSH keys. Use ssh-agent.", "category": "crypto"},
    {"name": "PGP Private Key", "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "base_score": 98, "fix": "Store PGP keys in a keyring.", "category": "crypto"},
    {"name": "Generic Private Key", "pattern": r"-----BEGIN (?:DSA |ENCRYPTED )?PRIVATE KEY-----", "base_score": 95, "fix": "Store private keys in a secure vault.", "category": "crypto"},
    {"name": "JWT Token", "pattern": r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", "base_score": 65, "fix": "JWTs should be obtained at runtime.", "category": "auth"},
    {"name": "Hardcoded Password", "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})['\"]", "base_score": 75, "fix": "Never hardcode passwords. Use env vars or credential store.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded API Key", "pattern": r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 75, "fix": "Move API keys to environment variables.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded Secret", "pattern": r"(?:secret|secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 80, "fix": "Use a secrets manager or environment variables.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded Auth Token", "pattern": r"(?:auth[_-]?token|access[_-]?token|bearer[_-]?token|refresh[_-]?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 80, "fix": "Tokens should come from OAuth flows or env vars.", "skip_test": True, "needs_entropy": True, "category": "credential"},
    {"name": "Hardcoded Encryption Key", "pattern": r"(?:encryption[_-]?key|encrypt[_-]?key|aes[_-]?key|signing[_-]?key)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 85, "fix": "Use a KMS for encryption keys.", "skip_test": True, "needs_entropy": True, "category": "crypto"},
    {"name": "URL with Embedded Credentials", "pattern": r"(https?://[^:]+:[^@]+@[^\s'\"]+)", "base_score": 85, "fix": "Never embed credentials in URLs.", "category": "credential"},
    {"name": "Hardcoded IP Address", "pattern": r"['\"](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})['\"]", "base_score": 25, "fix": "Use config files or env vars for IPs.", "category": "infra"},
    {"name": "Android Manifest API Key", "pattern": r"android:value\s*=\s*\"([A-Za-z0-9_-]{20,})\"", "base_score": 70, "fix": "Use BuildConfig from local.properties.", "file_pattern": r"AndroidManifest\.xml", "needs_entropy": True, "category": "android"},
    {"name": "BuildConfig Hardcoded Secret", "pattern": r"buildConfigField\s+['\"]String['\"]\s*,\s*['\"].*(?:KEY|SECRET|TOKEN).*['\"]\s*,\s*['\"]\\\"([^\"]+)\\\"['\"]", "base_score": 80, "fix": "Read from local.properties.", "file_pattern": r"\.gradle", "category": "android"},
    {"name": "Firebase Config Inline", "pattern": r"(?:firebase|firebaseConfig)\s*[=:]\s*\{[^}]*apiKey\s*:", "base_score": 60, "fix": "Use google-services.json.", "category": "android"},
    {"name": "npm Token", "pattern": r"//registry\.npmjs\.org/:_authToken=([A-Za-z0-9_-]+)", "base_score": 90, "fix": "Use npm login or CI env vars.", "category": "registry"},
    {"name": "PyPI Token", "pattern": r"(pypi-[A-Za-z0-9_-]{50,})", "base_score": 90, "fix": "Use keyring or CI secrets.", "category": "registry"},
    {"name": "Docker Hub Token", "pattern": r"(?:DOCKER_PASSWORD|DOCKER_TOKEN)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "base_score": 80, "fix": "Use docker credential helpers.", "category": "registry", "needs_entropy": True},
    {"name": "High Entropy String", "pattern": r"['\"]([A-Za-z0-9+/=_-]{32,})['\"]", "base_score": 35, "fix": "Review — high entropy strings may be secrets.", "needs_entropy": True, "skip_test": True, "category": "entropy"},
    {"name": "Possible Password (unquoted)", "pattern": r"(?:PASSWORD|PASSWD|PWD|DB_PASSWORD|EMAIL_PASSWORD|ADMIN_PASSWORD)\s*=\s*(\S{4,})", "base_score": 40, "fix": "If real, move to secrets manager or .gitignored .env.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible Secret/Key (unquoted)", "pattern": r"(?:SECRET|SECRET_KEY|JWT_SECRET|APP_SECRET|SIGNING_KEY|ENCRYPTION_KEY)\s*=\s*(\S{6,})", "base_score": 40, "fix": "If real, use env vars or secrets manager.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible Token (unquoted)", "pattern": r"(?:TOKEN|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|BEARER_TOKEN|API_TOKEN|GITHUB_TOKEN)\s*=\s*(\S{8,})", "base_score": 40, "fix": "If real, store in env vars or secrets manager.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible API Key (unquoted)", "pattern": r"(?:API_KEY|APIKEY|API_SECRET|GOOGLE_API_KEY|STRIPE_API_KEY|MAPS_API_KEY)\s*=\s*(\S{8,})", "base_score": 40, "fix": "If real, move to env vars or secrets manager.", "skip_test": True, "needs_entropy": True, "category": "candidate"},
    {"name": "Possible Connection String (unquoted)", "pattern": r"(?:DATABASE_URL|DB_URL|REDIS_URL|MONGO_URI|CONNECTION_STRING)\s*=\s*(\S{10,})", "base_score": 45, "fix": "Connection strings often contain credentials.", "skip_test": True, "category": "candidate"},
]


def stage_regex(ctx: ScanContext) -> None:
    """Run regex rules against normalized lines."""
    seen = set()
    for line_num, line in enumerate(ctx.normalized_lines, 1):
        if not line.strip():
            continue
        for rule in RULES:
            if rule.get("skip_test") and ctx.is_test:
                continue
            if rule.get("file_pattern") and not re.search(rule["file_pattern"], ctx.filename):
                continue
            for match in re.finditer(rule["pattern"], line, re.IGNORECASE):
                matched_text = match.group(0)
                secret_value = match.group(1) if match.lastindex else matched_text
                if is_placeholder(secret_value):
                    continue
                dedup_key = (line_num, rule["name"])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                ctx.regex_hits.append({
                    "line": line_num, "rule": rule["name"],
                    "category": rule.get("category", "unknown"),
                    "base_score": rule.get("base_score", 50),
                    "match": matched_text, "secret_value": secret_value,
                    "fix": rule["fix"], "needs_entropy": rule.get("needs_entropy", False),
                    "original_line": line,
                })
