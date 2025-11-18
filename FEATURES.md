# RedTeam Enhanced Features Documentation

This document describes the advanced visualization, reporting, and security features added to the RedTeam LLM security testing framework.

## Table of Contents

1. [Advanced Visualization & Reporting](#advanced-visualization--reporting)
2. [Security & Privacy Features](#security--privacy-features)
3. [Setup & Installation](#setup--installation)
4. [Usage Examples](#usage-examples)

---

## Advanced Visualization & Reporting

### 1. Enhanced Dashboard (ui/enhanced_app.py)

The new dashboard provides a comprehensive interface with multiple views:

#### Overview Page
- **Real-time Metrics**: Total attacks, vulnerabilities found, vulnerability rate, average severity
- **Severity Distribution**: Interactive pie chart showing critical/high/medium/low breakdown
- **Vulnerability Types**: Bar chart showing distribution of vulnerability categories
- **Recent Critical Vulnerabilities**: Quick view of the most severe findings

#### Attack Explorer
- **Interactive Filters**:
  - Filter by severity level (Critical, High, Medium, Low)
  - Filter by vulnerability status (Vulnerable, Safe)
  - Filter by tags (jailbreak, instruction, etc.)
  - Date range filtering
- **Results Table**: Sortable table with attack ID, prompt preview, vulnerability status, severity
- **Detailed View**: Click any attack to see full prompt, response, and analysis

#### Time Trends
- **Vulnerability Rate Over Time**: Line chart showing how vulnerability rate changes over time
- **Average Severity Trends**: Track if attacks are getting more or less severe
- **Attack Volume**: Bar chart showing daily attack execution volume

#### Model Comparison
- **Side-by-Side Comparison**: Compare vulnerability rates across different models
- **Performance Metrics**: Total attacks, vulnerable count, vulnerability rate, average severity
- **Visual Comparisons**: Bar charts comparing models by vulnerability rate and severity

#### Heatmap Analysis
- **Attack Type vs Model Matrix**: Visualize which models are most vulnerable to specific attack types
- **Color-Coded Intensity**: Darker colors indicate higher vulnerability rates
- **Interactive Tooltips**: Hover to see exact percentages

#### Export & Reports
- **CSV Export**: Export all results and scores to CSV format
- **JSON Export**: Export data in JSON format for programmatic access
- **SARIF Export**: Export to SARIF format for integration with security tools (GitHub Advanced Security, etc.)
- **PDF Report Generation**: Generate executive summary reports with charts and statistics
- **Attack Replay**: Re-run historical attacks against updated models

### 2. Export Functionality (exports/)

#### CSV Exporter
```python
from exports import export_results

# Export to CSV
path = export_results(results, format='csv', output_dir='exports')
```

Features:
- Flattens nested JSON structures
- Handles lists by converting to JSON strings
- Auto-generates filenames with timestamps

#### JSON Exporter
```python
# Export to JSON with pretty printing
path = export_results(results, format='json', output_dir='exports')
```

Features:
- Pretty-printed or compact output
- Preserves all data structures
- UTF-8 encoding support

#### SARIF Exporter
```python
# Export to SARIF (Static Analysis Results Interchange Format)
path = export_results(scores, format='sarif', output_dir='exports')
```

Features:
- SARIF 2.1.0 compliant
- Maps vulnerabilities to standard rules
- Compatible with GitHub Advanced Security
- Integrates with CI/CD pipelines

### 3. PDF Report Generation (exports/pdf_reporter.py)

Generate professional executive summary reports:

```python
from exports.pdf_reporter import generate_pdf_report

# Generate report
path = generate_pdf_report(
    results=results,
    scores=scores,
    metadata={
        "models_tested": ["gpt-4o-mini", "gemini-2.5-flash"],
        "test_date": "2025-01-17",
        "total_attacks": 18
    }
)
```

Features:
- Professional HTML/PDF output
- Executive-friendly layout
- Statistics dashboard
- Severity distribution charts
- Detailed vulnerability tables
- Uses Jinja2 templates for customization
- Automatic fallback to HTML if WeasyPrint unavailable

---

## Security & Privacy Features

### 1. PII Detection (security/pii_detector.py)

Automatically detect and redact personally identifiable information:

```python
from security import PIIDetector

detector = PIIDetector()

# Detect PII
findings = detector.detect(text)
# Returns: {'EMAIL': ['user@example.com'], 'PHONE_US': ['555-1234'], ...}

# Redact PII
redacted_text, counts = detector.redact(text)
# Returns: (redacted_text, {'EMAIL': 2, 'SSN': 1})

# Quick check
has_pii = detector.has_pii(text)
```

Supported PII Types:
- Email addresses
- Phone numbers (US format)
- Social Security Numbers
- Credit card numbers
- IP addresses
- Dates of birth
- ZIP codes
- Passport numbers
- Driver's license numbers

### 2. Credential Scanning (security/credential_scanner.py)

Detect exposed credentials and API keys:

```python
from security import CredentialScanner

scanner = CredentialScanner()

# Scan for credentials
findings = scanner.scan(text)
# Returns: {'OPENAI_API_KEY': ['sk-...'], 'AWS_ACCESS_KEY': ['AKIA...'], ...}

# Risk assessment
risk = scanner.assess_risk(text)
# Returns: {
#   'risk_level': 'CRITICAL',
#   'total_credentials': 3,
#   'high_risk_credentials': 2,
#   'findings': {...}
# }

# Redact credentials
redacted = scanner.redact_credentials(text)
```

Supported Credential Types:
- OpenAI API keys
- Anthropic API keys
- Google API keys
- AWS access keys and secrets
- GitHub tokens
- Slack tokens
- Stripe API keys
- JWT tokens
- Basic/Bearer auth tokens
- Private keys (RSA, EC)
- Generic secrets/passwords

### 3. Data Sanitization (security/sanitizer.py)

Combined PII and credential sanitization:

```python
from security import DataSanitizer

sanitizer = DataSanitizer()

# Sanitize text
result = sanitizer.sanitize(text)
# Returns: {
#   'sanitized_text': '...',
#   'pii_found': {...},
#   'credentials_found': {...},
#   'has_sensitive_data': True
# }

# Scan only (no redaction)
scan_results = sanitizer.scan_only(text)
```

### 4. Audit Logging (security/audit_logger.py)

Immutable audit trail with cryptographic verification:

```python
from security import get_audit_logger

logger = get_audit_logger()

# Log events
logger.log_attack_execution(
    user="admin",
    attack_id="jb-001",
    model="gpt-4o-mini",
    success=True
)

logger.log_data_access(
    user="analyst",
    resource="data/results.jsonl",
    access_type="READ"
)

logger.log_security_event(
    user="admin",
    event="PII detected in model response",
    severity="WARNING"
)

# Verify integrity
verification = logger.verify_log_integrity()
# Returns: {'valid': True, 'message': '...', 'total_events': 42}

# Get audit statistics
stats = logger.get_statistics()
```

Features:
- Append-only log file
- Cryptographic hash chain for tamper detection
- Event types: ATTACK_EXECUTION, DATA_ACCESS, SECURITY_EVENT, MODEL_QUERY
- Severity levels: INFO, WARNING, ERROR, CRITICAL
- Automatic timestamp and hash generation

### 5. Rate Limiting (security/rate_limiter.py)

Prevent API abuse with token bucket rate limiting:

```python
from security import get_model_rate_limiter

limiter = get_model_rate_limiter(max_requests=60, time_window=60)

# Check if request allowed
if limiter.allow_request("gpt-4o-mini"):
    # Make API call
    pass
else:
    # Rate limit exceeded
    pass

# Wait if needed
if limiter.wait_if_needed("gpt-4o-mini", max_wait=10.0):
    # Request allowed, proceed
    pass

# Get statistics
stats = limiter.get_stats("gpt-4o-mini")
# Returns: {
#   'remaining_requests': 45,
#   'reset_time': 32.5,
#   'max_requests': 60,
#   'time_window': 60
# }
```

Features:
- Per-model rate limiting
- Global rate limiting across all models
- Sliding window algorithm
- Configurable limits and time windows
- Automatic cleanup of old requests

### 6. Access Control (security/access_control.py)

Role-based access control system:

```python
from security import get_access_control, Role, Permission

ac = get_access_control()

# Add users
ac.add_user("alice", Role.OPERATOR, "alice@example.com")
ac.add_user("bob", Role.ANALYST, "bob@example.com")

# Check permissions
if ac.check_permission("alice", Permission.RUN_ATTACKS):
    # User has permission
    pass

# Require permission (raises PermissionError if lacking)
ac.require_permission("bob", Permission.RUN_ATTACKS)

# Update roles
ac.update_user_role("alice", Role.ADMIN)

# List users
users = ac.list_users()
```

Available Roles:
- **ADMIN**: Full access to all features
- **OPERATOR**: Can run attacks, create attacks, view results
- **ANALYST**: Can view results, export data, view audit logs
- **READ_ONLY**: Can only view results

Available Permissions:
- `RUN_ATTACKS`: Execute attack campaigns
- `CREATE_ATTACKS`: Create new attack templates
- `DELETE_ATTACKS`: Delete attack data
- `VIEW_RESULTS`: View attack results
- `EXPORT_DATA`: Export data to various formats
- `DELETE_DATA`: Delete result data
- `QUERY_MODELS`: Query LLM models
- `CONFIGURE_MODELS`: Configure model settings
- `VIEW_AUDIT_LOG`: View audit logs
- `MANAGE_USERS`: Manage user accounts
- `CONFIGURE_SYSTEM`: Configure system settings
- `SCAN_PII`: Scan for PII
- `SCAN_CREDENTIALS`: Scan for credentials

### 7. Enhanced Model Client

The model client now supports security features:

```python
from models.client import ModelClient

client = ModelClient(
    provider="openai",
    api_key="sk-...",
    enable_rate_limiting=True,
    enable_audit_logging=True,
    user="alice"
)

# Rate limiting and audit logging now automatic
response = client.query("jb-001", "Your prompt here")
```

---

## Setup & Installation

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

New dependencies include:
- `plotly` - Interactive visualizations
- `pandas` - Data manipulation
- `jinja2` - Template rendering
- `weasyprint` - PDF generation (optional)
- `pillow` - Image processing

### 2. Run the Enhanced Dashboard

```bash
streamlit run ui/enhanced_app.py
```

The dashboard will be available at `http://localhost:8501`

### 3. Enable Security Features

Security features are opt-in. To enable:

```python
# In runner/cli.py or your custom script
from models.client import ModelClient

client = ModelClient(
    provider="openai",
    api_key=os.environ.get("OPENAI_API_KEY"),
    enable_rate_limiting=True,
    enable_audit_logging=True,
    user="current_user"
)
```

---

## Usage Examples

### Example 1: Generate Comprehensive Report

```python
from exports.pdf_reporter import generate_pdf_report
import json

# Load data
with open('data/results.jsonl', 'r') as f:
    results = [json.loads(line) for line in f if line.strip()]

with open('data/score_report.json', 'r') as f:
    scores = json.load(f)['scores']

# Generate report
report_path = generate_pdf_report(
    results=results,
    scores=scores,
    metadata={
        "project": "Q1 2025 Security Assessment",
        "models_tested": ["gpt-4o-mini", "gemini-2.5-flash"],
        "test_date": "2025-01-17"
    }
)

print(f"Report generated: {report_path}")
```

### Example 2: Scan Results for Sensitive Data

```python
from security import DataSanitizer
import json

sanitizer = DataSanitizer()

# Load results
with open('data/results.jsonl', 'r') as f:
    results = [json.loads(line) for line in f if line.strip()]

# Scan each result
for result in results:
    response = result.get('response', '')
    scan = sanitizer.scan_only(response)

    if scan['has_pii'] or scan['has_credentials']:
        print(f"⚠️  {result['attack_id']}: Found sensitive data!")
        print(f"   PII: {scan['pii_summary']}")
        print(f"   Credentials: {scan['credential_risk']['risk_level']}")
```

### Example 3: Export to Multiple Formats

```python
from exports import export_results

# Load your data
combined_data = []  # Your results + scores

# Export to all formats
csv_path = export_results(combined_data, format='csv', output_dir='reports')
json_path = export_results(combined_data, format='json', output_dir='reports')
sarif_path = export_results(combined_data, format='sarif', output_dir='reports')

print(f"Exported to:")
print(f"  CSV: {csv_path}")
print(f"  JSON: {json_path}")
print(f"  SARIF: {sarif_path}")
```

### Example 4: Verify Audit Log Integrity

```python
from security import get_audit_logger

logger = get_audit_logger()

# Verify log hasn't been tampered with
verification = logger.verify_log_integrity()

if verification['valid']:
    print(f"✅ Audit log is valid ({verification['total_events']} events)")
else:
    print(f"❌ Audit log integrity compromised!")
    print(f"   {verification['message']}")

# Get statistics
stats = logger.get_statistics()
print(f"\nAudit Log Statistics:")
print(f"  Total Events: {stats['total_events']}")
print(f"  Event Types: {stats['event_types']}")
print(f"  Users: {stats['users']}")
print(f"  Severities: {stats['severities']}")
```

### Example 5: Replay Attacks with Security Features

```python
from models.client import ModelClient
from runner.runner import Runner
from security import get_audit_logger
import json

# Load attacks
with open('data/sample_attack_cases.json', 'r') as f:
    attacks = json.load(f)

# Create client with security features
client = ModelClient(
    provider="openai",
    api_key="sk-...",
    enable_rate_limiting=True,
    enable_audit_logging=True,
    user="security_team"
)

# Run attacks
runner = Runner(client)
runner.run_all(attacks, output_file='data/replay_results.jsonl', workers=4)

# Check audit log
logger = get_audit_logger()
events = logger.get_events(event_type='MODEL_QUERY', limit=100)
print(f"Logged {len(events)} model queries")
```

---

## Advanced Configuration

### Customize Rate Limits

```python
from security.rate_limiter import MultiRateLimiter

# Custom rate limiter with different limits per model
limiter = MultiRateLimiter(
    max_requests=100,  # Per model
    time_window=60,    # Per 60 seconds
    global_max=200     # Global limit across all models
)
```

### Customize Access Control

Edit `data/users.json` to manage users:

```json
{
  "admin": {
    "username": "admin",
    "role": "admin",
    "email": "admin@example.com",
    "permissions": ["run_attacks", "create_attacks", ...]
  },
  "analyst": {
    "username": "analyst",
    "role": "analyst",
    "email": "analyst@example.com",
    "permissions": ["view_results", "export_data"]
  }
}
```

### Customize PDF Reports

Modify the Jinja2 template in `exports/pdf_reporter.py` to customize report layout and styling.

---

## Troubleshooting

### PDF Generation Issues

If PDF generation fails, the system will automatically generate an HTML report instead. To enable PDF:

1. Install system dependencies for WeasyPrint (varies by OS)
2. Ensure `weasyprint` is installed: `pip install weasyprint`

### Rate Limiting Too Restrictive

Adjust rate limits in your code:

```python
from security import get_model_rate_limiter

limiter = get_model_rate_limiter(
    max_requests=100,  # Increase from default 60
    time_window=60
)
```

### Dashboard Performance

For large datasets, consider:
1. Using date filters to limit displayed data
2. Running the dashboard with `--server.maxMessageSize=500` to increase message size limit
3. Paginating results in the Attack Explorer

---

## Security Best Practices

1. **Enable Audit Logging**: Always enable audit logging in production
2. **Verify Log Integrity**: Regularly verify audit log integrity
3. **Scan for Sensitive Data**: Run PII and credential scans on all results before sharing
4. **Use Access Control**: Implement role-based access control for multi-user environments
5. **Rate Limiting**: Enable rate limiting to prevent API abuse and cost overruns
6. **Export to SARIF**: Integrate with security tools using SARIF export
7. **Regular Reports**: Generate PDF reports for stakeholders and compliance

---

## License

This enhanced framework maintains the same license as the original RedTeam project.

## Support

For issues or questions:
1. Check this documentation
2. Review code comments in the relevant modules
3. Open an issue on the project repository
