# Quick Start Guide - Enhanced RedTeam Features

This guide will help you quickly set up and use the new advanced features.

## Installation

### 1. Install Dependencies

```bash
# Navigate to the project directory
cd RedTeam

# Install all required packages
pip install -r requirements.txt
```

**Note:** If you encounter issues with `weasyprint` or `presidio`, you can skip them as they're optional:
```bash
pip install streamlit requests pytest langchain-openai langchain-google-genai langchain langchain-community plotly pandas jinja2 python-dateutil pillow
```

### 2. Verify Installation

Run the test script to verify everything is working:

```bash
python test_new_features.py
```

Expected output should show `[OK]` for most tests.

## Using the Enhanced Dashboard

### Launch the Dashboard

```bash
streamlit run ui/enhanced_app.py
```

Open your browser to `http://localhost:8501`

### Dashboard Features

#### 1. Overview Page
- View overall statistics (total attacks, vulnerabilities, rates)
- See severity distribution pie chart
- Check vulnerability types distribution
- View recent critical vulnerabilities

#### 2. Attack Explorer
**Filters:**
- Severity Level: Filter by Critical/High/Medium/Low
- Vulnerability Status: Show only Vulnerable or Safe attacks
- Tags: Filter by attack type (jailbreak, instruction, etc.)
- Date Range: Filter by date range

**Features:**
- Sortable table of all attacks
- Select any attack to see full details
- View prompt, response, and analysis
- See evidence and notes

#### 3. Time Trends
- View vulnerability rate over time
- Track average severity trends
- Monitor attack volume
- Identify patterns in your security testing

#### 4. Model Comparison
- Compare multiple models side-by-side
- View vulnerability rates per model
- Compare average severity scores
- Identify which models are most vulnerable

#### 5. Heatmap Analysis
- Visualize attack type vs model vulnerability
- Identify high-risk combinations
- Color-coded matrix for quick insights

#### 6. Export & Reports
- Export to CSV, JSON, or SARIF
- Generate PDF executive summaries
- Replay historical attacks
- Download reports for sharing

## Using Security Features

### PII Detection

```python
from security import PIIDetector

detector = PIIDetector()

# Check for PII
text = "Contact John at john@example.com or call 555-1234"
if detector.has_pii(text):
    print("PII detected!")

    # Get details
    findings = detector.detect(text)
    print(findings)  # {'EMAIL': ['john@example.com'], 'PHONE_US': ['555-1234']}

    # Redact PII
    redacted, counts = detector.redact(text)
    print(redacted)  # "Contact John at [REDACTED_EMAIL] or call [REDACTED_PHONE_US]"
```

### Credential Scanning

```python
from security import CredentialScanner

scanner = CredentialScanner()

# Scan for credentials
text = "My API key is sk-abc123def456"
risk = scanner.assess_risk(text)

if risk['risk_level'] in ['HIGH', 'CRITICAL']:
    print(f"⚠️ {risk['risk_level']} risk detected!")
    print(f"Found {risk['total_credentials']} credentials")

    # Redact credentials
    safe_text = scanner.redact_credentials(text)
```

### Audit Logging

```python
from security import get_audit_logger

logger = get_audit_logger()

# Log an attack execution
logger.log_attack_execution(
    user="analyst_alice",
    attack_id="jb-001",
    model="gpt-4o-mini",
    success=True,
    details={"severity": 0.85}
)

# Verify log integrity
verification = logger.verify_log_integrity()
if verification['valid']:
    print(f"✓ Audit log is valid ({verification['total_events']} events)")
else:
    print(f"✗ Log integrity compromised: {verification['message']}")
```

### Rate Limiting

```python
from models.client import ModelClient

# Create client with rate limiting
client = ModelClient(
    provider="openai",
    api_key="your-api-key",
    enable_rate_limiting=True,  # Enable rate limiting
    enable_audit_logging=True,  # Enable audit logging
    user="analyst_alice"
)

# Rate limiting is automatic
response = client.query("attack-001", "Your prompt here")
```

### Access Control

```python
from security import get_access_control, Role, Permission

ac = get_access_control()

# Add a new user
ac.add_user("analyst_bob", Role.ANALYST, "bob@example.com")

# Check permissions
if ac.check_permission("analyst_bob", Permission.EXPORT_DATA):
    print("User can export data")
else:
    print("User cannot export data")

# List all users
users = ac.list_users()
for user in users:
    print(f"{user['username']} - {user['role']}")
```

## Export & Reporting

### Export to CSV

```python
from exports import export_results
import json

# Load your data
with open('data/results.jsonl', 'r') as f:
    results = [json.loads(line) for line in f if line.strip()]

# Export
csv_path = export_results(results, format='csv', output_dir='exports')
print(f"Exported to {csv_path}")
```

### Export to SARIF (for GitHub)

```python
# Load scores
with open('data/score_report.json', 'r') as f:
    scores = json.load(f)['scores']

# Export to SARIF
sarif_path = export_results(scores, format='sarif', output_dir='exports')
print(f"SARIF report: {sarif_path}")

# Upload to GitHub Advanced Security
# GitHub will automatically parse and display vulnerabilities
```

### Generate PDF Report

```python
from exports.pdf_reporter import generate_pdf_report

# Generate executive summary
report_path = generate_pdf_report(
    results=results,
    scores=scores,
    metadata={
        "project": "Q1 2025 Security Assessment",
        "models_tested": ["gpt-4o-mini", "gemini-2.5-flash"],
        "test_date": "2025-01-17"
    },
    output_dir="reports"
)

print(f"Report generated: {report_path}")
```

## Running a Complete Security Assessment

Here's a complete workflow example:

### Step 1: Generate Attacks
```bash
python -m attacks.generator
```

### Step 2: Run Attacks with Security Features

Create a script `run_secure_assessment.py`:
```python
from models.client import ModelClient
from runner.runner import Runner
import json

# Load attacks
with open('data/sample_attack_cases.json', 'r') as f:
    attacks = json.load(f)

# Create secure client
client = ModelClient(
    provider="openai",  # or "gemini"
    api_key="your-api-key",
    enable_rate_limiting=True,
    enable_audit_logging=True,
    user="security_team"
)

# Run attacks
runner = Runner(client)
runner.run_all(
    attacks,
    output_file='data/results.jsonl',
    workers=4
)

print("✓ Attacks completed with audit logging")
```

Run it:
```bash
python run_secure_assessment.py
```

### Step 3: Score Results
```bash
python -m eval.scorer --results=data/results.jsonl --out=data/score_report.json
```

### Step 4: Scan for Sensitive Data

Create `scan_results.py`:
```python
from security import DataSanitizer
import json

sanitizer = DataSanitizer()

with open('data/results.jsonl', 'r') as f:
    results = [json.loads(line) for line in f if line.strip()]

print("Scanning for sensitive data...")
for result in results:
    scan = sanitizer.scan_only(result.get('response', ''))

    if scan['has_pii'] or scan['has_credentials']:
        print(f"\n⚠️  {result['attack_id']}:")
        if scan['has_pii']:
            print(f"   PII: {scan['pii_summary']}")
        if scan['has_credentials']:
            print(f"   Credentials: {scan['credential_risk']['risk_level']} risk")
```

Run it:
```bash
python scan_results.py
```

### Step 5: View Dashboard & Export
```bash
streamlit run ui/enhanced_app.py
```

1. Navigate to different pages to explore results
2. Use filters to focus on specific vulnerabilities
3. Export to CSV/JSON/SARIF as needed
4. Generate PDF reports for stakeholders

### Step 6: Verify Audit Trail
```python
from security import get_audit_logger

logger = get_audit_logger()

# Verify integrity
verification = logger.verify_log_integrity()
print(f"Audit log valid: {verification['valid']}")

# Get statistics
stats = logger.get_statistics()
print(f"Total events: {stats['total_events']}")
print(f"Event types: {stats['event_types']}")
```

## Tips & Best Practices

### 1. Performance Optimization
- Use date filters in the dashboard for large datasets
- Run attacks with appropriate worker count (4-8 recommended)
- Enable rate limiting to prevent API quota issues

### 2. Security
- Always scan results for PII before sharing
- Enable audit logging for compliance
- Use access control in multi-user environments
- Regularly verify audit log integrity

### 3. Reporting
- Generate PDF reports for executives (simplified view)
- Use CSV exports for detailed analysis in Excel/Pandas
- Use SARIF exports for CI/CD integration

### 4. Model Comparison
- Run the same attacks against multiple models
- Use the Model Comparison view to identify weakest models
- Use the Heatmap to find attack-model vulnerabilities

## Common Issues & Solutions

### Issue: Import errors
**Solution:** Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### Issue: PDF generation fails
**Solution:** WeasyPrint can be tricky to install. If it fails, the system will automatically generate HTML reports instead. This is perfectly fine for most use cases.

### Issue: Dashboard is slow
**Solution:** Use filters to reduce the amount of data displayed. Also consider using the date range filter.

### Issue: Rate limit exceeded
**Solution:** Adjust rate limits or use fewer workers:
```python
from security import get_model_rate_limiter

limiter = get_model_rate_limiter(max_requests=100, time_window=60)
```

## Next Steps

1. ✅ Review the full [FEATURES.md](FEATURES.md) documentation
2. ✅ Explore each dashboard page
3. ✅ Try exporting to different formats
4. ✅ Set up access control for your team
5. ✅ Integrate SARIF exports with your CI/CD pipeline

## Support

For detailed documentation, see:
- [FEATURES.md](FEATURES.md) - Complete feature documentation
- [README.md](README.md) - Project overview
- Individual module docstrings for API details

Enjoy the enhanced RedTeam framework! 🎯
