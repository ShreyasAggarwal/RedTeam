"""
Test script for new security and visualization features.
Run this to verify all modules are working correctly.
"""

import sys
from pathlib import Path

def test_security_modules():
    """Test security module imports and basic functionality."""
    print("Testing Security Modules...")

    try:
        from security import PIIDetector
        detector = PIIDetector()
        test_text = "Contact me at john.doe@example.com or call 555-123-4567"
        findings = detector.detect(test_text)
        print(f"  [OK] PII Detection: Found {len(findings)} PII types")
    except Exception as e:
        print(f"  [FAIL] PII Detection failed: {e}")

    try:
        from security import CredentialScanner
        scanner = CredentialScanner()
        test_text = "sk-ant-api03-abc123def456"
        findings = scanner.scan(test_text)
        print(f"  [OK] Credential Scanning: Working")
    except Exception as e:
        print(f"  [FAIL] Credential Scanning failed: {e}")

    try:
        from security import DataSanitizer
        sanitizer = DataSanitizer()
        result = sanitizer.sanitize("Test text")
        print(f"  [OK] Data Sanitization: Working")
    except Exception as e:
        print(f"  [FAIL] Data Sanitization failed: {e}")

    try:
        from security import get_audit_logger
        logger = get_audit_logger()
        logger.log("TEST_EVENT", "test_user", "Testing audit logging")
        print(f"  [OK] Audit Logging: Working")
    except Exception as e:
        print(f"  [FAIL] Audit Logging failed: {e}")

    try:
        from security import get_model_rate_limiter
        limiter = get_model_rate_limiter()
        allowed = limiter.allow_request("test_model")
        print(f"  [OK] Rate Limiting: Working (request allowed: {allowed})")
    except Exception as e:
        print(f"  [FAIL] Rate Limiting failed: {e}")

    try:
        from security import get_access_control, Role
        ac = get_access_control()
        users = ac.list_users()
        print(f"  [OK] Access Control: Working ({len(users)} users)")
    except Exception as e:
        print(f"  [FAIL] Access Control failed: {e}")

    print()

def test_export_modules():
    """Test export module imports and basic functionality."""
    print("Testing Export Modules...")

    try:
        from exports import CSVExporter, JSONExporter, SARIFExporter
        print(f"  [OK] Exporters: All imported successfully")
    except Exception as e:
        print(f"  [FAIL] Exporters failed: {e}")

    try:
        from exports import export_results
        # Test with empty data
        test_data = [{"test": "data"}]
        path = export_results(test_data, format='json', filename='test_export.json')
        print(f"  [OK] Export Function: Working")
        # Clean up
        Path(path).unlink(missing_ok=True)
    except Exception as e:
        print(f"  [FAIL] Export Function failed: {e}")

    try:
        from exports import PDFReporter, generate_pdf_report
        print(f"  [OK] PDF Reporter: Imported successfully")
    except Exception as e:
        print(f"  [FAIL] PDF Reporter failed: {e}")

    print()

def test_model_client():
    """Test enhanced model client."""
    print("Testing Enhanced Model Client...")

    try:
        from models.client import ModelClient
        client = ModelClient(
            provider="mock",
            enable_rate_limiting=True,
            enable_audit_logging=True,
            user="test_user"
        )
        print(f"  [OK] Model Client: Initialized with security features")

        # Test query
        result = client.query("test-001", "Test prompt")
        print(f"  [OK] Model Client: Query successful")
    except Exception as e:
        print(f"  [FAIL] Model Client failed: {e}")

    print()

def test_dependencies():
    """Test that all required dependencies are available."""
    print("Testing Dependencies...")

    dependencies = [
        ('plotly', 'Plotly'),
        ('pandas', 'Pandas'),
        ('jinja2', 'Jinja2'),
        ('streamlit', 'Streamlit'),
    ]

    for module, name in dependencies:
        try:
            __import__(module)
            print(f"  [OK] {name}: Installed")
        except ImportError:
            print(f"  [WARN] {name}: Not installed (required)")

    # Check optional dependencies
    try:
        import weasyprint
        print(f"  [OK] WeasyPrint: Installed (PDF generation available)")
    except ImportError:
        print(f"  [WARN] WeasyPrint: Not installed (PDF generation will use HTML fallback)")

    print()

def main():
    """Run all tests."""
    print("=" * 60)
    print("RedTeam Enhanced Features Test Suite")
    print("=" * 60)
    print()

    test_dependencies()
    test_security_modules()
    test_export_modules()
    test_model_client()

    print("=" * 60)
    print("Test suite completed!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("1. Run: streamlit run ui/enhanced_app.py")
    print("2. Navigate to http://localhost:8501")
    print("3. Explore the enhanced dashboard features")
    print()

if __name__ == "__main__":
    main()
