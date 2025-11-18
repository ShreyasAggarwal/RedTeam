"""
Setup script for RedTeam Enhanced Features
Run this script to verify your installation and set up initial configuration.
"""

import os
import sys
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    print("Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print(f"  [FAIL] Python {version.major}.{version.minor} is not supported.")
        print(f"  Please upgrade to Python 3.7 or higher.")
        return False
    print(f"  [OK] Python {version.major}.{version.minor}.{version.micro}")
    return True

def check_dependencies():
    """Check if required dependencies are installed."""
    print("\nChecking dependencies...")

    required = [
        'streamlit', 'requests', 'pytest', 'langchain',
        'langchain_openai', 'langchain_google_genai',
        'plotly', 'pandas', 'jinja2'
    ]

    optional = ['weasyprint', 'presidio_analyzer', 'spacy']

    missing_required = []
    missing_optional = []

    for package in required:
        try:
            __import__(package)
            print(f"  [OK] {package}")
        except ImportError:
            print(f"  [MISSING] {package}")
            missing_required.append(package)

    print("\nChecking optional dependencies...")
    for package in optional:
        try:
            __import__(package)
            print(f"  [OK] {package}")
        except ImportError:
            print(f"  [OPTIONAL] {package} (not required)")
            missing_optional.append(package)

    return missing_required, missing_optional

def create_directories():
    """Create necessary directories."""
    print("\nCreating directories...")
    directories = ['data', 'exports', 'security', 'ui']

    for directory in directories:
        path = Path(directory)
        if path.exists():
            print(f"  [EXISTS] {directory}/")
        else:
            path.mkdir(parents=True, exist_ok=True)
            print(f"  [CREATED] {directory}/")

def check_data_files():
    """Check if data files exist."""
    print("\nChecking data files...")
    files = {
        'data/sample_attack_cases.json': 'Attack cases',
        'data/results.jsonl': 'Results (will be created on first run)',
        'data/score_report.json': 'Scores (will be created by scorer)',
    }

    for file_path, description in files.items():
        path = Path(file_path)
        if path.exists():
            print(f"  [OK] {file_path} - {description}")
        else:
            print(f"  [MISSING] {file_path} - {description}")

def create_default_users():
    """Create default users file."""
    print("\nSetting up access control...")
    users_file = Path('data/users.json')

    if users_file.exists():
        print(f"  [EXISTS] Users file already exists")
        return

    # Import and create default admin
    try:
        from security import get_access_control
        ac = get_access_control()
        print(f"  [CREATED] Default admin user created")
        print(f"  [INFO] Username: admin")
        print(f"  [INFO] Role: ADMIN")
    except Exception as e:
        print(f"  [WARN] Could not create default users: {e}")

def print_next_steps(missing_required):
    """Print next steps for the user."""
    print("\n" + "="*60)
    print("Setup Summary")
    print("="*60)

    if missing_required:
        print("\n❌ Required dependencies missing!")
        print("\nPlease install missing dependencies:")
        print(f"  pip install {' '.join(missing_required)}")
        print("\nOr install all dependencies:")
        print("  pip install -r requirements.txt")
    else:
        print("\n✅ All required dependencies installed!")

    print("\n" + "="*60)
    print("Next Steps")
    print("="*60)

    print("\n1. Generate attack cases (if not already done):")
    print("   python -m attacks.generator")

    print("\n2. Run attacks:")
    print("   python -m runner.cli --model=mock --attacks-file=data/sample_attack_cases.json")

    print("\n3. Score results:")
    print("   python -m eval.scorer --results=data/results.jsonl --out=data/score_report.json")

    print("\n4. Launch enhanced dashboard:")
    print("   streamlit run ui/enhanced_app.py")

    print("\n5. Test security features:")
    print("   python test_new_features.py")

    print("\n" + "="*60)
    print("Documentation")
    print("="*60)
    print("\n- Quick Start: QUICKSTART.md")
    print("- Full Documentation: FEATURES.md")
    print("- Implementation Details: IMPLEMENTATION_SUMMARY.md")

    print("\n" + "="*60)
    print("Enjoy the enhanced RedTeam framework! 🎯")
    print("="*60)

def main():
    """Main setup function."""
    print("="*60)
    print("RedTeam Enhanced Features - Setup")
    print("="*60)

    # Check Python version
    if not check_python_version():
        return

    # Check dependencies
    missing_required, missing_optional = check_dependencies()

    # Create directories
    create_directories()

    # Check data files
    check_data_files()

    # Create default users
    if not missing_required:
        create_default_users()

    # Print next steps
    print_next_steps(missing_required)

if __name__ == "__main__":
    main()
