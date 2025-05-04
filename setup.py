import os
import sys
import subprocess
from setuptools import setup, find_packages

# Check if we're installing in development mode
dev_mode = 'develop' in sys.argv or 'dev' in sys.argv

def read_requirements():
    """Read the requirements file."""
    with open('requirements.txt') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

def install_playwright_browsers():
    """Install Playwright browser binaries."""
    print("\n\n=== Installing Playwright browser binaries ===")
    try:
        subprocess.check_call([sys.executable, '-m', 'playwright', 'install', 'chromium'])
        print("✅ Playwright browser binaries installed successfully!")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Playwright browser binaries: {e}")
        print("You may need to run 'python -m playwright install chromium' manually.")
    except Exception as e:
        print(f"❌ Unexpected error installing Playwright browser binaries: {e}")
        print("You may need to run 'python -m playwright install chromium' manually.")

# Main setup configuration
setup(
    name="secscan",
    version="1.0.0",
    description="Web Vulnerability Scanner with JavaScript Rendering Support",
    author="SecScan Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=read_requirements(),
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)

# Install Playwright browsers after package installation
if 'install' in sys.argv or 'develop' in sys.argv:
    install_playwright_browsers()

print("\n=== SecScan installation completed ===")
print("To start the application, run: python src/server/server.py")
