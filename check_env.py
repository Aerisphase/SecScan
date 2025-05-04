import sys
import os
import site

print("Python executable:", sys.executable)
print("Python version:", sys.version)
print("sys.path:")
for path in sys.path:
    print(f"  - {path}")

print("\nUser site packages:")
print(site.getusersitepackages())

print("\nTrying to import pandas:")
try:
    import pandas as pd
    print(f"Success! Pandas version: {pd.__version__}")
    print(f"Pandas location: {pd.__file__}")
except ImportError as e:
    print(f"Failed to import pandas: {e}")

print("\nEnvironment variables:")
for key, value in os.environ.items():
    if "PATH" in key or "PYTHON" in key:
        print(f"{key}: {value}")
