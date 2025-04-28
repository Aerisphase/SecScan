import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.parent.parent
DATA_DIR = BASE_DIR / "data"
TRAINING_DATA_DIR = DATA_DIR / "training"
MODELS_DIR = BASE_DIR / "models"
LOGS_DIR = BASE_DIR / "logs"
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"

# Create directories if they don't exist
for directory in [DATA_DIR, TRAINING_DATA_DIR, MODELS_DIR, LOGS_DIR, SAMPLE_DATA_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Data collection paths
WAF_LOG_PATHS = [
    str(SAMPLE_DATA_DIR / "waf" / "modsec_audit.log"),  # Sample WAF logs
    str(SAMPLE_DATA_DIR / "waf" / "nginx_audit.log")    # Sample Nginx logs
]

PEN_TEST_REPORT_PATHS = [
    str(SAMPLE_DATA_DIR / "reports" / "sample_pen_test.json"),
    str(SAMPLE_DATA_DIR / "reports" / "sample_security_assessment.json")
]

# API endpoints
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OWASP_RESOURCES = [
    "https://raw.githubusercontent.com/OWASP/Top10/master/2023/data.json",  # Updated to 2023
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md",
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md"
]

# Training parameters
TRAIN_TEST_SPLIT = 0.8
RANDOM_STATE = 42
CV_FOLDS = 5

# Model parameters
MODEL_PARAMS = {
    'random_forest': {
        'n_estimators': 100,
        'max_depth': None,
        'random_state': RANDOM_STATE
    },
    'svm': {
        'kernel': 'rbf',
        'random_state': RANDOM_STATE
    },
    'logistic_regression': {
        'max_iter': 1000,
        'random_state': RANDOM_STATE
    }
}

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
            'formatter': 'standard',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.FileHandler',
            'level': 'DEBUG',
            'formatter': 'standard',
            'filename': str(LOGS_DIR / 'training.log'),
            'mode': 'a'
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': True
        }
    }
} 