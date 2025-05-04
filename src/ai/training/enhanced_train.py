#!/usr/bin/env python3
"""
Enhanced training pipeline for SecScan AI components
This script orchestrates the complete training process:
1. Data collection from multiple sources
2. Data preprocessing with advanced NLP techniques
3. Model training with hyperparameter optimization
4. Model evaluation and selection
"""

import argparse
import logging
import logging.config
import os
import sys
import time
from pathlib import Path

# Add project root and site-packages to path to ensure dependencies are found
project_root = str(Path(__file__).parent.parent.parent.parent)
sys.path.append(project_root)

# Add user site-packages to path (where pandas and other packages are installed)
import site
user_site_packages = site.getusersitepackages()
if user_site_packages not in sys.path:
    sys.path.append(user_site_packages)

# Try to import required modules, with helpful error messages
try:
    import pandas as pd
except ImportError:
    print("Error: pandas module not found. Please install it with 'pip install pandas'")
    print("Python path:", sys.path)
    sys.exit(1)

try:
    import numpy as np
except ImportError:
    print("Error: numpy module not found. Please install it with 'pip install numpy'")
    sys.exit(1)

# Import project modules
try:
    from src.ai.training.enhanced_data_collector import EnhancedDataCollector
    from src.ai.training.enhanced_data_preprocessor import EnhancedDataPreprocessor
    from src.ai.training.enhanced_model_trainer import EnhancedModelTrainer
    from src.ai.training.config import LOGGING_CONFIG, TRAINING_DATA_DIR, MODELS_DIR
except ImportError as e:
    print(f"Error importing project modules: {e}")
    print("Make sure you're running this script from the project root directory")
    sys.exit(1)

# Configure logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Enhanced SecScan AI Training Pipeline')
    parser.add_argument('--skip-collection', action='store_true', help='Skip data collection step')
    parser.add_argument('--skip-preprocessing', action='store_true', help='Skip data preprocessing step')
    parser.add_argument('--skip-training', action='store_true', help='Skip model training step')
    parser.add_argument('--data-file', type=str, help='Path to preprocessed data file')
    parser.add_argument('--output-dir', type=str, help='Directory to save models')
    return parser.parse_args()

def main():
    """Main training pipeline"""
    start_time = time.time()
    args = parse_args()
    
    logger.info("Starting enhanced SecScan AI training pipeline")
    
    # Set output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        models_dir = output_dir
    else:
        models_dir = Path(MODELS_DIR)
        models_dir.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Data Collection
    if not args.skip_collection:
        logger.info("Step 1: Enhanced Data Collection")
        collector = EnhancedDataCollector()
        data = collector.collect_all()
        logger.info("Data collection completed")
    else:
        logger.info("Skipping data collection step")
    
    # Step 2: Data Preprocessing
    if not args.skip_preprocessing:
        logger.info("Step 2: Enhanced Data Preprocessing")
        preprocessor = EnhancedDataPreprocessor()
        
        if args.skip_collection:
            # Load collected data
            data_file = TRAINING_DATA_DIR / "enhanced_combined_data.json"
            if not data_file.exists():
                logger.error(f"Data file not found: {data_file}")
                return
                
            import json
            with open(data_file, 'r') as f:
                data = json.load(f)
        
        preprocessed_data = preprocessor.preprocess(data)
        logger.info("Data preprocessing completed")
    else:
        logger.info("Skipping data preprocessing step")
    
    # Step 3: Model Training
    if not args.skip_training:
        logger.info("Step 3: Enhanced Model Training")
        trainer = EnhancedModelTrainer()
        
        if args.data_file:
            data_file = Path(args.data_file)
            if not data_file.exists():
                logger.error(f"Data file not found: {data_file}")
                return
        else:
            data_file = None
            
        metadata = trainer.train(data_file)
        
        # Step 4: Model Evaluation
        logger.info("Step 4: Model Evaluation")
        evaluation = trainer.evaluate()
        
        logger.info(f"Best model for vulnerability type classification: {metadata['best_type_model']}")
        logger.info(f"Best model for severity classification: {metadata['best_severity_model']}")
        logger.info(f"Test accuracy: {evaluation.get('type_accuracy', 'N/A')}")
        logger.info(f"Test F1 score: {evaluation.get('type_f1', 'N/A')}")
    else:
        logger.info("Skipping model training step")
    
    total_time = time.time() - start_time
    logger.info(f"Enhanced training pipeline completed in {total_time:.2f} seconds")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Error in training pipeline: {e}", exc_info=True)
        sys.exit(1)
