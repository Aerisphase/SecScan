import logging
from pathlib import Path
from data_collector import DataCollector
from data_preprocessor import DataPreprocessor
from model_trainer import ModelTrainer
from config import (
    LOGGING_CONFIG,
    MODELS_DIR,
    TRAINING_DATA_DIR
)

# Configure logging
logging.basicConfig(**LOGGING_CONFIG)
logger = logging.getLogger(__name__)

class TrainingPipeline:
    def __init__(self):
        self.data_collector = DataCollector()
        self.data_preprocessor = DataPreprocessor()
        self.model_trainer = ModelTrainer()
        
    def run(self):
        """Run the complete training pipeline"""
        try:
            # Collect data
            logger.info("Starting data collection...")
            data = self.data_collector.collect_all()
            
            # Preprocess data
            logger.info("Preprocessing data...")
            processed_data = self.data_preprocessor.preprocess(data)
            
            # Train models
            logger.info("Training models...")
            results = self.model_trainer.train_all_models(processed_data)
            
            # Log results
            for target, target_results in results.items():
                logger.info(f"\nResults for {target}:")
                for model_name, (model, metrics) in target_results.items():
                    logger.info(f"{model_name}:")
                    for metric, value in metrics.items():
                        logger.info(f"  {metric}: {value}")
                        
            return results
            
        except Exception as e:
            logger.error(f"Training pipeline failed: {e}")
            raise

def main():
    """Main entry point for training"""
    try:
        # Ensure directories exist
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        TRAINING_DATA_DIR.mkdir(parents=True, exist_ok=True)
        
        # Run pipeline
        pipeline = TrainingPipeline()
        results = pipeline.run()
        
        logger.info("Training completed successfully")
        return results
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise

if __name__ == "__main__":
    main() 