import os
import sys
import yaml
import argparse
from typing import Dict, Optional
from src.core.monitor import FileMonitor
from src.crypto.signatures import SignatureManager
from src.utils.logger import Logger

def load_config(config_path: str = "config/config.yaml") -> Dict:
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        # Validate required configuration fields
        required_fields = ['monitoring', 'crypto', 'database', 'logging']
        missing_fields = [field for field in required_fields if field not in config]
        
        if missing_fields:
            raise ValueError(f"Missing required configuration fields: {missing_fields}")
            
        return config
    except Exception as e:
        raise ValueError(f"Error loading configuration: {str(e)}")

def setup_environment(config: Dict) -> None:
    """Setup necessary directories and files"""
    directories = [
        config['monitoring']['directory'],  # Monitored directory
        os.path.dirname(config['database']['path']),  # Database directory
        'keys',  # Cryptographic keys
        'logs'   # Log files
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            raise RuntimeError(f"Error creating directory {directory}: {str(e)}")

def initialize_crypto(config: Dict) -> SignatureManager:
    """Initialize cryptographic components"""
    try:
        signature_manager = SignatureManager(key_size=config['crypto']['key_size'])
        
        private_key_path = "./keys/private.pem"
        public_key_path = "./keys/public.pem"
        
        # Generate new keys if they don't exist
        if not (os.path.exists(private_key_path) and 
                os.path.exists(public_key_path)):
            signature_manager.generate_keys()
            signature_manager.save_keys(private_key_path, public_key_path)
            
        return signature_manager
    except Exception as e:
        raise RuntimeError(f"Error initializing cryptographic components: {str(e)}")

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor with cryptographic validation"
    )
    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify integrity of all monitored files"
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Create new baseline hashes"
    )
    return parser.parse_args()

def main() -> None:
    """Main entry point"""
    logger = Logger()
    
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Load configuration
        config = load_config(args.config)
        
        # Setup environment
        setup_environment(config)
        
        # Initialize cryptographic components
        signature_manager = initialize_crypto(config)
        
        # Create file monitor
        monitor = FileMonitor(
            config['monitoring']['directory'],
            chunk_size=config['monitoring'].get('chunk_size', 8192)
        )
        
        # Handle command line options
        if args.verify:
            logger.info("Verifying file integrity...")
            results = monitor.verify_all_files()
            
            # Report verification results
            total = len(results)
            passed = sum(1 for result in results.values() if result)
            logger.info(f"Verification complete: {passed}/{total} files passed")
            
            # Log failed verifications
            for file_path, passed in results.items():
                if not passed:
                    logger.warning(f"Verification failed: {file_path}")
                    
            return
            
        if args.baseline:
            logger.info("Creating new baseline hashes...")
            monitor.initialize_baseline()
            return
        
        # Normal monitoring mode
        logger.info("Initializing file monitoring...")
        monitor.initialize_baseline()
        
        logger.info("Starting file monitoring...")
        monitor.start_monitoring()
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()