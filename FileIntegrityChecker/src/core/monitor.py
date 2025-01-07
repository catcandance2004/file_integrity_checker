import os
import time
from typing import Dict, Set, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ..core.hasher import FileHasher
from ..database.hash_store import HashStore
from ..utils.logger import Logger

class FileChangeHandler(FileSystemEventHandler):
    """Handles file system events with cryptographic validation"""
    
    def __init__(self, hasher: FileHasher, hash_store: HashStore):
        self.hasher = hasher
        self.hash_store = hash_store
        self.logger = Logger()
        self._processing = set()  # Track files being processed to prevent duplicates
    
    def _process_file_change(self, file_path: str, event_type: str) -> None:
        """Common file processing logic with duplicate prevention"""
        if file_path in self._processing:
            return
            
        try:
            self._processing.add(file_path)
            new_hash = self.hasher.hash_file(file_path)
            
            if new_hash:
                old_hash = self.hash_store.get_hash(file_path)
                if old_hash and event_type == 'modified':
                    if old_hash['hash'] != new_hash['hash']:
                        self.logger.warning(
                            f"File modified: {file_path}\n"
                            f"Old hash: {old_hash['hash']}\n"
                            f"New hash: {new_hash['hash']}"
                        )
                
                # Store new hash
                self.hash_store.store_hash(file_path, new_hash)
                
                if event_type == 'created':
                    self.logger.info(f"New file created and hashed: {file_path}")
                    
        except Exception as e:
            self.logger.error(f"Error processing {event_type} event for {file_path}: {str(e)}")
        finally:
            self._processing.remove(file_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process_file_change(event.src_path, 'modified')

    def on_created(self, event):
        if not event.is_directory:
            self._process_file_change(event.src_path, 'created')

    def on_deleted(self, event):
        if not event.is_directory:
            try:
                # Log deletion event
                self.logger.info(f"File deleted: {event.src_path}")
                # Could implement additional cleanup here if needed
            except Exception as e:
                self.logger.error(f"Error processing deletion of {event.src_path}: {str(e)}")

    def on_moved(self, event):
        if not event.is_directory:
            try:
                self.logger.info(f"File moved/renamed: {event.src_path} -> {event.dest_path}")
                # Process the new file location
                self._process_file_change(event.dest_path, 'created')
            except Exception as e:
                self.logger.error(f"Error processing move event: {str(e)}")

class FileMonitor:
    """Main file monitoring class with cryptographic integrity checks"""
    
    def __init__(self, directory: str, chunk_size: int = 8192):
        self.directory = os.path.abspath(directory)
        self.chunk_size = chunk_size
        self.hasher = FileHasher()
        self.hash_store = HashStore()
        self.observer = Observer()
        self.logger = Logger()
        self._running = False
        
        # Create monitored directory if it doesn't exist
        os.makedirs(self.directory, exist_ok=True)
    
    def initialize_baseline(self) -> None:
        """Create baseline hashes for all files"""
        self.logger.info(f"Creating baseline hashes for directory: {self.directory}")
        file_count = 0
        error_count = 0
        
        try:
            for root, _, files in os.walk(self.directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_hash = self.hasher.hash_file(file_path)
                        if file_hash:
                            self.hash_store.store_hash(file_path, file_hash)
                            file_count += 1
                    except Exception as e:
                        self.logger.error(f"Error processing {file_path}: {str(e)}")
                        error_count += 1
                        
            self.logger.info(
                f"Baseline creation completed. Processed {file_count} files "
                f"with {error_count} errors."
            )
        except Exception as e:
            self.logger.error(f"Error during baseline creation: {str(e)}")
            raise
    
    def start_monitoring(self) -> None:
        """Start monitoring directory for changes"""
        if self._running:
            self.logger.warning("Monitoring is already running")
            return
            
        try:
            handler = FileChangeHandler(self.hasher, self.hash_store)
            self.observer.schedule(handler, self.directory, recursive=True)
            self.observer.start()
            self._running = True
            
            self.logger.info(f"Started monitoring directory: {self.directory}")
            
            try:
                while self._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop_monitoring()
                
        except Exception as e:
            self._running = False
            self.logger.error(f"Error during monitoring: {str(e)}")
            raise
    
    def stop_monitoring(self) -> None:
        """Stop monitoring directory"""
        if not self._running:
            return
            
        try:
            self.observer.stop()
            self.observer.join()
            self._running = False
            self.logger.info("Monitoring stopped")
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {str(e)}")
            raise
    
    def verify_all_files(self) -> Dict[str, bool]:
        """Verify integrity of all monitored files"""
        results = {}
        
        try:
            for root, _, files in os.walk(self.directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    stored_hash = self.hash_store.get_hash(file_path)
                    
                    if stored_hash:
                        results[file_path] = self.hasher.verify_file(
                            file_path, stored_hash
                        )
                    else:
                        self.logger.warning(f"No stored hash for {file_path}")
                        results[file_path] = False
                        
            return results
        except Exception as e:
            self.logger.error(f"Error during verification: {str(e)}")
            raise