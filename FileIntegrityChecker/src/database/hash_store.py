import sqlite3
import json
import os
from typing import Optional, Dict
from ..utils.logger import Logger

class HashStore:
    """Enhanced hash storage with signature verification"""
    
    def __init__(self, db_path: str = "data/file_hashes.db"):
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self.db_path = db_path
        self.logger = Logger()
        self._init_db()

    # Check
    def _init_db(self):
        """Initialize database with enhanced schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_hashes (
                        file_path TEXT PRIMARY KEY,
                        hash_value TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        verification_count INTEGER DEFAULT 0
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS hash_history (
                        file_path TEXT,
                        hash_value TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (file_path) REFERENCES file_hashes(file_path)
                    )
                ''')
                conn.commit()
        except Exception as e:
            self.logger.error(f"Database initialization error: {str(e)}")
            raise
    
    def store_hash(self, file_path: str, hash_data: Dict) -> bool:
        """Store or update file hash with signature"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Store current hash in history
                cursor.execute('''
                    INSERT INTO hash_history (file_path, hash_value, signature)
                    SELECT file_path, hash_value, signature
                    FROM file_hashes
                    WHERE file_path = ?
                ''', (file_path,))
                
                # Update current hash
                cursor.execute('''
                    INSERT OR REPLACE INTO file_hashes 
                    (file_path, hash_value, signature, verification_count)
                    VALUES (?, ?, ?, 0)
                ''', (file_path, hash_data['hash'], hash_data['signature']))
                
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Error storing hash: {str(e)}")
            return False
    
    def get_hash(self, file_path: str) -> Optional[Dict]:
        """Retrieve hash and signature for a file"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT hash_value, signature 
                    FROM file_hashes 
                    WHERE file_path = ?
                ''', (file_path,))
                
                result = cursor.fetchone()
                if result:
                    return {
                        'hash': result[0],
                        'signature': result[1]
                    }
                return None
        except Exception as e:
            self.logger.error(f"Error retrieving hash: {str(e)}")
            return None