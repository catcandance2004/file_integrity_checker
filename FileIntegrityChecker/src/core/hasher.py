import os
import hashlib
from typing import Dict, Optional
from ..crypto.hash_functions import HashFunction, SHA256Handler
from ..crypto.signatures import SignatureManager
from ..utils.logger import Logger

class FileHasher:
    """Enhanced file hasher with cryptographic security"""
    
    def __init__(self, hash_function: Optional[HashFunction] = None,
                 hmac_key: Optional[bytes] = None):
        self.hash_function = hash_function or SHA256Handler()
        self.hmac_key = hmac_key or os.urandom(32)
        self.signature_manager = SignatureManager()
        self.logger = Logger()
    
    def hash_file(self, file_path: str, chunk_size: int = 8192) -> Optional[Dict]:
        """
        Compute authenticated hash of file in chunks with HMAC
        """
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return None
                
            hasher = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    
            # Compute HMAC of the file hash
            file_hash = hasher.digest()
            hmac_hash = self.hash_function.compute(file_hash, self.hmac_key)
            
            # Sign the HMAC hash
            signature = self.signature_manager.sign(hmac_hash.encode())
            
            return {
                'hash': hmac_hash,
                'signature': signature.hex()
            }
                
        except Exception as e:
            self.logger.error(f"Error hashing file {file_path}: {str(e)}")
            return None
    
    def verify_file(self, file_path: str, stored_hash: Dict) -> bool:
        """
        Verify file integrity using stored hash and signature
        """
        try:
            current_hash = self.hash_file(file_path)
            if not current_hash:
                return False
            
            # Verify signature first
            signature_valid = self.signature_manager.verify(
                stored_hash['hash'].encode(),
                bytes.fromhex(stored_hash['signature'])
            )
            
            if not signature_valid:
                self.logger.warning(f"Invalid signature for {file_path}")
                return False
            
            # Then verify hash
            return current_hash['hash'] == stored_hash['hash']
            
        except Exception as e:
            self.logger.error(f"Error verifying file {file_path}: {str(e)}")
            return False