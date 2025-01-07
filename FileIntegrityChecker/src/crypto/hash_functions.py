from abc import ABC, abstractmethod
import hashlib
from typing import Union, Optional
import hmac
import os

class HashFunction(ABC):
    """Abstract base class for hash functions with HMAC support"""
    
    @abstractmethod
    def compute(self, data: Union[str, bytes], key: Optional[bytes] = None) -> str:
        """Compute hash of data, optionally with HMAC"""
        pass
    
    @abstractmethod
    def verify(self, data: Union[str, bytes], hash_value: str, 
               key: Optional[bytes] = None) -> bool:
        """Verify if hash matches the data"""
        pass

class SHA256Handler(HashFunction):
    """SHA256 implementation with HMAC support"""
    
    def compute(self, data: Union[str, bytes], key: Optional[bytes] = None) -> str:
        if isinstance(data, str):
            data = data.encode()
            
        if key:
            # Use HMAC-SHA256 if key is provided
            h = hmac.new(key, data, hashlib.sha256)
            return h.hexdigest()
        else:
            # Use regular SHA256 otherwise
            return hashlib.sha256(data).hexdigest()
    
    def verify(self, data: Union[str, bytes], hash_value: str,
               key: Optional[bytes] = None) -> bool:
        return self.compute(data, key) == hash_value