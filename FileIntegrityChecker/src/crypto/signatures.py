from typing import Tuple, Optional
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

class SignatureManager:
    """Enhanced digital signature management with RSA-PSS"""
    
    def __init__(self, key_size: int = 2048):
        self.key_size = key_size
        self._private_key = None
        self._public_key = None
        self._hash_algorithm = hashes.SHA256()
        # Generate keys immediately upon initialization
        self.generate_keys()
    
    def generate_keys(self) -> None:
        """Generate RSA key pair with specified size"""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
    
    def save_keys(self, private_key_path: str, public_key_path: str) -> None:
        """Save keys to files"""
        if not self._private_key or not self._public_key:
            raise ValueError("Keys not initialized")
        
        os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
        os.makedirs(os.path.dirname(public_key_path), exist_ok=True)
        
        # Save private key
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
    
    def sign(self, data: bytes) -> bytes:
        """Sign data using RSA-PSS with SHA256"""
        if not self._private_key:
            raise ValueError("Private key not initialized")
        
        return self._private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(self._hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self._hash_algorithm
        )
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify RSA-PSS signature"""
        if not self._public_key:
            raise ValueError("Public key not initialized")
            
        try:
            self._public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(self._hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                self._hash_algorithm
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise ValueError(f"Verification error: {str(e)}")
