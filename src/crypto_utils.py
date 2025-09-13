"""
Cryptographic utilities for the VPN prototype.
Handles RSA key generation, AES encryption/decryption, and key exchange.
"""

import os
import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


class CryptoManager:
    """Manages cryptographic operations for the VPN prototype."""
    
    def __init__(self):
        """Initialize the crypto manager."""
        self.rsa_key = None
        self.aes_key = None
        self.aes_cipher = None
    
    # ==================== RSA Key Management ====================
    
    def generate_rsa_keys(self, key_size=2048):
        try:
            self.rsa_key = RSA.generate(key_size)
            private_key = self.rsa_key
            public_key = self.rsa_key.publickey()
            return private_key, public_key
        except Exception:
            return None, None
    
    def export_public_key(self):
        """
        Export the public key for transmission.
        
        Returns:
            str: Base64-encoded public key in PEM format
        """
        if not self.rsa_key:
            raise ValueError("RSA key not generated")
        
        try:
            public_key_pem = self.rsa_key.publickey().export_key()
            public_key_b64 = base64.b64encode(public_key_pem).decode('utf-8')
            return public_key_b64
            
        except Exception as e:
            print(f"[ERROR] Public key export failed: {e}")
            return None
    
    def import_public_key(self, public_key_b64):
        """
        Import a public key from base64-encoded PEM format.
        
        Args:
            public_key_b64 (str): Base64-encoded public key
            
        Returns:
            RSA.RsaKey: Imported public key object
        """
        try:
            public_key_pem = base64.b64decode(public_key_b64.encode('utf-8'))
            public_key = RSA.import_key(public_key_pem)
            return public_key
            
        except Exception as e:
            print(f"[ERROR] Public key import failed: {e}")
            return None
    
    def rsa_encrypt(self, data, public_key):
        """
        Encrypt data using RSA public key.
        
        Args:
            data (bytes): Data to encrypt
            public_key (RSA.RsaKey): RSA public key
            
        Returns:
            str: Base64-encoded encrypted data
        """
        try:
            cipher = PKCS1_OAEP.new(public_key)
            encrypted_data = cipher.encrypt(data)
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            print(f"[ERROR] RSA encryption failed: {e}")
            return None
    
    def rsa_decrypt(self, encrypted_data_b64):
        """
        Decrypt data using RSA private key.
        
        Args:
            encrypted_data_b64 (str): Base64-encoded encrypted data
            
        Returns:
            bytes: Decrypted data
        """
        if not self.rsa_key:
            raise ValueError("RSA private key not available")
        
        try:
            encrypted_data = base64.b64decode(encrypted_data_b64.encode('utf-8'))
            cipher = PKCS1_OAEP.new(self.rsa_key)
            decrypted_data = cipher.decrypt(encrypted_data)
            return decrypted_data
            
        except Exception as e:
            print(f"[ERROR] RSA decryption failed: {e}")
            return None
    
    # ==================== AES Symmetric Encryption ====================
    
    def generate_aes_key(self, key_size=32):
        try:
            self.aes_key = get_random_bytes(key_size)
            return self.aes_key
        except Exception:
            return None
    
    def set_aes_key(self, aes_key):
        self.aes_key = aes_key
    
    def aes_encrypt(self, data):
        """
        Encrypt data using AES in CBC mode.
        
        Args:
            data (str or bytes): Data to encrypt
            
        Returns:
            str: Base64-encoded encrypted data with IV
        """
        if not self.aes_key:
            raise ValueError("AES key not set")
        
        try:
            # Convert string to bytes if necessary
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate random IV
            iv = get_random_bytes(AES.block_size)
            
            # Create cipher and encrypt
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            padded_data = pad(data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Combine IV and encrypted data
            combined = iv + encrypted_data
            return base64.b64encode(combined).decode('utf-8')
            
        except Exception as e:
            print(f"[ERROR] AES encryption failed: {e}")
            return None
    
    def aes_decrypt(self, encrypted_data_b64):
        """
        Decrypt data using AES in CBC mode.
        
        Args:
            encrypted_data_b64 (str): Base64-encoded encrypted data with IV
            
        Returns:
            bytes: Decrypted data
        """
        if not self.aes_key:
            raise ValueError("AES key not set")
        
        try:
            # Decode from base64
            combined = base64.b64decode(encrypted_data_b64.encode('utf-8'))
            
            # Extract IV and encrypted data
            iv = combined[:AES.block_size]
            encrypted_data = combined[AES.block_size:]
            
            # Create cipher and decrypt
            cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
            padded_data = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(padded_data, AES.block_size)
            
            return decrypted_data
            
        except Exception as e:
            print(f"[ERROR] AES decryption failed: {e}")
            return None
    
    # ==================== Message Protocol ====================
    
    def create_message(self, msg_type, data, encrypted=True):
        """
        Create a protocol message.
        
        Args:
            msg_type (str): Message type (e.g., 'AUTH', 'KEY_EXCHANGE', 'DATA')
            data (dict): Message data
            encrypted (bool): Whether to encrypt the message
            
        Returns:
            str: JSON message string (encrypted if specified)
        """
        try:
            message = {
                'type': msg_type,
                'data': data,
                'encrypted': encrypted
            }
            
            json_message = json.dumps(message)
            
            if encrypted and self.aes_key:
                # Encrypt the entire JSON message
                encrypted_json = self.aes_encrypt(json_message)
                if encrypted_json:
                    # Create wrapper for encrypted message
                    encrypted_message = {
                        'type': 'ENCRYPTED',
                        'data': encrypted_json,
                        'encrypted': True
                    }
                    return json.dumps(encrypted_message)
            
            return json_message
            
        except Exception as e:
            print(f"[ERROR] Message creation failed: {e}")
            return None
    
    def parse_message(self, message_str):
        """
        Parse a protocol message.
        
        Args:
            message_str (str): JSON message string
            
        Returns:
            dict: Parsed message data
        """
        try:
            message = json.loads(message_str)
            
            # Check if message is encrypted
            if message.get('type') == 'ENCRYPTED' and message.get('encrypted'):
                if not self.aes_key:
                    print("[ERROR] Received encrypted message but no AES key available")
                    return None
                
                # Decrypt the message
                decrypted_data = self.aes_decrypt(message['data'])
                if decrypted_data:
                    decrypted_str = decrypted_data.decode('utf-8')
                    return json.loads(decrypted_str)
            
            return message
            
        except Exception as e:
            print(f"[ERROR] Message parsing failed: {e}")
            return None


def main():
    """Test the cryptographic utilities."""
    print("=== Testing Cryptographic Utilities ===\n")
    
    # Initialize crypto managers for client and server
    server_crypto = CryptoManager()
    client_crypto = CryptoManager()
    
    # Test RSA key generation
    print("1. Testing RSA Key Generation:")
    server_private, server_public = server_crypto.generate_rsa_keys(2048)
    
    if server_private and server_public:
        print("   ✓ RSA keys generated successfully")
        
        # Test public key export/import
        print("\n2. Testing Public Key Exchange:")
        public_key_b64 = server_crypto.export_public_key()
        if public_key_b64:
            print("   ✓ Public key exported")
            
            imported_public_key = client_crypto.import_public_key(public_key_b64)
            if imported_public_key:
                print("   ✓ Public key imported")
    
    # Test AES key generation and exchange
    print("\n3. Testing AES Key Exchange:")
    aes_key = client_crypto.generate_aes_key(32)  # 256-bit key
    
    if aes_key:
        print("   ✓ AES key generated")
        
        # Encrypt AES key with RSA
        encrypted_aes_key = client_crypto.rsa_encrypt(aes_key, imported_public_key)
        if encrypted_aes_key:
            print("   ✓ AES key encrypted with RSA")
            
            # Decrypt AES key with RSA
            decrypted_aes_key = server_crypto.rsa_decrypt(encrypted_aes_key)
            if decrypted_aes_key and decrypted_aes_key == aes_key:
                print("   ✓ AES key decrypted successfully")
                server_crypto.set_aes_key(decrypted_aes_key)
    
    # Test AES encryption/decryption
    print("\n4. Testing AES Encryption:")
    test_data = "This is a secret message for the VPN tunnel!"
    
    encrypted_data = client_crypto.aes_encrypt(test_data)
    if encrypted_data:
        print("   ✓ Data encrypted with AES")
        
        decrypted_data = server_crypto.aes_decrypt(encrypted_data)
        if decrypted_data and decrypted_data.decode('utf-8') == test_data:
            print("   ✓ Data decrypted successfully")
            print(f"   Original: {test_data}")
            print(f"   Decrypted: {decrypted_data.decode('utf-8')}")
    
    # Test message protocol
    print("\n5. Testing Message Protocol:")
    
    # Create unencrypted message
    message_data = {"command": "GET", "url": "http://example.com", "headers": {}}
    unencrypted_msg = client_crypto.create_message("HTTP_REQUEST", message_data, encrypted=False)
    print(f"   Unencrypted message: {unencrypted_msg[:100]}...")
    
    # Create encrypted message
    encrypted_msg = client_crypto.create_message("HTTP_REQUEST", message_data, encrypted=True)
    if encrypted_msg:
        print(f"   Encrypted message: {encrypted_msg[:100]}...")
        
        # Parse encrypted message
        parsed_msg = server_crypto.parse_message(encrypted_msg)
        if parsed_msg:
            print("   ✓ Encrypted message parsed successfully")
            print(f"   Parsed data: {parsed_msg}")
    
    print("\n=== All tests completed ===")


if __name__ == "__main__":
    main()
