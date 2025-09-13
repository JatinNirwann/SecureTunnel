import socket
import json
import sys
import os
import getpass
from datetime import datetime

sys.path.append(os.path.dirname(__file__))

from crypto_utils import CryptoManager


class VPNClient:
    def __init__(self, server_host='localhost', server_port=8888):
        self.server_host = server_host
        self.server_port = server_port
        self.connected = False
        self.authenticated = False
        self.encryption_enabled = True
        self.crypto = CryptoManager()
        self.socket = None
    
    def connect_to_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True
            return True
        except socket.error:
            return False
    
    def authenticate(self, username=None, password=None):
        if not self.connected:
            return False
        
        try:
            if not username:
                username = input("Username: ")
            if not password:
                password = getpass.getpass("Password: ")
            
            auth_message = {
                'type': 'AUTH',
                'data': {'username': username, 'password': password},
                'encrypted': False
            }
            
            self.socket.send(json.dumps(auth_message).encode('utf-8'))
            response_data = self.socket.recv(1024).decode('utf-8')
            response = json.loads(response_data)
            
            if (response.get('type') == 'AUTH_RESPONSE' and 
                response.get('data', {}).get('status') == 'SUCCESS'):
                self.authenticated = True
                return True
            else:
                return False
                
        except Exception:
            return False
    
    def perform_key_exchange(self):
        if not self.authenticated:
            return False
        
        try:
            key_data = self.socket.recv(2048).decode('utf-8')
            key_message = json.loads(key_data)
            
            if key_message.get('type') != 'PUBLIC_KEY':
                return False
            
            server_public_key_b64 = key_message['data']['public_key']
            server_public_key = self.crypto.import_public_key(server_public_key_b64)
            
            if not server_public_key:
                return False
            
            aes_key = self.crypto.generate_aes_key(32)
            if not aes_key:
                return False
            
            encrypted_aes_key = self.crypto.rsa_encrypt(aes_key, server_public_key)
            if not encrypted_aes_key:
                return False
            
            aes_message = {
                'type': 'AES_KEY',
                'data': {'aes_key': encrypted_aes_key},
                'encrypted': False
            }
            
            self.socket.send(json.dumps(aes_message).encode('utf-8'))
            response_data = self.socket.recv(1024).decode('utf-8')
            response = json.loads(response_data)
            
            if (response.get('type') == 'KEY_EXCHANGE_RESPONSE' and 
                response.get('data', {}).get('status') == 'SUCCESS'):
                self.encryption_enabled = True
                return True
            else:
                return False
                
        except Exception:
            return False
    
    def send_http_request(self, method='GET', url=None, headers=None, data=None):
        if not self.connected or not self.authenticated:
            return None
        
        try:
            if not url:
                url = input("Enter URL to fetch: ")
            
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            request_data = {
                'method': method,
                'url': url,
                'headers': headers or {},
                'data': data
            }
            
            if self.encryption_enabled:
                message = self.crypto.create_message('HTTP_REQUEST', request_data, encrypted=True)
            else:
                message = json.dumps({
                    'type': 'HTTP_REQUEST',
                    'data': request_data,
                    'encrypted': False
                })
            
            if not message:
                return None
            
            self.socket.send(message.encode('utf-8'))
            response_data = self.socket.recv(8192).decode('utf-8')
            
            if self.encryption_enabled:
                response = self.crypto.parse_message(response_data)
            else:
                response = json.loads(response_data)
            
            if not response:
                return None
            
            if response.get('type') == 'HTTP_RESPONSE':
                return response['data']
            elif response.get('type') == 'HTTP_ERROR':
                return None
            else:
                return None
                
        except Exception:
            return None
    
    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.connected = False
            self.authenticated = False
    
    def interactive_session(self):
        print("\n=== SecureTunnel VPN Client ===")
        print("Commands: get <url>, ping, status, help, exit")
        
        while True:
            try:
                command = input("VPN> ").strip().lower()
                
                if command.startswith('get '):
                    url = command[4:].strip()
                    response = self.send_http_request(url=url)
                    
                    if response:
                        print(f"\nStatus: {response['status_code']}")
                        print(f"URL: {response['url']}")
                        print(f"Content: {response['content'][:500]}")
                        if len(response['content']) > 500:
                            print("...")
                
                elif command == 'ping':
                    print("Ping functionality not implemented")
                
                elif command == 'status':
                    print(f"Connected: {self.connected}")
                    print(f"Authenticated: {self.authenticated}")
                    print(f"Encryption: {self.encryption_enabled}")
                
                elif command in ['help', '?']:
                    print("Commands: get <url>, ping, status, help, exit")
                
                elif command in ['exit', 'quit']:
                    break
                
                elif command == '':
                    continue
                
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                break
            except Exception:
                pass


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SecureTunnel VPN Client')
    parser.add_argument('--host', default='localhost', help='VPN server host')
    parser.add_argument('--port', type=int, default=8888, help='VPN server port')
    parser.add_argument('--no-encryption', action='store_true', help='Disable encryption')
    parser.add_argument('--url', help='URL to fetch (non-interactive mode)')
    
    args = parser.parse_args()
    
    client = VPNClient(server_host=args.host, server_port=args.port)
    
    try:
        if not client.connect_to_server():
            print("Failed to connect to server")
            return 1
        
        if not client.authenticate():
            print("Authentication failed")
            return 1
        
        if not args.no_encryption:
            if not client.perform_key_exchange():
                client.encryption_enabled = False
        else:
            client.encryption_enabled = False
        
        if args.url:
            response = client.send_http_request(url=args.url)
            if response:
                print(f"HTTP {response['status_code']} - {response['url']}")
                print(f"Content: {response['content'][:200]}")
            return 0 if response else 1
        
        client.interactive_session()
        
    except KeyboardInterrupt:
        pass
    
    finally:
        client.disconnect()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
