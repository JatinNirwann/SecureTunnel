import socket
import threading
import json
import requests
import sys
import os
from datetime import datetime

sys.path.append(os.path.dirname(__file__))

from database import DatabaseManager
from crypto_utils import CryptoManager


class VPNServer:
    def __init__(self, host='localhost', port=8888, encryption_enabled=True):
        self.host = host
        self.port = port
        self.encryption_enabled = encryption_enabled
        self.running = False
        self.crypto = CryptoManager()
        self.database = DatabaseManager()
        self.private_key, self.public_key = self.crypto.generate_rsa_keys(2048)
        self.active_connections = {}
    
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            print(f"VPN Server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error:
                    if self.running:
                        break
        
        except Exception:
            pass
        finally:
            self.stop_server()
    
    def handle_client(self, client_socket, client_address):
        client_id = f"{client_address[0]}:{client_address[1]}"
        
        try:
            client_crypto = CryptoManager()
            
            if not self.authenticate_client(client_socket, client_address):
                return
            
            if self.encryption_enabled:
                if not self.perform_key_exchange(client_socket, client_crypto):
                    return
            
            self.active_connections[client_id] = {
                'socket': client_socket,
                'address': client_address,
                'crypto': client_crypto,
                'authenticated': True
            }
            
            self.handle_client_requests(client_socket, client_crypto, client_id)
            
        except Exception:
            pass
        finally:
            if client_id in self.active_connections:
                del self.active_connections[client_id]
            client_socket.close()
    
    def authenticate_client(self, client_socket, client_address):
        try:
            auth_data = client_socket.recv(1024).decode('utf-8')
            auth_message = json.loads(auth_data)
            
            if auth_message.get('type') != 'AUTH':
                return False
            
            username = auth_message['data']['username']
            password = auth_message['data']['password']
            
            if self.database.verify_user(username, password):
                response = {
                    'type': 'AUTH_RESPONSE',
                    'data': {'status': 'SUCCESS', 'message': 'Authentication successful'},
                    'encrypted': False
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
                self.database.log_connection(username, client_address[0], 'SUCCESS')
                return True
            else:
                response = {
                    'type': 'AUTH_RESPONSE',
                    'data': {'status': 'FAILED', 'message': 'Invalid credentials'},
                    'encrypted': False
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
                self.database.log_connection(username, client_address[0], 'FAILED')
                return False
                
        except Exception:
            return False
    
    def perform_key_exchange(self, client_socket, client_crypto):
        try:
            public_key_b64 = self.crypto.export_public_key()
            key_message = {
                'type': 'PUBLIC_KEY',
                'data': {'public_key': public_key_b64},
                'encrypted': False
            }
            client_socket.send(json.dumps(key_message).encode('utf-8'))
            
            key_data = client_socket.recv(2048).decode('utf-8')
            key_message = json.loads(key_data)
            
            if key_message.get('type') != 'AES_KEY':
                return False
            
            encrypted_aes_key = key_message['data']['aes_key']
            aes_key = self.crypto.rsa_decrypt(encrypted_aes_key)
            
            if not aes_key:
                return False
            
            client_crypto.set_aes_key(aes_key)
            
            response = {
                'type': 'KEY_EXCHANGE_RESPONSE',
                'data': {'status': 'SUCCESS', 'message': 'AES key received'},
                'encrypted': False
            }
            client_socket.send(json.dumps(response).encode('utf-8'))
            return True
            
        except Exception:
            return False
    
    def handle_client_requests(self, client_socket, client_crypto, client_id):
        while self.running:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                if self.encryption_enabled:
                    message = client_crypto.parse_message(data)
                else:
                    message = json.loads(data)
                
                if not message:
                    continue
                
                if message.get('type') == 'HTTP_REQUEST':
                    self.handle_http_request(client_socket, client_crypto, message['data'])
                
            except socket.timeout:
                continue
            except ConnectionResetError:
                break
            except Exception:
                break
    
    def handle_http_request(self, client_socket, client_crypto, request_data):
        try:
            method = request_data.get('method', 'GET')
            url = request_data.get('url')
            headers = request_data.get('headers', {})
            data = request_data.get('data')
            
            if not url:
                return
            
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=10,
                allow_redirects=True
            )
            
            response_data = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text[:10000],
                'url': response.url
            }
            
            if self.encryption_enabled:
                response_message = client_crypto.create_message(
                    'HTTP_RESPONSE', response_data, encrypted=True
                )
            else:
                response_message = json.dumps({
                    'type': 'HTTP_RESPONSE',
                    'data': response_data,
                    'encrypted': False
                })
            
            if response_message:
                client_socket.send(response_message.encode('utf-8'))
                
        except requests.RequestException:
            error_data = {'error': 'HTTP request failed'}
            if self.encryption_enabled:
                error_message = client_crypto.create_message(
                    'HTTP_ERROR', error_data, encrypted=True
                )
            else:
                error_message = json.dumps({
                    'type': 'HTTP_ERROR',
                    'data': error_data,
                    'encrypted': False
                })
            
            if error_message:
                client_socket.send(error_message.encode('utf-8'))
        
        except Exception:
            pass
    
    def stop_server(self):
        self.running = False
        if hasattr(self, 'server_socket'):
            self.server_socket.close()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SecureTunnel VPN Server')
    parser.add_argument('--host', default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=8888, help='Server port')
    parser.add_argument('--no-encryption', action='store_true', help='Disable encryption')
    
    args = parser.parse_args()
    
    print("=== Initializing VPN Server ===")
    db = DatabaseManager()
    db.create_default_users()
    
    server = VPNServer(
        host=args.host,
        port=args.port,
        encryption_enabled=not args.no_encryption
    )
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        server.stop_server()


if __name__ == "__main__":
    main()
