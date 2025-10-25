import socket
import random
import threading
import sys

LISTEN_HOST = '0.0.0.0' 
LISTEN_PORT = 9999

P_PRIME = 23 
G_BASE = 5   

def vigenere_encrypt_bytes(plain_bytes, key):
    encrypted_bytes = bytearray()
    key_len = len(key)
    for i, byte_val in enumerate(plain_bytes):
        key_char = key[i % key_len]
        key_ord = ord(key_char)
        encrypted_ord = (byte_val + key_ord) % 256
        encrypted_bytes.append(encrypted_ord)
    return bytes(encrypted_bytes)

def vigenere_decrypt_bytes(encrypted_bytes, key):
    decrypted_bytes = bytearray()
    key_len = len(key)
    for i, byte_val in enumerate(encrypted_bytes):
        key_char = key[i % key_len]
        key_ord = ord(key_char)
        decrypted_ord = (byte_val - key_ord + 256) % 256 
        decrypted_bytes.append(decrypted_ord)
    return bytes(decrypted_bytes)

def relay_data(src_conn, dest_conn, shared_secret_key, encrypt):
    try:
        while True:
            data = src_conn.recv(4096)
            if not data:
                break
            
            if encrypt:
                processed_data = vigenere_encrypt_bytes(data, shared_secret_key)
            else:
                processed_data = vigenere_decrypt_bytes(data, shared_secret_key)
                
            dest_conn.sendall(processed_data)
            
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        print(f"[Relay Error] {e}")
    finally:
        src_conn.close()
        dest_conn.close()
        print("[Relay] A connection was closed.")

def handle_client(vpn_client_conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    
    try:
        server_private_key = random.randint(2, P_PRIME - 1)
        server_public_key = (G_BASE ** server_private_key) % P_PRIME
        
        vpn_client_conn.sendall(str(server_public_key).encode('utf-8'))
        
        client_public_key = int(vpn_client_conn.recv(1024).decode('utf-8'))
        
        shared_secret_key = str((client_public_key ** server_private_key) % P_PRIME)
        print(f"[{addr}] Established shared secret: {shared_secret_key}")
        
        encrypted_connect_request = vpn_client_conn.recv(4096)
        if not encrypted_connect_request:
            print(f"[{addr}] Client disconnected before sending request.")
            return
            
        connect_request_bytes = vigenere_decrypt_bytes(encrypted_connect_request, shared_secret_key)
        
        connect_request_str = connect_request_bytes.decode('latin-1')
        print(f"[{addr}] Decrypted request: {connect_request_str.splitlines()[0]}...")
        
        try:
            first_line = connect_request_str.splitlines()[0]
            method = first_line.split()[0]
            
            target_host = ""
            target_port = 0

            if method == 'CONNECT':
                target_host, target_port_str = first_line.split()[1].split(':')
                target_port = int(target_port_str)
            else:
                target_port = 80
                for line in connect_request_str.splitlines():
                    if line.lower().startswith('host:'):
                        target_host = line.split(':', 1)[1].strip()
                        if ':' in target_host:
                            target_host, target_port_str = target_host.split(':', 1)
                            target_port = int(target_port_str)
                        break
                if not target_host:
                    print(f"[{addr}] Could not find 'Host:' header in HTTP request.")
                    return

        except Exception as e:
            print(f"[{addr}] Could not parse request. {e}")
            print(f"Request dump: {connect_request_str[:200]}...")
            return
            
        print(f"[{addr}] Connecting to target {target_host}:{target_port}")
        
        remote_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_server_socket.connect((target_host, target_port))
        
        if method == 'CONNECT':
            ok_response = "HTTP/1.1 200 OK\r\n\r\n"
            encrypted_ok = vigenere_encrypt_bytes(ok_response.encode('latin-1'), shared_secret_key)
            vpn_client_conn.sendall(encrypted_ok)
            print(f"[{addr}] OK response sent. Tunnelling data for {target_host}:{target_port}")
        else:
            remote_server_socket.sendall(connect_request_bytes)
            print(f"[{addr}] Sent HTTP request to {target_host}:{target_port}")

        t1 = threading.Thread(target=relay_data, 
                              args=(vpn_client_conn, remote_server_socket, shared_secret_key, False))
        
        t2 = threading.Thread(target=relay_data, 
                              args=(remote_server_socket, vpn_client_conn, shared_secret_key, True))
        
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()

    except (ConnectionResetError, BrokenPipeError):
        print(f"[{addr}] Client connection lost.")
    except Exception as e:
        print(f"[{addr}] Error in handle_client: {e}")
    finally:
        vpn_client_conn.close()
        print(f"[{addr}] Connection closed.")

def main():
    print("--- VPN Proxy EXIT NODE is starting... ---")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
        server_socket.listen()
        print(f"Server is listening on {LISTEN_HOST}:{LISTEN_PORT}")
        print("Waiting for clients to connect...")
        
        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            
    except OSError as e:
        print(f"\n[Error] Could not bind to port {LISTEN_PORT}. Is it already in use?")
        print(f"Details: {e}")
    except KeyboardInterrupt:
        print("\n[Server shutting down]... Goodbye.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
