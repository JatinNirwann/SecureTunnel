import socket
import random
import sys
import threading

VPN_SERVER_HOST = '139.59.231.109'
VPN_SERVER_PORT = 9999

LOCAL_PROXY_HOST = '127.0.0.1'
LOCAL_PROXY_PORT = 8080

P_PRIME = 23
G_BASE = 5

def vigenere_encrypt_bytes(plain_bytes, key):
    """
    Encrypts a bytes object using a modulo 256 Vigenère cipher.
    """
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
# --- END OF REPLACEMENT ---


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

def handle_browser(browser_socket, addr, vpn_server_host, vpn_server_port):
    print(f"[Browser] New connection from {addr}")
    
    try:
        connect_request = browser_socket.recv(4096)
        if not connect_request:
            print(f"[Browser] No data from browser.")
            return
            
        vpn_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        vpn_server_socket.connect((vpn_server_host, vpn_server_port))
        print(f"[VPN] Connected to server {vpn_server_host}:{vpn_server_port}")
        
        server_public_key = int(vpn_server_socket.recv(1024).decode('utf-8'))
        client_private_key = random.randint(2, P_PRIME - 1)
        client_public_key = (G_BASE ** client_private_key) % P_PRIME
        vpn_server_socket.sendall(str(client_public_key).encode('utf-8'))
        shared_secret_key = str((server_public_key ** client_private_key) % P_PRIME)
        print(f"[VPN] Established shared secret: {shared_secret_key}")
        encrypted_request = vigenere_encrypt_bytes(connect_request, shared_secret_key)
        vpn_server_socket.sendall(encrypted_request)
        
        # 5. Receive the encrypted "200 OK" from the server
        encrypted_ok = vpn_server_socket.recv(4096)
        # --- THIS LINE IS UPDATED ---
        ok_response_bytes = vigenere_decrypt_bytes(encrypted_ok, shared_secret_key)
        
        ok_response_str = ok_response_bytes.decode('latin-1')

        if "200 OK" in ok_response_str:
            browser_socket.sendall(ok_response_bytes)
            print(f"[Browser] OK response sent. Tunnelling data.")
        else:
            print(f"[Browser] Server did not approve connection. Closing.")
            browser_socket.close()
            return
            
        t1 = threading.Thread(target=relay_data, 
                              args=(browser_socket, vpn_server_socket, shared_secret_key, True))
        
        t2 = threading.Thread(target=relay_data, 
                              args=(vpn_server_socket, browser_socket, shared_secret_key, False))
        
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()

    except (ConnectionRefusedError, socket.gaierror):
        print(f"\n[Error] Connection refused. Is the VPN server running at {vpn_server_host}?")
    except Exception as e:
        print(f"[Browser Handler Error] {e}")
    finally:
        browser_socket.close()
        print(f"[Browser] Connection from {addr} closed.")


def main():
    print(f"--- VPN Client (Local Proxy) starting... ---")
    
    print(f"Attempting to connect to VPN Server at: {VPN_SERVER_HOST}")
        
    local_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        local_proxy_socket.bind((LOCAL_PROXY_HOST, LOCAL_PROXY_PORT))
        local_proxy_socket.listen()
        print(f"Local proxy is listening on {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}")
        print(f"Configure your browser to use HTTP/HTTPS proxy at this address.")
        
        while True:
            browser_socket, addr = local_proxy_socket.accept()
            proxy_thread = threading.Thread(target=handle_browser, 
                                            args=(browser_socket, addr, VPN_SERVER_HOST, VPN_SERVER_PORT))
            proxy_thread.start()
            
    except OSError as e:
        if e.errno == 98:
            print(f"\n[Error] Port {LOCAL_PROXY_PORT} is already in use.")
            print("Is another copy of the script running?")
        else:
            print(f"\n[Error] {e}")
    except KeyboardInterrupt:
        print("\n[Shutting down local proxy]... Goodbye.")
    finally:
        local_proxy_socket.close()

if __name__ == "__main__":
    main()

