# VPN Prototype for Geo-Unblocking

A sophisticated VPN prototype built in Python that demonstrates secure tunneling, encryption, user authentication, and geo-unblocking capabilities. This system creates an encrypted tunnel between clients and a VPS server, allowing users to bypass geographic restrictions and access blocked content.

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Security Features](#security-features)
- [Geo-Unblocking Mechanism](#geo-unblocking-mechanism)
- [Components](#components)
- [Installation & Deployment](#installation--deployment)
- [Usage Guide](#usage-guide)
- [Technical Implementation](#technical-implementation)
- [Network Flow](#network-flow)
- [Security Considerations](#security-considerations)

## Architecture Overview

```
[Client] --encrypted--> [VPS Server] ---> [Target Website]
   |                        |                    |
   |                        |                    |
User's                 64.227.128.92         google.com
Location              (US/EU Server)        youtube.com
                                           netflix.com
```

SecureTunnel operates as a proxy server that:
1. **Encrypts** all traffic between client and VPS using RSA + AES encryption
2. **Authenticates** users with secure login/registration system
3. **Masks** the client's real IP address and location
4. **Spoofs** headers to appear as if requests originate from the VPS location

## Security Features

### 1. **Hybrid Encryption System**
- **RSA 2048-bit** key exchange for initial secure channel establishment
- **AES-256** symmetric encryption for all data transmission
- **Automatic key rotation** for each session

### 2. **User Authentication**
- SQLite database with hashed passwords (SHA-256)
- Session-based authentication
- Connection logging for security auditing
- Dynamic user registration

### 3. **Secure Communication Protocol**
- JSON-based message protocol with encryption flags
- Message integrity verification
- SSL/TLS bypass for blocked HTTPS sites

## Geo-Unblocking Mechanism

### Why VPS IP Instead of Random IP?

The system uses the VPS IP (`64.227.128.92`) for geo-spoofing headers instead of random IPs like `203.0.113.195` because:

1. **Real Geographic Location**: The VPS is physically located in a different region (likely US/EU), making the geo-spoofing authentic
2. **Consistent IP Reputation**: Using the actual VPS IP maintains consistency with the source of requests
3. **ISP Validation**: Many services validate that forwarded IPs match the actual source, making VPS IP more effective
4. **Reduced Detection**: Random IPs from test ranges (like 203.0.113.x) are easily flagged as proxies

### Header Spoofing Strategy
```python
geo_headers = {
    'X-Forwarded-For': '64.227.128.92',      # Actual VPS location
    'X-Real-IP': '64.227.128.92',            # Reinforces geo location
    'CF-Connecting-IP': '64.227.128.92',     # Cloudflare compatibility
    'User-Agent': 'Mozilla/5.0...',          # Real browser fingerprint
    'Accept-Language': 'en-US,en;q=0.5'      # US locale preference
}
```

## Components

### 1. **server.py** - VPS Server
- Binds to `0.0.0.0:8888` (all interfaces)
- Handles multiple concurrent client connections
- Manages encryption key exchange
- Performs HTTP requests with geo-spoofing
- Maintains user database and connection logs

### 2. **client.py** - Client Application
- Connects to VPS server (`64.227.128.92:8888`)
- Provides interactive shell for commands
- Handles user registration and authentication
- Encrypts/decrypts all communications
- Supports both interactive and command-line modes

### 3. **crypto_utils.py** - Encryption Engine
- RSA key generation and management
- AES encryption/decryption with CBC mode
- Message protocol with encryption wrapper
- Key exchange protocol implementation

### 4. **database.py** - User Management
- SQLite database for user storage
- Password hashing with SHA-256
- Connection logging system
- Default test users creation

## Installation & Deployment

### VPS Server Setup
```bash
# 1. Upload files to VPS
scp -r SecureTunnel root@64.227.128.92:/root/

# 2. Install dependencies
ssh root@64.227.128.92
cd /root/SecureTunnel
pip3 install pycryptodome requests urllib3

# 3. Open firewall
sudo ufw allow 8888/tcp

# 4. Start server
python3 src/server.py
```

### Client Setup
```bash
# 1. Install dependencies
pip install pycryptodome requests

# 2. Run client
python src/client.py
```

## Usage Guide

### Starting the System

**Server (VPS):**
```bash
python3 src/server.py
# Output: VPN Server listening on 0.0.0.0:8888
```

**Client:**
```bash
python src/client.py
# Choose: Login (l) or Register (r)?
```

### Client Commands
```
VPN> get google.com           # Fetch website through VPS
VPN> get httpbin.org/ip       # Check apparent IP (shows VPS IP)
VPN> get youtube.com          # Access geo-blocked content
VPN> register                 # Create new user account
VPN> status                   # Show connection status
VPN> help                     # List available commands  
VPN> exit                     # Disconnect and quit
```

### Default Test Users
- **alice** / **password123**
- **bob** / **securepass**
- **admin** / **admin123**

## Technical Implementation

### Network Protocol Flow

1. **Connection Establishment**
```
Client -> Server: TCP connection to 64.227.128.92:8888
Server -> Client: Connection accepted
```

2. **User Authentication**
```
Client -> Server: {"type": "AUTH", "data": {"username": "alice", "password": "password123"}}
Server -> Client: {"type": "AUTH_RESPONSE", "data": {"status": "SUCCESS"}}
```

3. **Key Exchange (RSA + AES)**
```
Server -> Client: RSA Public Key
Client -> Server: AES Key (encrypted with RSA)
Server -> Client: Key exchange confirmation
```

4. **Encrypted HTTP Request**
```
Client -> Server: Encrypted {"type": "HTTP_REQUEST", "data": {"url": "google.com"}}
Server -> Internet: HTTP request with spoofed headers from VPS IP
Internet -> Server: Response
Server -> Client: Encrypted response
```

### Encryption Process

```python
# 1. RSA Key Exchange
server_public_key = rsa.generate(2048)
aes_key = generate_random_bytes(32)  # 256-bit
encrypted_aes = rsa_encrypt(aes_key, server_public_key)

# 2. AES Message Encryption
iv = generate_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
encrypted_data = cipher.encrypt(pad(message))
final_message = base64_encode(iv + encrypted_data)
```

### Database Schema

```sql
-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Connection logs table  
CREATE TABLE connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    connection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL
);
```

## Network Flow

### Request Path Analysis
```
1. User in restricted country (e.g., China)
   |
2. Encrypted request to VPS (64.227.128.92 in US)
   |
3. VPS decrypts and adds geo-headers
   |  
4. VPS makes request to target site (appears to come from US)
   |
5. Target site responds (thinks user is in US)
   |
6. VPS encrypts response and sends back to client
   |
7. Client decrypts and displays content
```

### Geo-Unblocking Effectiveness

**Blocked Content Access:**
- Netflix US content from restricted regions
- YouTube videos blocked by country
- News sites with geographic restrictions
- Social media platforms blocked in certain countries

**Detection Avoidance:**
- Uses real browser User-Agent strings
- Maintains consistent IP (VPS IP) across headers
- Disables SSL verification for HTTPS sites
- Encrypts all client-server communication

## Security Considerations

### Strengths
- End-to-end encryption between client and VPS
- Strong authentication system
- No logs of user browsing activity
- Secure key exchange protocol

### Limitations
- VPS-to-target site traffic is unencrypted (normal HTTP/HTTPS)
- SQLite database stored in plaintext (for development)
- No protection against VPS compromise
- Limited to HTTP/HTTPS protocols

### Production Recommendations
- Implement database encryption
- Add certificate pinning
- Use multiple VPS locations
- Add traffic obfuscation
- Implement perfect forward secrecy

## Lab Showcase Demo

**Demonstration Script:**

1. **Start server on VPS**
   ```bash
   python3 src/server.py
   ```

2. **Connect client and register new user**
   ```bash
   python src/client.py
   # Register: testuser/password123
   ```

3. **Show geo-unblocking**
   ```
   VPN> get httpbin.org/ip
   # Shows VPS IP instead of real IP
   
   VPN> get google.com
   # Successfully fetches Google homepage
   
   VPN> get youtube.com  
   # Access YouTube through US server
   ```

4. **Demonstrate encryption**
   - Show encrypted traffic in network capture
   - Compare with direct HTTP requests

This SecureTunnel prototype demonstrates the core principles of VPN technology, secure tunneling, and geo-unblocking in a lab environment.
