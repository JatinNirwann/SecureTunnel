import sqlite3
import hashlib
import os
from datetime import datetime


class DatabaseManager:    
    def __init__(self, db_path=None):
        if db_path is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.db_path = os.path.join(script_dir, "..", "vpn_users.db")
        else:
            self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS connection_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        connection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT NOT NULL,
                        FOREIGN KEY (username) REFERENCES users (username)
                    )
                ''')
                
                conn.commit()
                
        except sqlite3.Error:
            pass
    
    def _hash_password(self, password):
        
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_user(self, username, password):
        try:
            password_hash = self._hash_password(password)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
                return True
                
        except sqlite3.IntegrityError:
            return False
        except sqlite3.Error:
            return False
    
    def verify_user(self, username, password):
        try:
            password_hash = self._hash_password(password)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT password_hash FROM users WHERE username = ?",
                    (username,)
                )
                result = cursor.fetchone()
                
                if result and result[0] == password_hash:
                    return True
                else:
                    return False
                    
        except sqlite3.Error:
            return False
    
    def log_connection(self, username, client_ip, status):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO connection_logs (username, client_ip, status) VALUES (?, ?, ?)",
                    (username, client_ip, status)
                )
                conn.commit()
                
        except sqlite3.Error:
            pass
    
    def get_connection_logs(self, limit=10):

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT username, client_ip, connection_time, status "
                    "FROM connection_logs ORDER BY connection_time DESC LIMIT ?",
                    (limit,)
                )
                return cursor.fetchall()
                
        except sqlite3.Error as e:
            print(f"[ERROR] Failed to retrieve logs: {e}")
            return []
    
    def create_default_users(self):
        test_users = [
            ("alice", "password123"),
            ("bob", "securepass"),
            ("admin", "admin123")
        ]
        
        for username, password in test_users:
            self.create_user(username, password)


def main():
    db = DatabaseManager()
    
    print("\n=== Creating Test Users ===")
    db.create_default_users()
    
    print("\n=== Testing Authentication ===")
    print(f"Alice login (correct): {db.verify_user('alice', 'password123')}")
    print(f"Alice login (wrong): {db.verify_user('alice', 'wrongpass')}")
    print(f"Bob login: {db.verify_user('bob', 'securepass')}")
    
    # Test logging
    print("\n=== Testing Connection Logging ===")
    db.log_connection("alice", "127.0.0.1", "SUCCESS")
    db.log_connection("bob", "192.168.1.100", "SUCCESS")
    db.log_connection("alice", "127.0.0.1", "FAILED")
    
    # Show recent logs
    print("\n=== Recent Connection Logs ===")
    logs = db.get_connection_logs(5)
    for log in logs:
        print(f"User: {log[0]}, IP: {log[1]}, Time: {log[2]}, Status: {log[3]}")


if __name__ == "__main__":
    main()
