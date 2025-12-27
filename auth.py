# auth.py - Authentication Manager
import sqlite3
import hashlib
from datetime import datetime

class AuthManager:
    def __init__(self, db_path='users.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize users database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register_user(self, username, email, password):
        """Register a new user"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            # Check if username or email already exists
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
            if c.fetchone():
                conn.close()
                return False, "Username or email already exists"
            
            # Hash password and insert user
            password_hash = self.hash_password(password)
            c.execute('''INSERT INTO users (username, email, password)
                        VALUES (?, ?, ?)''',
                     (username, email, password_hash))
            conn.commit()
            user_id = c.lastrowid
            conn.close()
            return True, f"User {username} registered successfully"
        except Exception as e:
            return False, f"Registration error: {str(e)}"
    
    def login_user(self, username, password):
        """Login user and return success status, user_id, and email"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            
            password_hash = self.hash_password(password)
            c.execute('SELECT id, email FROM users WHERE username = ? AND password = ?',
                     (username, password_hash))
            result = c.fetchone()
            conn.close()
            
            if result:
                return True, result[0], result[1]
            else:
                return False, None, None
        except Exception as e:
            return False, None, None
    
    def verify_user(self, user_id):
        """Verify if user exists"""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT username, email FROM users WHERE id = ?', (user_id,))
            result = c.fetchone()
            conn.close()
            if result:
                return True, result[0], result[1]
            return False, None, None
        except:
            return False, None, None
