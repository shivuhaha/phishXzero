# db_manager.py - Scan Database Management
import sqlite3
from datetime import datetime
import pandas as pd

class ScanDatabase:
    def __init__(self, db_path='phishing_scans.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sender TEXT,
            subject TEXT,
            email_body TEXT,
            verdict TEXT,
            score INTEGER,
            risk_level TEXT,
            reasons TEXT
        )''')
        conn.commit()
        conn.close()
    
    def add_scan(self, user_id, sender, subject, body, verdict, score, risk_level, reasons):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            reasons_str = '|'.join(reasons) if reasons else ''
            c.execute('''INSERT INTO scans (user_id, sender, subject, email_body, verdict, score, risk_level, reasons)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (user_id, sender, subject, body, verdict, score, risk_level, reasons_str))
            conn.commit()
            conn.close()
            return True
        except:
            return False
    
    def get_user_scans(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            df = pd.read_sql_query('''SELECT id, timestamp, sender, subject, verdict, score, risk_level
                FROM scans WHERE user_id = ? ORDER BY timestamp DESC''', conn, params=(user_id,))
            conn.close()
            return df
        except:
            return pd.DataFrame()
    
    def get_scan_stats(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM scans WHERE user_id = ?', (user_id,))
            total = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND verdict = "PHISHING"', (user_id,))
            phishing = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND verdict = "LEGITIMATE"', (user_id,))
            legitimate = c.fetchone()[0]
            c.execute('SELECT COUNT(*) FROM scans WHERE user_id = ? AND verdict = "SUSPICIOUS"', (user_id,))
            suspicious = c.fetchone()[0]
            conn.close()
            return {'total': total, 'phishing': phishing, 'legitimate': legitimate, 'suspicious': suspicious}
        except:
            return {'total': 0, 'phishing': 0, 'legitimate': 0, 'suspicious': 0}
    
    def clear_user_history(self, user_id):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('DELETE FROM scans WHERE user_id = ?', (user_id,))
            conn.commit()
            conn.close()
            return True
        except:
            return False

# Module-level functions for easier imports
_db = ScanDatabase()

def record_scan(sender, body, threat_level, details):
    """Record a scan result"""
    try:
        conn = sqlite3.connect('phishing_scans.db')
        c = conn.cursor()
        c.execute('''INSERT INTO scans (sender, email_body, verdict, reasons)
                    VALUES (?, ?, ?, ?)''',
                 (sender, body, threat_level, details))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_scan_statistics():
    """Get global scan statistics"""
    try:
        conn = sqlite3.connect('phishing_scans.db')
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM scans')
        total = c.fetchone()[0] or 0
        c.execute('SELECT COUNT(*) FROM scans WHERE verdict = "SAFE"')
        safe = c.fetchone()[0] or 0
        c.execute('SELECT COUNT(*) FROM scans WHERE verdict = "DANGEROUS"')
        dangerous = c.fetchone()[0] or 0
        
        detection_rate = int((dangerous / total * 100)) if total > 0 else 0
        
        conn.close()
        return {
            'total_scans': total,
            'safe_emails': safe,
            'phishing_detected': dangerous,
            'detection_rate': detection_rate
        }
    except:
        return {'total_scans': 0, 'safe_emails': 0, 'phishing_detected': 0, 'detection_rate': 0}

def get_recent_scans(limit=50):
    """Get recent scan records"""
    try:
        conn = sqlite3.connect('phishing_scans.db')
        c = conn.cursor()
        c.execute('''SELECT id, sender, email_body, verdict, timestamp, reasons 
                    FROM scans ORDER BY timestamp DESC LIMIT ?''', (limit,))
        results = c.fetchall()
        conn.close()
        return results
    except:
        return []