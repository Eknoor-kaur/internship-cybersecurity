# Password Strength Analyzer
# Author: Noor
# Description: Analyzes password strength, detects reuse via SQLite,
# and generates cryptographically secure passwords.
import re
import sqlite3
import hashlib
import secrets
import string
import math
import os

# ==========================================
# PART 1: Analysis Logic & Entropy Calculation
# ==========================================

class PasswordAnalyzer:
    def __init__(self, password):
        self.password = password
        self.score = 0
        self.feedback = []
        self.entropy = 0
        self.strength_label = "Very Weak"

    def analyze(self):
        self.check_length()
        self.check_complexity()
        self.check_repetitive_patterns()
        self.calculate_entropy()
        self.determine_strength()
        return {
            "score": self.score,
            "label": self.strength_label,
            "feedback": self.feedback,
            "entropy": round(self.entropy, 2)
        }

    def check_length(self):
        if len(self.password) < 8:
            self.feedback.append("❌ Password is too short (min 8 chars).")
        else:
            self.score += 1
            self.feedback.append("✅ Good length.")

    def check_complexity(self):
        has_upper = re.search(r"[A-Z]", self.password)
        has_lower = re.search(r"[a-z]", self.password)
        has_digit = re.search(r"[0-9]", self.password)
        has_special = re.search(r"[!@#$%^&*()]", self.password)

        categories = [has_upper, has_lower, has_digit, has_special]
        
        for cat in categories:
            if cat:
                self.score += 1
            else:
                self.feedback.append("❌ Missing character type.")

        if has_upper and has_lower and has_digit and has_special:
            self.feedback.append("✅ Excellent complexity.")

    def check_repetitive_patterns(self):
        sequences = ["123", "abc", "aaa", "111", "qwerty"]
        found_seq = False
        for seq in sequences:
            if seq in self.password.lower():
                found_seq = True
                break
        
        if found_seq:
            self.score -= 1
            self.feedback.append("⚠️ Avoid predictable sequences.")

    def calculate_entropy(self):
        pool_size = 0
        if re.search(r"[a-z]", self.password): pool_size += 26
        if re.search(r"[A-Z]", self.password): pool_size += 26
        if re.search(r"[0-9]", self.password): pool_size += 10
        if re.search(r"[!@#$%^&*()]", self.password): pool_size += 32
        
        if pool_size > 0:
            self.entropy = len(self.password) * math.log2(pool_size)

    def determine_strength(self):
        if self.entropy > 60:
            self.strength_label = "Strong"
        elif self.entropy > 40:
            self.strength_label = "Medium"
        elif self.entropy > 20:
            self.strength_label = "Weak"
        else:
            self.strength_label = "Very Weak"

# ==========================================
# PART 2: Secure Password Generator
# ==========================================

def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and 
            any(c.isupper() for c in password) and 
            any(c.isdigit() for c in password) and 
            any(c in string.punctuation for c in password)):
            return password

# ==========================================
# PART 3: Database Manager (NEW: Status Check)
# ==========================================

class PasswordDB:
    def __init__(self, db_name="passwords.db"):
        self.db_name = db_name
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        self.conn.commit()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_reuse(self, password):
        h = self.hash_password(password)
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM password_history WHERE password_hash = ?", (h,))
        return cursor.fetchone() is not None

    def save_password(self, password):
        h = self.hash_password(password)
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO password_history (password_hash) VALUES (?)", (h,))
        self.conn.commit()

    def get_status(self):
        """Check database status and return info"""
        try:
            cursor = self.conn.cursor()
            
            # Check if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='password_history'")
            table_exists = cursor.fetchone() is not None
            
            if not table_exists:
                return {
                    "status": "❌ ERROR",
                    "connected": False,
                    "table_exists": False,
                    "total_passwords": 0,
                    "message": "Table 'password_history' does not exist!"
                }
            
            # Get total count
            cursor.execute("SELECT COUNT(*) FROM password_history")
            total_count = cursor.fetchone()[0]
            
            # Get recent entries (last 3)
            cursor.execute("SELECT password_hash, created_at FROM password_history ORDER BY id DESC LIMIT 3")
            recent = cursor.fetchall()
            
            return {
                "status": "✅ OK",
                "connected": True,
                "table_exists": True,
                "total_passwords": total_count,
                "recent_entries": recent,
                "message": "Database is working correctly!"
            }
            
        except sqlite3.Error as e:
            return {
                "status": "❌ ERROR",
                "connected": False,
                "table_exists": False,
                "total_passwords": 0,
                "message": f"Database Error: {str(e)}"
            }

    def close(self):
        self.conn.close()

# ==========================================
# PART 4: Main User Interface
# ==========================================

def main():
    print("--- Password Strength Analyzer ---")
    
    # Initialize DB
    db = PasswordDB()

    while True:
        print("\n" + "="*40)
        print("1. Analyze a Password")
        print("2. Generate a Strong Password")
        print("3. Check Database Status  [NEW]")
        print("4. Exit")
        print("="*40)
        choice = input("Select an option: ")

        if choice == "1":
            pwd = input("Enter password to analyze: ")
            
            # Check Reuse
            if db.check_reuse(pwd):
                print("⚠️ WARNING: This password has been used before!")

            # Analyze
            analyzer = PasswordAnalyzer(pwd)
            results = analyzer.analyze()

            print(f"\n--- Results ---")
            print(f"Strength: {results['label']} (Entropy: {results['entropy']})")
            print("Feedback:")
            for item in results['feedback']:
                print(f"  - {item}")
            
            save = input("Save to history? (y/n): ").lower()
            if save == 'y':
                db.save_password(pwd)
                print("✅ Saved securely to database.")

        elif choice == "2":
            length = int(input("Enter desired length (e.g., 16): "))
            new_pwd = generate_strong_password(length)
            print(f"\n🔐 Suggested Password: {new_pwd}")
            print("Tip: Memorize this or use a password manager.")

        elif choice == "3":
            # NEW: Show Database Status
            print("\n--- Database Status ---")
            status = db.get_status()
            
            print(f"Status: {status['status']}")
            print(f"Message: {status['message']}")
            print(f"Table Exists: {status['table_exists']}")
            print(f"Total Passwords Saved: {status['total_passwords']}")
            
            if status['recent_entries']:
                print("\n--- Recent Entries (Last 3) ---")
                for idx, (hsh, date) in enumerate(status['recent_entries'], 1):
                    print(f"  {idx}. Hash: {hsh[:16]}... | Date: {date}")

        elif choice == "4":
            print("Goodbye!")
            db.close()
            break

if __name__ == "__main__":
    main()