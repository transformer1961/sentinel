"""
Gmail Diagnostic Script - Debug Email Authentication Issues
"""

import os
import sys
import smtplib
from dotenv import load_dotenv

load_dotenv()

SENTINEL_EMAIL = os.getenv('SENTINEL_EMAIL')
SENTINEL_EMAIL_PASS = os.getenv('SENTINEL_EMAIL_PASS')

def diagnose():
    """Run diagnostic checks"""
    
    print("\n" + "="*60)
    print("GMAIL AUTHENTICATION DIAGNOSTIC")
    print("="*60)
    
    # 1. Check environment
    print("\n1️⃣  ENVIRONMENT CHECK:")
    print(f"   Email: {SENTINEL_EMAIL}")
    print(f"   Password Length: {len(SENTINEL_EMAIL_PASS)} chars")
    print(f"   Password (visible): {SENTINEL_EMAIL_PASS}")
    
    # 2. Check for common issues
    print("\n2️⃣  PASSWORD ANALYSIS:")
    if ' ' in SENTINEL_EMAIL_PASS:
        print("   ⚠️  WARNING: Password contains spaces!")
        print(f"   Raw: '{SENTINEL_EMAIL_PASS}'")
    else:
        print("   ✅ No spaces detected")
    
    if SENTINEL_EMAIL_PASS.startswith(' ') or SENTINEL_EMAIL_PASS.endswith(' '):
        print("   ⚠️  WARNING: Leading/trailing whitespace!")
    else:
        print("   ✅ No leading/trailing whitespace")
    
    print(f"   First 4 chars: {SENTINEL_EMAIL_PASS[:4]}")
    print(f"   Last 4 chars: {SENTINEL_EMAIL_PASS[-4:]}")
    
    # 3. Check email format
    print("\n3️⃣  EMAIL CHECK:")
    if '@gmail.com' in SENTINEL_EMAIL:
        print("   ✅ Valid Gmail address")
    else:
        print(f"   ⚠️  Not a Gmail address: {SENTINEL_EMAIL}")
    
    # 4. Test connection
    print("\n4️⃣  CONNECTION TEST:")
    try:
        print("   Connecting to smtp.gmail.com:587...")
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        print("   ✅ Connected")
        
        print("   Starting TLS...")
        server.starttls()
        print("   ✅ TLS started")
        
        # 5. Attempt login with detailed error
        print("\n5️⃣  LOGIN ATTEMPT:")
        print(f"   Email: {SENTINEL_EMAIL}")
        print(f"   Password: {SENTINEL_EMAIL_PASS}")
        
        try:
            server.login(SENTINEL_EMAIL, SENTINEL_EMAIL_PASS)
            print("   ✅ LOGIN SUCCESSFUL!")
            server.quit()
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"   ❌ Authentication Error: {e}")
            print("\n   TROUBLESHOOTING STEPS:")
            print("   1. Go to: https://myaccount.google.com/apppasswords")
            print("   2. Generate a NEW app password (copy carefully)")
            print("   3. Delete old passwords from the list")
            print("   4. Paste EXACTLY as shown (no edits)")
            print("   5. Update .env file")
            print("   6. Save .env")
            print("   7. Run this script again")
            server.quit()
            return False
            
        except smtplib.SMTPException as e:
            print(f"   ❌ SMTP Error: {e}")
            server.quit()
            return False
            
    except Exception as e:
        print(f"   ❌ Connection Error: {e}")
        return False

def check_env_file():
    """Check .env file directly"""
    print("\n6️⃣  .ENV FILE CHECK:")
    
    if not os.path.exists('.env'):
        print("   ❌ .env file not found!")
        return False
    
    print("   ✅ .env file exists")
    
    # Read the raw file
    with open('.env', 'r') as f:
        lines = f.readlines()
    
    for line in lines:
        if 'SENTINEL_EMAIL_PASS' in line:
            print(f"   Raw line: {repr(line)}")
            if '=' in line:
                key, value = line.split('=', 1)
                value = value.strip()
                print(f"   Value: {repr(value)}")
                print(f"   Length: {len(value)}")
    
    return True

if __name__ == "__main__":
    check_env_file()
    success = diagnose()
    
    if success:
        print("\n" + "="*60)
        print("✅ EMAIL CONFIGURATION IS WORKING!")
        print("="*60)
        sys.exit(0)
    else:
        print("\n" + "="*60)
        print("❌ EMAIL CONFIGURATION HAS ISSUES")
        print("="*60)
        sys.exit(1)