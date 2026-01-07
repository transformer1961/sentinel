"""
Gmail Email Testing Script for Discord Security Bot
Run this to verify your email configuration works correctly
"""

import os
import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get email credentials
SENTINEL_EMAIL = os.getenv('SENTINEL_EMAIL')
SENTINEL_EMAIL_PASS = os.getenv('SENTINEL_EMAIL_PASS')

def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60)

def check_env_variables():
    """Check if environment variables are set"""
    print_section("Checking Environment Variables")
    
    if not SENTINEL_EMAIL:
        print("❌ SENTINEL_EMAIL not found in .env")
        return False
    else:
        print(f"✅ SENTINEL_EMAIL: {SENTINEL_EMAIL}")
    
    if not SENTINEL_EMAIL_PASS:
        print("❌ SENTINEL_EMAIL_PASS not found in .env")
        return False
    else:
        # Don't print the full password, just show it's there
        print(f"✅ SENTINEL_EMAIL_PASS: {'*' * len(SENTINEL_EMAIL_PASS)} ({len(SENTINEL_EMAIL_PASS)} chars)")
    
    return True

def validate_email_format(email):
    """Validate email format"""
    if '@' not in email or '.' not in email:
        print(f"❌ Invalid email format: {email}")
        return False
    print(f"✅ Email format is valid: {email}")
    return True

def test_smtp_connection():
    """Test SMTP connection to Gmail"""
    print_section("Testing SMTP Connection")
    
    try:
        print("Connecting to smtp.gmail.com:587...")
        server = smtplib.SMTP('smtp.gmail.com', 587, timeout=10)
        print("✅ Connected successfully!")
        
        print("Starting TLS encryption...")
        server.starttls()
        print("✅ TLS encryption started!")
        
        return server
    except smtplib.SMTPException as e:
        print(f"❌ SMTP Error: {e}")
        return None
    except TimeoutError:
        print("❌ Connection timeout - check firewall/internet connection")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return None

def test_login(server):
    """Test Gmail login with App Password"""
    print_section("Testing Gmail Authentication")
    
    try:
        print(f"Attempting login with: {SENTINEL_EMAIL}")
        server.login(SENTINEL_EMAIL, SENTINEL_EMAIL_PASS)
        print("✅ Login successful!")
        return True
    except smtplib.SMTPAuthenticationError:
        print("❌ Authentication failed!")
        print("\nPossible causes:")
        print("  1. Wrong App Password (must be 16 characters)")
        print("  2. Using Gmail password instead of App Password")
        print("  3. 2-Factor Authentication not enabled")
        print("  4. Email address is incorrect")
        print("\nSolution: https://support.google.com/accounts/answer/185833")
        return False
    except Exception as e:
        print(f"❌ Login error: {e}")
        return False

def send_test_email(server, recipient_email):
    """Send a test email"""
    print_section("Sending Test Email")
    
    try:
        # Create email
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Sentinel Security Bot <{SENTINEL_EMAIL}>"
        msg['To'] = recipient_email
        msg['Subject'] = "🧪 Sentinel Bot - Email Test"
        
        # Plain text version
        text = """
Hello,

This is a test email from Sentinel Security Bot!

If you're seeing this, your email configuration is working correctly.

Server: Test Email
Time: Test

---
This is an automated message from Sentinel Security Bot.
        """
        
        # HTML version
        html = """
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #27ae60;">🧪 Sentinel Bot Email Test</h2>
            <p>Hello,</p>
            <p>This is a test email from <strong>Sentinel Security Bot</strong>!</p>
            <p style="color: #27ae60;"><strong>If you're seeing this, your email configuration is working correctly!</strong></p>
            
            <hr>
            <p><strong>Test Details:</strong></p>
            <ul>
                <li>From: """ + SENTINEL_EMAIL + """</li>
                <li>To: """ + recipient_email + """</li>
                <li>Status: ✅ Successfully Sent</li>
            </ul>
            <hr>
            
            <p style="color: #7f8c8d; font-size: 12px;">
                This is an automated test message from Sentinel Security Bot.<br>
                Your email configuration is ready for production use!
            </p>
        </body>
        </html>
        """
        
        # Attach both versions
        text_part = MIMEText(text, 'plain')
        html_part = MIMEText(html, 'html')
        msg.attach(text_part)
        msg.attach(html_part)
        
        # Send email
        print(f"Sending email to: {recipient_email}")
        server.send_message(msg)
        print("✅ Email sent successfully!")
        print("\nCheck your inbox (and spam folder) for the test email.")
        return True
        
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

def close_connection(server):
    """Close SMTP connection"""
    try:
        server.quit()
        print("✅ Connection closed")
    except:
        pass

def main():
    """Run all tests"""
    print("\n")
    print("╔" + "="*58 + "╗")
    print("║" + " "*58 + "║")
    print("║" + "  SENTINEL SECURITY BOT - EMAIL TEST SCRIPT".center(58) + "║")
    print("║" + " "*58 + "║")
    print("╚" + "="*58 + "╝")
    
    # Step 1: Check environment variables
    if not check_env_variables():
        print_section("Setup Failed")
        print("Please configure .env file with:")
        print("  SENTINEL_EMAIL=your_email@gmail.com")
        print("  SENTINEL_EMAIL_PASS=your_16_char_app_password")
        sys.exit(1)
    
    # Step 2: Validate email format
    if not validate_email_format(SENTINEL_EMAIL):
        sys.exit(1)
    
    # Step 3: Test SMTP connection
    server = test_smtp_connection()
    if not server:
        sys.exit(1)
    
    # Step 4: Test login
    if not test_login(server):
        close_connection(server)
        sys.exit(1)
    
    # Step 5: Get recipient email
    print_section("Recipient Email")
    recipient = input("Enter recipient email address (or press Enter to use sender): ").strip()
    if not recipient:
        recipient = SENTINEL_EMAIL
    
    if not validate_email_format(recipient):
        close_connection(server)
        sys.exit(1)
    
    # Step 6: Send test email
    if not send_test_email(server, recipient):
        close_connection(server)
        sys.exit(1)
    
    # Step 7: Close connection
    print_section("Closing Connection")
    close_connection(server)
    
    # Final summary
    print_section("✅ All Tests Passed!")
    print("""
Your email configuration is working correctly!

Next steps:
1. Check your inbox for the test email
2. Check spam folder if not found
3. Your bot is ready to send security alerts

To enable email alerts in your Discord bot:
  /set_admin_email your@email.com

This will make you receive alerts for:
  • Critical security breaches
  • Mass actions (deletions, bans)
  • Threat level changes
  • Quarantine actions
    """)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Test cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)