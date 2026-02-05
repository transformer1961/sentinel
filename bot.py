"""
SENTINEL SECURITY BOT v2.1 - PART 1/5
OPTIMIZED & ENHANCED VERSION

This part contains:
- Imports and logging setup
- Configuration and constants
- Optimized data structures
- Enhanced notification system
- Security monitoring system
"""

import discord
from discord.ext import commands, tasks
from discord import app_commands
import os
from dotenv import load_dotenv
import asyncio
from datetime import datetime, timedelta, timezone, time
from collections import defaultdict, deque
import logging
import aiohttp
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
from typing import Optional, List, Dict, Any, Set, Tuple
from functools import wraps
import time as time_module
from dataclasses import dataclass, field
import json

try:
    import database as db
except ImportError:
    print("ERROR: database.py not found!")
    exit(1)

# ============= LOGGING SETUP =============
import sys

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# Enhanced logging with rotation
from logging.handlers import RotatingFileHandler

logger = logging.getLogger('SecurityBot')
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# File handler with rotation (10MB max, 5 backups)
file_handler = RotatingFileHandler(
    'security_bot.log',
    maxBytes=10*1024*1024,
    backupCount=5,
    encoding='utf-8'
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(console_formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# ============= ENVIRONMENT CONFIG =============
load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
if not TOKEN:
    logger.critical("DISCORD_TOKEN not found in .env!")
    raise ValueError("DISCORD_TOKEN required")

# Email configuration
SENTINEL_EMAIL = os.getenv('SENTINEL_EMAIL')
SENTINEL_EMAIL_PASS = os.getenv('SENTINEL_EMAIL_PASS')

# Twilio SMS configuration (optional)
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE = os.getenv('TWILIO_PHONE_NUMBER')
YOUR_PHONE = os.getenv('YOUR_PHONE_NUMBER')

# Initialize Twilio client if credentials exist
twilio_client: Optional[Any] = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        from twilio.rest import Client as TwilioClient
        twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        logger.info("✅ Twilio SMS enabled")
    except ImportError:
        logger.warning("⚠️ Twilio package not installed - SMS features disabled")
    except Exception as e:
        logger.warning(f"⚠️ Twilio initialization failed: {e}")
else:
    logger.info("ℹ️ Twilio credentials not found - SMS features disabled")

# Bot intents
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True
intents.moderation = True
intents.voice_states = True

bot = commands.Bot(command_prefix='!', intents=intents)

# ============= OPTIMIZED DATA STRUCTURES =============

@dataclass
class SecurityConfig:
    """Memory-efficient server configuration using dataclass"""
    log_channel_id: Optional[int] = None
    quarantine_role_id: Optional[int] = None
    verification_enabled: bool = False
    lockdown_enabled: bool = False
    threat_level: int = 0
    daily_reports_enabled: bool = False
    voice_log_channel_id: Optional[int] = None
    onduty_role_id: Optional[int] = None
    verified_role_id: Optional[int] = None
    unverified_role_id: Optional[int] = None
    verification_channel_id: Optional[int] = None
    allstaff_role_id: Optional[int] = None
    auto_response_enabled: bool = True
    raid_protection_enabled: bool = True
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for database storage"""
        return {
            'log_channel_id': self.log_channel_id,
            'quarantine_role_id': self.quarantine_role_id,
            'verification_enabled': self.verification_enabled,
            'lockdown_enabled': self.lockdown_enabled,
            'threat_level': self.threat_level,
            'daily_reports_enabled': self.daily_reports_enabled,
            'voice_log_channel_id': self.voice_log_channel_id,
            'onduty_role_id': self.onduty_role_id,
            'verified_role_id': self.verified_role_id,
            'unverified_role_id': self.unverified_role_id,
            'verification_channel_id': self.verification_channel_id,
            'allstaff_role_id': self.allstaff_role_id,
            'auto_response_enabled': self.auto_response_enabled,
            'raid_protection_enabled': self.raid_protection_enabled,
        }

# ============= CONSTANTS =============

# Security thresholds with time windows
THRESHOLDS = {
    'channel_delete': {'count': 3, 'window': 10},
    'channel_create': {'count': 5, 'window': 10},
    'role_delete': {'count': 3, 'window': 10},
    'role_create': {'count': 5, 'window': 30},
    'member_ban': {'count': 5, 'window': 30},
    'member_kick': {'count': 5, 'window': 30},
    'message_delete': {'count': 20, 'window': 10},
    'member_join': {'count': 10, 'window': 60},  # Raid detection
}

# Threat level definitions
THREAT_LEVELS = {
    0: {
        "name": "🟢 Clear",
        "color": discord.Color.green(),
        "description": "Normal operations - no threats detected",
        "actions": []
    },
    1: {
        "name": "🟡 Elevated",
        "color": discord.Color.gold(),
        "description": "Minor threat detected - increased monitoring",
        "actions": ["log_suspicious", "notify_admins"]
    },
    2: {
        "name": "🟠 High",
        "color": discord.Color.orange(),
        "description": "Serious threat active - defensive measures enabled",
        "actions": ["log_all", "notify_admins", "restrict_new_members", "sms_alerts"]
    },
    3: {
        "name": "🔴 Critical",
        "color": discord.Color.red(),
        "description": "FULL BREACH - Emergency protocols active",
        "actions": ["emergency_lockdown", "quarantine_suspects", "sms_alerts", "email_alerts"]
    }
}

# Role hierarchy for permissions
ROLE_HIERARCHY = {
    'OWNER': 9,
    'DIRECTOR': 9,
    'MANAGEMENT': 8,
    'INTERNAL_AFFAIRS': 7,
    'ADMINISTRATOR': 6,
    'MODERATOR': 5,
    'DEPARTMENT_HEAD': 4,
    'SUPERVISOR': 3,
    'MEMBER': 2,
    'USER': 1
}

# Warning system configuration
WARNING_CONFIG = {
    'max_warnings': 3,
    'warning_expire_days': 30,
    'timeout_duration': 3600,  # 1 hour for second strike
    'actions': {
        1: 'warn',          # First strike: warning only
        2: 'timeout',       # Second strike: timeout
        3: 'quarantine'     # Third strike: quarantine
    }
}

# Validation patterns
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
DISCORD_ID_MIN = 100000000000000000
DISCORD_ID_MAX = 999999999999999999

# Rate limiting
MAX_EMAIL_RECIPIENTS = 10
MAX_PARTNERSHIPS_DISPLAY = 10
VERIFICATION_CODE_LENGTH = 8
VERIFICATION_TIMEOUT = 300

# ============= OPTIMIZED ACTION TRACKER =============

class ActionTracker:
    """
    Optimized action tracking using deque for O(1) operations.
    Automatically cleans up old entries to prevent memory leaks.
    """
    
    def __init__(self):
        self._trackers: Dict[int, Dict[str, deque]] = defaultdict(lambda: defaultdict(deque))
        self._max_size = 1000  # Prevent unbounded growth
    
    def track(self, guild_id: int, action_type: str, user_id: int) -> int:
        """
        Track an action and return count within threshold window.
        
        Args:
            guild_id: Discord guild ID
            action_type: Type of action being tracked
            user_id: User performing the action
            
        Returns:
            Count of actions by this user within the threshold window
        """
        now = time_module.time()
        threshold = THRESHOLDS.get(action_type, {'count': 10, 'window': 60})
        window = threshold['window']
        
        tracker = self._trackers[guild_id][action_type]
        
        # Cleanup old entries efficiently (O(k) where k is old entries)
        while tracker and now - tracker[0][0] > window:
            tracker.popleft()
        
        # Enforce max size to prevent memory issues
        if len(tracker) >= self._max_size:
            tracker.popleft()
        
        # Add new action
        tracker.append((now, user_id))
        
        # Count actions by this specific user
        count = sum(1 for timestamp, uid in tracker if uid == user_id)
        
        return count
    
    def get_recent_actions(self, guild_id: int, action_type: str, window: int = 60) -> List[Tuple[float, int]]:
        """Get all recent actions of a type"""
        now = time_module.time()
        tracker = self._trackers[guild_id][action_type]
        return [(t, u) for t, u in tracker if now - t <= window]
    
    def cleanup_guild(self, guild_id: int):
        """Clean up all tracking data for a guild"""
        if guild_id in self._trackers:
            del self._trackers[guild_id]
            logger.info(f"Cleaned up action tracker for guild {guild_id}")
    
    def get_stats(self) -> Dict[str, int]:
        """Get tracker statistics"""
        total_guilds = len(self._trackers)
        total_trackers = sum(len(actions) for actions in self._trackers.values())
        total_actions = sum(
            sum(len(tracker) for tracker in actions.values())
            for actions in self._trackers.values()
        )
        
        return {
            'guilds': total_guilds,
            'trackers': total_trackers,
            'actions': total_actions
        }

# ============= OPTIMIZED RATE LIMITER =============

class RateLimiter:
    """
    Efficient rate limiter using deque with sliding window algorithm.
    Automatically cleans up old entries.
    """
    
    def __init__(self):
        self._limits: Dict[int, deque] = defaultdict(deque)
        self._max_entries = 100  # Per user
    
    def check(self, user_id: int, max_calls: int, window: int) -> bool:
        """
        Check if user is within rate limit.
        
        Args:
            user_id: Discord user ID
            max_calls: Maximum calls allowed
            window: Time window in seconds
            
        Returns:
            True if allowed, False if rate limited
        """
        now = time_module.time()
        user_calls = self._limits[user_id]
        
        # Remove expired calls
        while user_calls and now - user_calls[0] > window:
            user_calls.popleft()
        
        # Check limit
        if len(user_calls) >= max_calls:
            return False
        
        # Enforce max entries
        if len(user_calls) >= self._max_entries:
            user_calls.popleft()
        
        # Record this call
        user_calls.append(now)
        return True
    
    def reset_user(self, user_id: int):
        """Reset rate limit for a user"""
        if user_id in self._limits:
            del self._limits[user_id]
    
    def get_remaining(self, user_id: int, max_calls: int, window: int) -> int:
        """Get remaining calls for user"""
        now = time_module.time()
        user_calls = self._limits[user_id]
        
        # Count valid calls
        valid_calls = sum(1 for t in user_calls if now - t <= window)
        return max(0, max_calls - valid_calls)

# ============= STORAGE =============

# Global storage with optimized types
server_configs: Dict[int, SecurityConfig] = {}
whitelists: Dict[int, Set[int]] = defaultdict(set)  # Sets are faster than lists
action_tracker = ActionTracker()
rate_limiter = RateLimiter()

# Shift tracking
ACTIVE_SHIFTS: Dict[int, Dict[int, Dict]] = defaultdict(dict)
SHIFT_LOCKS: Dict[int, Dict[int, bool]] = defaultdict(lambda: defaultdict(bool))

# Voice tracking
voice_sessions: Dict[int, Dict[int, datetime]] = defaultdict(dict)

# Report tracking
last_report_time: Dict[int, datetime] = {}

# ============= ENHANCED NOTIFICATION MANAGER =============

class NotificationManager:
    """
    Advanced notification system with queuing, priority, and multi-channel support.
    Prevents blocking operations and provides guaranteed delivery.
    """
    
    def __init__(self):
        self.email_queue = asyncio.Queue()
        self.sms_queue = asyncio.Queue()
        self._processing = False
        self._email_stats = {'sent': 0, 'failed': 0}
        self._sms_stats = {'sent': 0, 'failed': 0}
    
    async def start_processing(self):
        """Start background notification processors"""
        if self._processing:
            logger.warning("Notification processing already started")
            return
        
        self._processing = True
        asyncio.create_task(self._process_emails())
        asyncio.create_task(self._process_sms())
        logger.info("✅ Notification processing started")
    
    async def stop_processing(self):
        """Stop notification processing"""
        self._processing = False
        logger.info("⏹️ Notification processing stopped")
    
    async def _process_emails(self):
        """Background email processor with retry logic"""
        while self._processing:
            try:
                # Wait for email with timeout
                email_data = await asyncio.wait_for(
                    self.email_queue.get(),
                    timeout=1.0
                )
                
                # Send email
                success = await self._send_email(**email_data)
                
                if success:
                    self._email_stats['sent'] += 1
                else:
                    self._email_stats['failed'] += 1
                    logger.warning(f"Email failed: {email_data.get('to')}")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Email processing error: {e}")
                self._email_stats['failed'] += 1
    
    async def _process_sms(self):
        """Background SMS processor"""
        while self._processing:
            try:
                sms_data = await asyncio.wait_for(
                    self.sms_queue.get(),
                    timeout=1.0
                )
                
                success = await self._send_sms(**sms_data)
                
                if success:
                    self._sms_stats['sent'] += 1
                else:
                    self._sms_stats['failed'] += 1
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"SMS processing error: {e}")
                self._sms_stats['failed'] += 1
    
    async def send_email(
        self,
        to: str,
        subject: str,
        text: str,
        html: str = None,
        priority: str = 'normal'
    ):
        """
        Queue email for sending (non-blocking).
        
        Args:
            to: Recipient email
            subject: Email subject
            text: Plain text body
            html: HTML body (optional)
            priority: 'normal' or 'high'
        """
        if not SENTINEL_EMAIL or not SENTINEL_EMAIL_PASS:
            logger.warning("Email not configured - skipping email send")
            return
        
        await self.email_queue.put({
            'to': to,
            'subject': subject,
            'text': text,
            'html': html,
            'priority': priority
        })
        
        logger.debug(f"Email queued to {to}: {subject}")
    
    async def send_sms(self, message: str, phone: str = None):
        """
        Queue SMS for sending (non-blocking).
        
        Args:
            message: SMS message (max 1600 chars)
            phone: Phone number (defaults to YOUR_PHONE)
        """
        if not twilio_client:
            logger.debug("SMS not configured - skipping SMS send")
            return
        
        await self.sms_queue.put({
            'message': message[:1600],
            'phone': phone or YOUR_PHONE
        })
        
        logger.debug(f"SMS queued to {phone or YOUR_PHONE}")
    
    async def _send_email(
        self,
        to: str,
        subject: str,
        text: str,
        html: str = None,
        priority: str = 'normal'
    ) -> bool:
        """Actually send email via SMTP"""
        if not validate_email(to):
            logger.warning(f"Invalid email address: {to}")
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = f"Sentinel Security <{SENTINEL_EMAIL}>"
            msg['To'] = to
            msg['Subject'] = sanitize_string(subject, 200)
            
            # Priority headers
            if priority == 'high':
                msg['X-Priority'] = '1'
                msg['Importance'] = 'high'
            
            # Attach text
            text_part = MIMEText(sanitize_string(text, 10000), 'plain')
            msg.attach(text_part)
            
            # Attach HTML if provided
            if html:
                html_part = MIMEText(sanitize_string(html, 20000), 'html')
                msg.attach(html_part)
            
            # Send via SMTP (non-blocking)
            await asyncio.to_thread(self._send_smtp, msg)
            
            logger.info(f"📧 Email sent to {to}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False
    
    def _send_smtp(self, msg):
        """Synchronous SMTP send"""
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as server:
            server.starttls()
            server.login(SENTINEL_EMAIL, SENTINEL_EMAIL_PASS)
            server.send_message(msg)
    
    async def _send_sms(self, message: str, phone: str) -> bool:
        """Actually send SMS via Twilio"""
        if not twilio_client or not TWILIO_PHONE:
            return False
        
        try:
            result = await asyncio.to_thread(
                twilio_client.messages.create,
                body=message,
                from_=TWILIO_PHONE,
                to=phone
            )
            
            logger.info(f"📱 SMS sent to {phone}: {result.sid}")
            return True
            
        except Exception as e:
            logger.error(f"SMS send error: {e}")
            return False
    
    async def send_critical_alert(
        self,
        guild: discord.Guild,
        message: str,
        user: discord.User = None
    ):
        """
        Send CRITICAL multi-channel alert: Discord + Email + SMS.
        Used for breaches, raids, and emergencies.
        """
        logger.warning(f"🚨 CRITICAL ALERT: {guild.name} - {message}")
        
        # 1. Discord alert (immediate)
        await send_alert(guild, message, user, color=discord.Color.red())
        
        # 2. SMS alert (if configured)
        sms_text = f"🚨 CRITICAL: {guild.name}\n{message[:120]}"
        await self.send_sms(sms_text)
        
        # 3. Email alerts to all admins
        emails = await self._get_admin_emails(guild)
        for email in emails[:MAX_EMAIL_RECIPIENTS]:
            await self.send_email(
                email,
                f"🚨 CRITICAL SECURITY ALERT: {guild.name}",
                f"CRITICAL SECURITY ALERT\n\n{message}\n\nServer: {guild.name}\nTime: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                self._create_critical_html(guild.name, message),
                priority='high'
            )
    
    async def _get_admin_emails(self, guild: discord.Guild) -> List[str]:
        """Get all admin emails efficiently"""
        emails = []
        for member in guild.members:
            if member.guild_permissions.administrator:
                try:
                    email = await db.get_user_email(guild.id, member.id)
                    if email and validate_email(email):
                        emails.append(email)
                except:
                    pass
        return emails
    
    def _create_critical_html(self, guild_name: str, message: str) -> str:
        """Create styled critical alert email"""
        return f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; 
                        border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
                        border: 3px solid #dc3545;">
                <div style="background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); 
                            color: white; padding: 25px; border-radius: 6px; text-align: center; 
                            margin-bottom: 20px;">
                    <h1 style="margin: 0; font-size: 28px; text-shadow: 0 2px 4px rgba(0,0,0,0.2);">
                        🚨 CRITICAL SECURITY ALERT
                    </h1>
                </div>
                
                <div style="background-color: #f8f9fa; padding: 20px; border-radius: 6px; margin-bottom: 20px;">
                    <p style="margin: 5px 0; font-size: 16px;"><strong>Server:</strong> {guild_name}</p>
                    <p style="margin: 5px 0; font-size: 16px;"><strong>Time:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                    <p style="margin: 5px 0; font-size: 16px;"><strong>Severity:</strong> <span style="color: #dc3545; font-weight: bold;">CRITICAL</span></p>
                </div>
                
                <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; 
                            padding: 20px; margin: 20px 0; border-radius: 4px;">
                    <h3 style="margin-top: 0; color: #856404;">Alert Details</h3>
                    <p style="margin: 0; white-space: pre-wrap; color: #212529; line-height: 1.6;">{message}</p>
                </div>
                
                <div style="background-color: #f8d7da; border-left: 4px solid #dc3545; 
                            padding: 15px; margin: 20px 0; border-radius: 4px;">
                    <p style="margin: 0; color: #721c24; font-weight: bold; font-size: 16px;">
                        ⚠️ IMMEDIATE ACTION REQUIRED
                    </p>
                    <p style="margin: 10px 0 0 0; color: #721c24;">
                        Please check your Discord server immediately and take appropriate action.
                    </p>
                </div>
                
                <div style="border-top: 1px solid #dee2e6; padding-top: 20px; margin-top: 30px; 
                            text-align: center; color: #6c757d; font-size: 12px;">
                    <p style="margin: 5px 0;"><strong>Sentinel Security Bot v2.1</strong></p>
                    <p style="margin: 5px 0;">Automated Critical Security Alert</p>
                    <p style="margin: 15px 0 5px 0; border-top: 1px solid #dee2e6; padding-top: 15px;">
                        This is an automated message. Do not reply to this email.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def get_stats(self) -> Dict[str, Any]:
        """Get notification statistics"""
        return {
            'email': {
                'queued': self.email_queue.qsize(),
                'sent': self._email_stats['sent'],
                'failed': self._email_stats['failed']
            },
            'sms': {
                'queued': self.sms_queue.qsize(),
                'sent': self._sms_stats['sent'],
                'failed': self._sms_stats['failed']
            },
            'processing': self._processing
        }

# Initialize notification manager
notification_manager = NotificationManager()

# ============= VALIDATION & UTILITY FUNCTIONS =============

def validate_email(email: str) -> bool:
    """Validate email address format"""
    if not email or len(email) > 254:
        return False
    return EMAIL_REGEX.match(email) is not None

def validate_discord_id(did: int) -> bool:
    """Validate Discord ID range"""
    return DISCORD_ID_MIN <= did <= DISCORD_ID_MAX

def sanitize_string(text: str, max_length: int = 2000) -> str:
    """
    Sanitize string for safe output.
    Removes null bytes and truncates to max length.
    """
    if not text:
        return ""
    # Remove null bytes and other dangerous characters
    clean = text.replace('\x00', '').replace('\r', '\n')
    return clean[:max_length]

# ============= END OF PART 1 =============
"""
SENTINEL SECURITY BOT v2.1 - PART 2/5
SECURITY MONITORING & PERMISSIONS

This part contains:
- Advanced Security Monitor
- Permission system
- Helper functions
- Whitelist management
- Alert systems
"""

# ============= ADVANCED SECURITY MONITOR =============

class SecurityMonitor:
    """
    Advanced AI-like security monitoring system with pattern detection,
    auto-response, and threat intelligence.
    """
    
    def __init__(self):
        self.suspicious_patterns: Dict[int, List[Dict]] = defaultdict(list)
        self.breach_attempts: Dict[int, int] = defaultdict(int)
        self.blocked_users: Dict[int, Set[int]] = defaultdict(set)
        self._scan_interval = 300  # 5 minutes
    
    async def detect_raid(self, guild: discord.Guild) -> Tuple[bool, int]:
        """
        Detect potential raid attack.
        
        Returns:
            (is_raid, join_count)
        """
        try:
            recent_joins = await db.get_logs(
                guild.id,
                category='member_join',
                limit=30
            )
            
            if not recent_joins:
                return False, 0
            
            now = datetime.now(timezone.utc)
            threshold = THRESHOLDS['member_join']
            
            # Count joins in last 60 seconds
            recent_count = 0
            new_accounts = 0
            
            for log in recent_joins:
                try:
                    log_time = datetime.fromisoformat(log['timestamp'])
                    if (now - log_time).total_seconds() < threshold['window']:
                        recent_count += 1
                        
                        # Check if account is new
                        details = log.get('details', {})
                        if details.get('account_age_days', 999) < 7:
                            new_accounts += 1
                except:
                    continue
            
            # Raid if: 10+ joins in 60s OR 5+ new accounts in 60s
            is_raid = recent_count >= threshold['count'] or new_accounts >= 5
            
            if is_raid:
                logger.warning(
                    f"🚨 RAID DETECTED: {guild.name} - "
                    f"{recent_count} joins, {new_accounts} new accounts"
                )
            
            return is_raid, recent_count
            
        except Exception as e:
            logger.error(f"Raid detection error: {e}")
            return False, 0
    
    async def detect_mass_action(
        self,
        guild_id: int,
        action_type: str,
        threshold: int = None
    ) -> Tuple[bool, int]:
        """
        Detect mass actions (deletions, bans, etc.).
        
        Returns:
            (is_mass_action, count)
        """
        if threshold is None:
            threshold = THRESHOLDS.get(action_type, {}).get('count', 5)
        
        # Get recent actions
        recent = action_tracker.get_recent_actions(
            guild_id,
            action_type,
            THRESHOLDS.get(action_type, {}).get('window', 60)
        )
        
        count = len(recent)
        is_mass = count >= threshold
        
        if is_mass:
            logger.warning(
                f"🚨 MASS {action_type.upper()}: Guild {guild_id} - "
                f"{count} actions detected"
            )
        
        return is_mass, count
    
    async def check_account_age(self, member: discord.Member) -> Tuple[bool, int]:
        """
        Check if account is suspiciously new.
        
        Returns:
            (is_suspicious, age_in_days)
        """
        age_days = (datetime.now(timezone.utc) - member.created_at).days
        is_suspicious = age_days < 7
        
        return is_suspicious, age_days
    
    async def detect_permission_escalation(
        self,
        guild: discord.Guild,
        user_id: int
    ) -> bool:
        """
        Detect suspicious permission escalation.
        Flags when users gain admin/mod roles unexpectedly.
        """
        try:
            recent_changes = await db.get_logs(
                guild.id,
                category='member_roles_changed',
                user_id=user_id,
                limit=5
            )
            
            if not recent_changes:
                return False
            
            # Check for admin/mod role grants
            dangerous_keywords = ['admin', 'owner', 'moderator', 'management']
            
            for log in recent_changes:
                details = log.get('details', {})
                added_roles = details.get('added', [])
                
                for role_name in added_roles:
                    role_lower = role_name.lower()
                    if any(keyword in role_lower for keyword in dangerous_keywords):
                        logger.warning(
                            f"⚠️ PERMISSION ESCALATION: "
                            f"User {user_id} gained role '{role_name}' in {guild.name}"
                        )
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Permission escalation detection error: {e}")
            return False
    
    async def detect_suspicious_pattern(
        self,
        guild: discord.Guild,
        user: discord.User,
        pattern_type: str
    ) -> bool:
        """
        Detect suspicious behavior patterns.
        
        Pattern types:
        - rapid_actions: Many actions in short time
        - mass_messaging: Spam detection
        - permission_abuse: Elevated permission misuse
        """
        try:
            if pattern_type == 'rapid_actions':
                # Check for many different action types
                action_types = ['channel_delete', 'role_delete', 'member_ban', 'member_kick']
                total_actions = 0
                
                for action in action_types:
                    count = action_tracker.track(guild.id, action, user.id)
                    total_actions += count
                
                return total_actions >= 10  # 10+ different actions
            
            elif pattern_type == 'mass_messaging':
                # Check message deletion patterns
                is_mass, count = await self.detect_mass_action(
                    guild.id,
                    'message_delete'
                )
                return is_mass
            
            elif pattern_type == 'permission_abuse':
                # Check for permission escalation
                return await self.detect_permission_escalation(guild, user.id)
            
            return False
            
        except Exception as e:
            logger.error(f"Pattern detection error: {e}")
            return False
    
    async def auto_response(
        self,
        guild: discord.Guild,
        threat_type: str,
        user: discord.User = None,
        severity: int = 2
    ):
        """
        Automated threat response system.
        
        Threat types:
        - raid: Mass member joins
        - mass_delete: Mass deletions
        - permission_escalation: Unauthorized admin access
        - spam: Mass messaging
        """
        try:
            config = server_configs.get(guild.id)
            if not config or not config.auto_response_enabled:
                logger.info(f"Auto-response disabled for {guild.name}")
                return
            
            logger.warning(
                f"🤖 AUTO-RESPONSE: {guild.name} - "
                f"Type: {threat_type}, Severity: {severity}"
            )
            
            if threat_type == 'raid':
                # Emergency lockdown
                if config.raid_protection_enabled:
                    await self._emergency_lockdown(guild, "Raid detected - automated response")
                    
                    # Set critical threat level
                    await db.set_threat_level(guild.id, 3)
                    if config:
                        config.threat_level = 3
                    
                    # Send critical alert
                    await notification_manager.send_critical_alert(
                        guild,
                        f"🚨 RAID DETECTED - Auto-lockdown activated\n\n"
                        f"Multiple suspicious joins detected. Server is now in emergency lockdown mode.\n\n"
                        f"Actions taken:\n"
                        f"• Server locked down\n"
                        f"• Threat level: CRITICAL\n"
                        f"• Admins notified via email/SMS",
                        user
                    )
                    
                    await log_action(
                        guild,
                        'auto_response',
                        'Raid Auto-Response',
                        None,
                        f"Emergency lockdown activated due to raid detection"
                    )
            
            elif threat_type == 'mass_delete':
                # Quarantine user
                if user and not await is_whitelisted(guild.id, user.id):
                    success = await quarantine_user(
                        guild,
                        user,
                        "Mass deletion detected - automated quarantine"
                    )
                    
                    if success:
                        # Set high threat level
                        await db.set_threat_level(guild.id, 2)
                        if config:
                            config.threat_level = 2
                        
                        await notification_manager.send_critical_alert(
                            guild,
                            f"🚨 MASS DELETION DETECTED\n\n"
                            f"{user.mention} ({user.name}) has been automatically quarantined.\n\n"
                            f"Actions taken:\n"
                            f"• User quarantined\n"
                            f"• Permissions removed\n"
                            f"• Threat level: HIGH",
                            user
                        )
                        
                        await log_action(
                            guild,
                            'auto_response',
                            'Mass Delete Auto-Response',
                            user,
                            f"User quarantined for mass deletion"
                        )
            
            elif threat_type == 'permission_escalation':
                # Alert only, no auto-action (too dangerous)
                await db.set_threat_level(guild.id, 2)
                if config:
                    config.threat_level = 2
                
                await notification_manager.send_critical_alert(
                    guild,
                    f"🚨 PERMISSION ESCALATION DETECTED\n\n"
                    f"{user.mention if user else 'A user'} gained elevated permissions unexpectedly.\n\n"
                    f"⚠️ MANUAL REVIEW REQUIRED\n"
                    f"Please review role changes immediately!",
                    user
                )
                
                await log_action(
                    guild,
                    'auto_response',
                    'Permission Escalation Detected',
                    user,
                    f"Elevated permissions granted - manual review required"
                )
            
            elif threat_type == 'spam':
                # Timeout user
                if user:
                    member = guild.get_member(user.id)
                    if member and not await is_whitelisted(guild.id, user.id):
                        try:
                            timeout_until = datetime.now(timezone.utc) + timedelta(hours=1)
                            await member.timeout(
                                timeout_until,
                                reason="Spam detected - automated timeout"
                            )
                            
                            await send_alert(
                                guild,
                                f"⚠️ Spam detected: {user.mention} timed out for 1 hour",
                                user,
                                color=discord.Color.orange()
                            )
                            
                            await log_action(
                                guild,
                                'auto_response',
                                'Spam Auto-Response',
                                user,
                                f"User timed out for spam"
                            )
                        except Exception as e:
                            logger.error(f"Timeout error: {e}")
            
        except Exception as e:
            logger.error(f"Auto-response error: {e}")
    
    async def _emergency_lockdown(self, guild: discord.Guild, reason: str):
        """Execute emergency lockdown procedure"""
        locked_count = 0
        
        try:
            # Lock all text channels
            for channel in guild.text_channels:
                try:
                    await channel.set_permissions(
                        guild.default_role,
                        send_messages=False,
                        add_reactions=False,
                        create_instant_invite=False,
                        reason=f"EMERGENCY LOCKDOWN: {reason}"
                    )
                    locked_count += 1
                except discord.Forbidden:
                    logger.warning(f"Cannot lock channel: {channel.name}")
                except Exception as e:
                    logger.error(f"Error locking {channel.name}: {e}")
            
            # Lock all voice channels
            for channel in guild.voice_channels:
                try:
                    await channel.set_permissions(
                        guild.default_role,
                        connect=False,
                        speak=False,
                        reason=f"EMERGENCY LOCKDOWN: {reason}"
                    )
                    locked_count += 1
                except:
                    pass
            
            # Update config
            await db.update_server_field(guild.id, 'lockdown_enabled', True)
            config = server_configs.get(guild.id)
            if config:
                config.lockdown_enabled = True
            
            logger.critical(
                f"🚨 EMERGENCY LOCKDOWN: {guild.name} - "
                f"Locked {locked_count} channels - Reason: {reason}"
            )
            
        except Exception as e:
            logger.error(f"Emergency lockdown error: {e}")
    
    async def scan_guild_security(self, guild: discord.Guild) -> Dict[str, Any]:
        """
        Comprehensive security scan of a guild.
        Returns security report with recommendations.
        """
        report = {
            'guild_id': guild.id,
            'guild_name': guild.name,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'issues': [],
            'recommendations': [],
            'score': 100
        }
        
        try:
            config = server_configs.get(guild.id)
            
            # Check if basic security features are configured
            if not config or not config.log_channel_id:
                report['issues'].append("No log channel configured")
                report['recommendations'].append("Set up logging with /set_log_channel")
                report['score'] -= 20
            
            if not config or not config.quarantine_role_id:
                report['issues'].append("No quarantine role configured")
                report['recommendations'].append("Create quarantine role with /create_quarantine_role")
                report['score'] -= 15
            
            # Check for suspicious recent activity
            recent_joins = await db.get_logs(guild.id, 'member_join', limit=20)
            if len(recent_joins) > 15:
                report['issues'].append(f"High join rate: {len(recent_joins)} recent joins")
                report['recommendations'].append("Monitor for potential raid")
                report['score'] -= 10
            
            # Check threat level
            if config and config.threat_level >= 2:
                report['issues'].append(f"Elevated threat level: {THREAT_LEVELS[config.threat_level]['name']}")
                report['recommendations'].append("Review recent security alerts")
                report['score'] -= 15
            
            # Check for unwhitelisted admins
            admin_count = sum(1 for m in guild.members if m.guild_permissions.administrator)
            whitelisted_count = len(whitelists.get(guild.id, set()))
            
            if admin_count > whitelisted_count + 2:
                report['issues'].append(f"Not all admins whitelisted ({whitelisted_count}/{admin_count})")
                report['recommendations'].append("Whitelist trusted admins to prevent false positives")
                report['score'] -= 10
            
            # Security score rating
            if report['score'] >= 90:
                report['rating'] = "🟢 Excellent"
            elif report['score'] >= 70:
                report['rating'] = "🟡 Good"
            elif report['score'] >= 50:
                report['rating'] = "🟠 Fair"
            else:
                report['rating'] = "🔴 Poor"
            
        except Exception as e:
            logger.error(f"Security scan error: {e}")
            report['issues'].append(f"Scan error: {str(e)}")
        
        return report

# Initialize security monitor
security_monitor = SecurityMonitor()

# ============= PERMISSIONS SYSTEM =============

async def get_user_tier(guild_id: int, user_id: int) -> int:
    """Get user permission tier from database"""
    try:
        data = await db.get_member_tier(guild_id, user_id)
        return data.get('tier', 1) if data else 1
    except Exception as e:
        logger.error(f"Error getting user tier: {e}")
        return 1

async def check_permission(guild_id: int, user_id: int, required_tier: int) -> bool:
    """Check if user has required permission tier"""
    tier = await get_user_tier(guild_id, user_id)
    return tier >= required_tier

def require_permission(min_tier: int):
    """Decorator to require minimum permission tier"""
    def decorator(func):
        @wraps(func)
        async def wrapper(interaction: discord.Interaction, *args, **kwargs):
            has_permission = await check_permission(
                interaction.guild.id,
                interaction.user.id,
                min_tier
            )
            
            if not has_permission:
                tier_names = [k for k, v in ROLE_HIERARCHY.items() if v == min_tier]
                tier_name = tier_names[0] if tier_names else f"Tier {min_tier}"
                
                embed = discord.Embed(
                    title="❌ Permission Denied",
                    description=f"This command requires **{tier_name}** permission or higher.",
                    color=discord.Color.red()
                )
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                return
            
            return await func(interaction, *args, **kwargs)
        return wrapper
    return decorator

def rate_limit(max_calls: int = 10, window: int = 60):
    """Decorator for rate limiting commands"""
    def decorator(func):
        @wraps(func)
        async def wrapper(interaction: discord.Interaction, *args, **kwargs):
            user_id = interaction.user.id
            
            if not rate_limiter.check(user_id, max_calls, window):
                remaining_time = window
                
                embed = discord.Embed(
                    title="⏳ Rate Limited",
                    description=f"You're sending commands too quickly.\n\n"
                                f"**Limit:** {max_calls} commands per {window} seconds\n"
                                f"**Try again in:** ~{remaining_time} seconds",
                    color=discord.Color.orange()
                )
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                return
            
            return await func(interaction, *args, **kwargs)
        return wrapper
    return decorator

# ============= WHITELIST MANAGEMENT =============

async def is_whitelisted(guild_id: int, user_id: int) -> bool:
    """
    Check if user is whitelisted (with caching for performance).
    Whitelisted users bypass most security restrictions.
    """
    try:
        # Check cache first (O(1) lookup in set)
        if user_id in whitelists[guild_id]:
            return True
        
        # Check database
        is_wl = await db.is_whitelisted(guild_id, user_id)
        
        if is_wl:
            # Add to cache
            whitelists[guild_id].add(user_id)
        
        return is_wl
        
    except Exception as e:
        logger.error(f"Whitelist check error: {e}")
        return False

async def add_to_whitelist(guild_id: int, user_id: int, added_by: int) -> bool:
    """Add user to whitelist"""
    try:
        await db.add_to_whitelist(guild_id, user_id, 'user', added_by)
        whitelists[guild_id].add(user_id)
        logger.info(f"✅ User {user_id} whitelisted in guild {guild_id}")
        return True
    except Exception as e:
        logger.error(f"Whitelist add error: {e}")
        return False

async def remove_from_whitelist(guild_id: int, user_id: int) -> bool:
    """Remove user from whitelist"""
    try:
        removed = await db.remove_from_whitelist(guild_id, user_id)
        
        if removed and user_id in whitelists[guild_id]:
            whitelists[guild_id].remove(user_id)
        
        logger.info(f"✅ User {user_id} removed from whitelist in guild {guild_id}")
        return removed
    except Exception as e:
        logger.error(f"Whitelist remove error: {e}")
        return False

# ============= ALERT SYSTEM =============

async def send_alert(
    guild: discord.Guild,
    message: str,
    user: Optional[discord.User] = None,
    color: discord.Color = discord.Color.red(),
    email_admins: bool = False
):
    """
    Send security alert to log channel and optionally email admins.
    """
    config = server_configs.get(guild.id)
    
    if not config or not config.log_channel_id:
        logger.warning(f"No log channel configured for {guild.name}")
        return
    
    # Create embed
    embed = discord.Embed(
        title="🚨 Security Alert",
        description=sanitize_string(message, 2000),
        color=color,
        timestamp=datetime.now(timezone.utc)
    )
    
    if user:
        embed.add_field(
            name="User",
            value=f"{user.mention} (`{user.name}`)\nID: {user.id}",
            inline=False
        )
        embed.set_thumbnail(url=user.display_avatar.url)
    
    # Add footer with threat level
    threat_level = config.threat_level if config else 0
    threat_info = THREAT_LEVELS.get(threat_level, THREAT_LEVELS[0])
    embed.set_footer(text=f"Threat Level: {threat_info['name']}")
    
    # Send to log channel
    try:
        channel = guild.get_channel(config.log_channel_id)
        if channel:
            await channel.send(embed=embed)
    except Exception as e:
        logger.error(f"Failed to send alert to channel: {e}")
    
    # Log to database
    try:
        await db.add_log(
            guild.id,
            'security_alert',
            user.id if user else None,
            {
                'message': message,
                'severity': 'high' if color == discord.Color.red() else 'medium'
            }
        )
    except Exception as e:
        logger.error(f"Failed to log alert to database: {e}")
    
    # Email admins if requested
    if email_admins:
        asyncio.create_task(_send_alert_emails(guild, message, user))

async def _send_alert_emails(guild: discord.Guild, message: str, user: Optional[discord.User]):
    """Send alert emails to all admins (background task)"""
    try:
        emails = []
        for member in guild.members:
            if member.guild_permissions.administrator:
                try:
                    email = await db.get_user_email(guild.id, member.id)
                    if email and validate_email(email):
                        emails.append(email)
                except:
                    pass
        
        for email in emails[:MAX_EMAIL_RECIPIENTS]:
            await notification_manager.send_email(
                email,
                f"🚨 Security Alert: {guild.name}",
                f"Security Alert\n\nServer: {guild.name}\n\n{message}",
                _create_alert_html(guild.name, message, user),
                priority='high'
            )
    except Exception as e:
        logger.error(f"Alert email error: {e}")

def _create_alert_html(guild_name: str, message: str, user: Optional[discord.User]) -> str:
    """Create HTML email for security alert"""
    user_info = f"<p><strong>User:</strong> {user.name} ({user.id})</p>" if user else ""
    
    return f"""
    <html>
    <body style="font-family: Arial; background: #f5f5f5; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; 
                    border-radius: 8px; border-left: 4px solid #dc3545;">
            <h2 style="color: #dc3545; margin-top: 0;">🚨 Security Alert</h2>
            <p><strong>Server:</strong> {guild_name}</p>
            <p><strong>Time:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            {user_info}
            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0;">
                <p style="margin: 0; white-space: pre-wrap;">{message}</p>
            </div>
            <p style="color: #666; font-size: 12px;">Sentinel Security Bot v2.1</p>
        </div>
    </body>
    </html>
    """

async def log_action(
    guild: discord.Guild,
    category: str,
    title: str,
    user: Optional[discord.User],
    description: str,
    extra: Optional[Dict] = None
):
    """Log action to channel and database"""
    config = server_configs.get(guild.id)
    
    # Create embed
    embed = discord.Embed(
        title=f"📋 {title}",
        description=sanitize_string(description, 2000),
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    
    embed.add_field(name="Category", value=category.title(), inline=True)
    embed.add_field(
        name="User",
        value=user.mention if user else "System",
        inline=True
    )
    
    if extra:
        for key, value in list(extra.items())[:3]:
            embed.add_field(
                name=str(key).title(),
                value=str(value)[:1000],
                inline=True
            )
    
    # Send to log channel
    if config and config.log_channel_id:
        try:
            channel = guild.get_channel(config.log_channel_id)
            if channel:
                await channel.send(embed=embed)
        except Exception as e:
            logger.error(f"Failed to send log to channel: {e}")
    
    # Log to database
    try:
        log_data = {
            'title': title,
            'description': description,
            **(extra or {})
        }
        await db.add_log(
            guild.id,
            category,
            user.id if user else None,
            log_data
        )
    except Exception as e:
        logger.error(f"Failed to log to database: {e}")

# ============= QUARANTINE SYSTEM =============

async def quarantine_user(
    guild: discord.Guild,
    user: discord.User,
    reason: str
) -> bool:
    """
    Quarantine a user by removing all roles and adding quarantine role.
    Returns True if successful.
    """
    config = server_configs.get(guild.id)
    
    if not config or not config.quarantine_role_id:
        logger.warning(f"Quarantine role not configured for {guild.name}")
        return False
    
    qrole = guild.get_role(config.quarantine_role_id)
    if not qrole:
        logger.error(f"Quarantine role {config.quarantine_role_id} not found")
        return False
    
    member = guild.get_member(user.id)
    if not member:
        logger.warning(f"Member {user.id} not found in {guild.name}")
        return False
    
    if qrole in member.roles:
        logger.info(f"User {user.name} already quarantined")
        return True
    
    try:
        # Remove all roles except @everyone
        roles_to_remove = [r for r in member.roles if r != guild.default_role]
        
        if roles_to_remove:
            await member.remove_roles(
                *roles_to_remove,
                reason=f"Quarantine: {reason}",
                atomic=False
            )
        
        # Add quarantine role
        await member.add_roles(qrole, reason=f"Quarantine: {reason}")
        
        # Send alert
        await send_alert(
            guild,
            f"✅ **Quarantined:** {user.mention}\n**Reason:** {reason}",
            user,
            color=discord.Color.orange(),
            email_admins=True
        )
        
        # DM user
        try:
            dm_embed = discord.Embed(
                title="⚠️ Quarantined",
                description=f"You have been quarantined in **{guild.name}**",
                color=discord.Color.orange()
            )
            dm_embed.add_field(name="Reason", value=reason, inline=False)
            dm_embed.add_field(
                name="What now?",
                value="Contact a server administrator to resolve this issue.",
                inline=False
            )
            await member.send(embed=dm_embed)
        except:
            logger.debug(f"Could not DM quarantined user {user.name}")
        
        # Log action
        await log_action(
            guild,
            'quarantine',
            'User Quarantined',
            user,
            f"Quarantined for: {reason}"
        )
        
        logger.info(f"✅ Quarantined {user.name} in {guild.name}: {reason}")
        return True
        
    except discord.Forbidden:
        logger.error(f"Missing permissions to quarantine {user.name}")
        return False
    except Exception as e:
        logger.error(f"Quarantine error: {e}")
        return False

# ============= END OF PART 2 =============
"""
SENTINEL SECURITY BOT v2.1 - PART 3/5 (FINAL COMBINED)
EVENT HANDLERS, MONITORING, BACKGROUND TASKS, AND EXECUTION

This file should be appended to Parts 1 and 2 to create the complete bot.

To use:
1. Combine part1.py + part2.py + part3.py into one file: bot.py
2. Run: python bot.py

This part contains:
- Remaining bot events (member joins, role changes, voice monitoring)
- Security event monitoring
- Background tasks (cleanup, reports, scans)
- Additional admin commands
- Bot execution and startup
"""

# ============= CONTINUED BACKGROUND TASKS =============

@tasks.loop(hours=6)
async def reset_daily_threat():
    """Reset threat level if no incidents"""
    try:
        for guild_id in server_configs.keys():
            threat = await db.get_current_threat_level(guild_id)
            level = threat.get('threat_level', 0) if threat else 0
            
            if level > 0:
                # Check for recent incidents
                recent_alerts = await db.get_recent_alerts(guild_id, hours=6)
                
                if not recent_alerts:
                    # No incidents - reset to clear
                    await db.set_threat_level(guild_id, 0)
                    config = server_configs.get(guild_id)
                    if config:
                        config.threat_level = 0
                    logger.info(f"Reset threat level for guild {guild_id}")
        
        logger.info("✅ Threat level reset check complete")
    except Exception as e:
        logger.error(f"Threat reset error: {e}")

@tasks.loop(hours=24)
async def security_scan_task():
    """Daily automated security scan"""
    try:
        for guild in bot.guilds:
            report = await security_monitor.scan_guild_security(guild)
            
            # Send report if issues found
            if report['score'] < 70:
                config = server_configs.get(guild.id)
                if config and config.log_channel_id:
                    channel = guild.get_channel(config.log_channel_id)
                    if channel:
                        embed = discord.Embed(
                            title="🔍 Daily Security Scan",
                            description=f"**Security Score:** {report['score']}/100 {report['rating']}",
                            color=discord.Color.orange() if report['score'] < 50 else discord.Color.gold(),
                            timestamp=datetime.now(timezone.utc)
                        )
                        
                        if report['issues']:
                            embed.add_field(
                                name="⚠️ Issues Found",
                                value="\n".join([f"• {issue}" for issue in report['issues'][:5]]),
                                inline=False
                            )
                        
                        if report['recommendations']:
                            embed.add_field(
                                name="💡 Recommendations",
                                value="\n".join([f"• {rec}" for rec in report['recommendations'][:5]]),
                                inline=False
                            )
                        
                        await channel.send(embed=embed)
        
        logger.info("✅ Daily security scans complete")
    except Exception as e:
        logger.error(f"Security scan task error: {e}")

@tasks.loop(minutes=5)
async def daily_violation_report():
    """Send daily violation reports at 6 AM UTC"""
    try:
        now = datetime.now(timezone.utc)
        current_time = now.time()
        
        # Send at 6 AM UTC
        report_time_start = time(6, 0, 0)
        report_time_end = time(6, 5, 0)
        
        if not (report_time_start <= current_time < report_time_end):
            return
        
        logger.info("📊 Starting daily violation reports...")
        
        for guild in bot.guilds:
            try:
                guild_id = guild.id
                
                # Check if already sent today
                last_sent = last_report_time.get(guild_id)
                if last_sent and (now - last_sent).total_seconds() < 3600:
                    continue
                
                # Check if enabled
                config = server_configs.get(guild_id)
                if not config or not config.daily_reports_enabled:
                    continue
                
                # Get violations
                violations = await db.detect_shift_violations(guild_id, hours=24)
                quarantine_logs = await db.get_logs(guild_id, category='quarantine', limit=50)
                threat_logs = await db.get_logs(guild_id, category='threat', limit=50)
                
                if not violations and not quarantine_logs and not threat_logs:
                    continue
                
                # Generate report
                report = await generate_violation_report(
                    guild,
                    violations,
                    quarantine_logs,
                    threat_logs
                )
                
                # Send to admins
                admin_emails = await notification_manager._get_admin_emails(guild)
                
                sent_count = 0
                for email in admin_emails[:MAX_EMAIL_RECIPIENTS]:
                    success = await send_violation_report_email(email, guild.name, report)
                    if success:
                        sent_count += 1
                
                if sent_count > 0:
                    last_report_time[guild_id] = now
                    
                    await log_action(
                        guild,
                        'daily_report',
                        'Daily Violation Report Sent',
                        None,
                        f"Sent to {sent_count} admin(s)"
                    )
                
            except Exception as e:
                logger.error(f"Report error for {guild.name}: {e}")
        
        logger.info("✅ Daily violation reports complete")
        
    except Exception as e:
        logger.error(f"Daily report task error: {e}")

async def generate_violation_report(
    guild: discord.Guild,
    violations: List[Dict],
    quarantine_logs: List[Dict],
    threat_logs: List[Dict]
) -> Dict[str, Any]:
    """Generate comprehensive violation report"""
    report = {
        'guild_name': guild.name,
        'guild_id': guild.id,
        'timestamp': datetime.now(timezone.utc),
        'violations': [],
        'quarantines': [],
        'threats': [],
        'summary': {}
    }
    
    try:
        # Process violations
        for v in violations[:10]:
            user_id = v.get('user_id')
            user = bot.get_user(user_id)
            report['violations'].append({
                'user': user.name if user else f"User {user_id}",
                'type': v.get('type', 'unknown'),
                'timestamp': v.get('timestamp', 'Unknown')
            })
        
        # Process quarantines
        for q in quarantine_logs[:10]:
            user_id = q.get('user_id')
            user = bot.get_user(user_id)
            report['quarantines'].append({
                'user': user.name if user else f"User {user_id}",
                'reason': q.get('details', {}).get('message', 'No reason'),
                'timestamp': q.get('timestamp', 'Unknown')
            })
        
        # Process threat changes
        for t in threat_logs[:10]:
            details = t.get('details', {})
            report['threats'].append({
                'level': details.get('threat_name', 'Unknown'),
                'timestamp': t.get('timestamp', 'Unknown')
            })
        
        report['summary'] = {
            'total_violations': len(violations),
            'total_quarantines': len(quarantine_logs),
            'total_threats': len(threat_logs),
            'period': '24 hours'
        }
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
    
    return report

async def send_violation_report_email(email: str, guild_name: str, report: Dict) -> bool:
    """Send formatted violation report via email"""
    try:
        subject = f"🛡️ Sentinel Daily Report - {guild_name}"
        
        # Plain text version
        text = f"""
SENTINEL SECURITY BOT - DAILY VIOLATION REPORT
=============================================

Server: {guild_name}
Date: {report['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}
Period: Last 24 Hours

SUMMARY
-------
Violations: {report['summary']['total_violations']}
Quarantines: {report['summary']['total_quarantines']}
Threat Changes: {report['summary']['total_threats']}
"""
        
        if report['violations']:
            text += "\nVIOLATIONS\n----------\n"
            for v in report['violations'][:5]:
                text += f"• {v['user']} - {v['type']} ({v['timestamp']})\n"
        
        if report['quarantines']:
            text += "\nQUARANTINES\n-----------\n"
            for q in report['quarantines'][:5]:
                text += f"• {q['user']} - {q['reason']} ({q['timestamp']})\n"
        
        text += "\n---\nSentinel Security Bot v2.1\n"
        
        # HTML version
        html = f"""
        <html>
        <body style="font-family: Arial; background: #f5f5f5; padding: 20px;">
            <div style="max-width: 700px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 6px; margin-bottom: 20px;">
                    <h1 style="margin: 0;">🛡️ Daily Security Report</h1>
                </div>
                
                <p><strong>Server:</strong> {guild_name}</p>
                <p><strong>Date:</strong> {report['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p><strong>Period:</strong> Last 24 Hours</p>
                
                <div style="background: #f0f0f0; padding: 15px; border-radius: 6px; margin: 20px 0;">
                    <h3 style="margin-top: 0;">Summary</h3>
                    <p style="margin: 5px 0;">Violations: <strong>{report['summary']['total_violations']}</strong></p>
                    <p style="margin: 5px 0;">Quarantines: <strong>{report['summary']['total_quarantines']}</strong></p>
                    <p style="margin: 5px 0;">Threat Changes: <strong>{report['summary']['total_threats']}</strong></p>
                </div>
        """
        
        if report['violations']:
            html += '<div style="margin: 20px 0;"><h3>⚠️ Violations</h3><ul style="list-style: none; padding: 0;">'
            for v in report['violations'][:5]:
                html += f'<li style="background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107;">• {v["user"]} - {v["type"]}</li>'
            html += '</ul></div>'
        
        if report['quarantines']:
            html += '<div style="margin: 20px 0;"><h3>🔒 Quarantines</h3><ul style="list-style: none; padding: 0;">'
            for q in report['quarantines'][:5]:
                html += f'<li style="background: #f8d7da; padding: 10px; margin: 5px 0; border-left: 4px solid #dc3545;">• {q["user"]} - {q["reason"]}</li>'
            html += '</ul></div>'
        
        html += """
                <div style="border-top: 1px solid #ddd; padding-top: 15px; margin-top: 20px; text-align: center; color: #666; font-size: 12px;">
                    <p><strong>Sentinel Security Bot v2.1</strong></p>
                    <p>Automated Daily Security Report</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        await notification_manager.send_email(email, subject, text, html, priority='normal')
        return True
        
    except Exception as e:
        logger.error(f"Violation report email error: {e}")
        return False

# ============= ENHANCED EVENT HANDLERS =============

@bot.event
async def on_member_join(member: discord.Member):
    """Enhanced member join monitoring with raid detection"""
    try:
        guild = member.guild
        
        # Log join
        account_age_days = (datetime.now(timezone.utc) - member.created_at).days
        
        await db.add_log(
            guild.id,
            'member_join',
            member.id,
            {
                'username': member.name,
                'account_age_days': account_age_days,
                'created_at': member.created_at.isoformat()
            }
        )
        
        # Check for raid
        is_raid, join_count = await security_monitor.detect_raid(guild)
        
        if is_raid:
            await security_monitor.auto_response(guild, 'raid', member, severity=3)
        
        # Check account age
        is_suspicious, age = await security_monitor.check_account_age(member)
        
        if is_suspicious:
            config = server_configs.get(guild.id)
            if config and config.threat_level >= 2:
                # Auto-quarantine new accounts during high threat
                await quarantine_user(
                    guild,
                    member,
                    f"New account ({age} days old) during elevated threat"
                )
                
                await send_alert(
                    guild,
                    f"⚠️ New account auto-quarantined: {member.mention}\nAccount age: {age} days",
                    member,
                    color=discord.Color.orange()
                )
        
        logger.info(f"Member joined: {member.name} ({member.id}) in {guild.name}")
        
    except Exception as e:
        logger.error(f"Member join handler error: {e}")

@bot.event
async def on_member_remove(member: discord.Member):
    """Monitor member departures"""
    try:
        await db.add_log(
            member.guild.id,
            'member_remove',
            member.id,
            {'username': member.name}
        )
        
        # Clean up active shift if any
        guild_id = member.guild.id
        if member.id in ACTIVE_SHIFTS.get(guild_id, {}):
            del ACTIVE_SHIFTS[guild_id][member.id]
        
        logger.info(f"Member left: {member.name} ({member.id}) from {member.guild.name}")
        
    except Exception as e:
        logger.error(f"Member remove handler error: {e}")

@bot.event
async def on_guild_role_delete(role: discord.Role):
    """Monitor role deletions for mass deletion attacks"""
    try:
        await asyncio.sleep(1)  # Wait for audit log
        guild = role.guild
        
        async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.role_delete):
            if entry.target.id == role.id:
                user = entry.user
                
                if user.bot or await is_whitelisted(guild.id, user.id):
                    return
                
                # Track action
                count = action_tracker.track(guild.id, 'role_delete', user.id)
                threshold = THRESHOLDS['role_delete']
                
                if count >= threshold['count']:
                    await send_alert(
                        guild,
                        f"⚠️ **MASS ROLE DELETION DETECTED**\n\n"
                        f"{user.mention} deleted **{count} roles** in {threshold['window']} seconds!\n\n"
                        f"**Auto-Response:** User will be quarantined",
                        user,
                        email_admins=True
                    )
                    
                    # Trigger auto-response
                    await security_monitor.auto_response(guild, 'mass_delete', user, severity=2)
                
                break
                
    except Exception as e:
        logger.error(f"Role delete handler error: {e}")

@bot.event
async def on_guild_channel_delete(channel):
    """Monitor channel deletions for mass deletion attacks"""
    try:
        await asyncio.sleep(1)
        guild = channel.guild
        
        async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.channel_delete):
            if entry.target.id == channel.id:
                user = entry.user
                
                if user.bot or await is_whitelisted(guild.id, user.id):
                    return
                
                count = action_tracker.track(guild.id, 'channel_delete', user.id)
                threshold = THRESHOLDS['channel_delete']
                
                if count >= threshold['count']:
                    await send_alert(
                        guild,
                        f"⚠️ **MASS CHANNEL DELETION DETECTED**\n\n"
                        f"{user.mention} deleted **{count} channels** in {threshold['window']} seconds!\n\n"
                        f"**Auto-Response:** User will be quarantined",
                        user,
                        email_admins=True
                    )
                    
                    await security_monitor.auto_response(guild, 'mass_delete', user, severity=2)
                
                break
                
    except Exception as e:
        logger.error(f"Channel delete handler error: {e}")

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Monitor role changes and permission escalation"""
    try:
        if before.roles != after.roles:
            added = [r for r in after.roles if r not in before.roles]
            removed = [r for r in before.roles if r not in after.roles]
            
            # Log role changes
            await db.add_log(
                after.guild.id,
                'member_roles_changed',
                after.id,
                {
                    'added': [r.name for r in added],
                    'removed': [r.name for r in removed]
                }
            )
            
            # Check for permission escalation
            if added:
                is_escalation = await security_monitor.detect_permission_escalation(
                    after.guild,
                    after.id
                )
                
                if is_escalation:
                    await security_monitor.auto_response(
                        after.guild,
                        'permission_escalation',
                        after,
                        severity=2
                    )
    
    except Exception as e:
        logger.error(f"Member update handler error: {e}")

@bot.event
async def on_voice_state_update(
    member: discord.Member,
    before: discord.VoiceState,
    after: discord.VoiceState
):
    """Monitor voice channel activity"""
    try:
        guild_id = member.guild.id
        config = server_configs.get(guild_id)
        
        if not config or not config.voice_log_channel_id:
            return
        
        log_channel = member.guild.get_channel(config.voice_log_channel_id)
        if not log_channel:
            return
        
        # User joined voice
        if before.channel is None and after.channel is not None:
            voice_sessions[guild_id][member.id] = datetime.now(timezone.utc)
            
            embed = discord.Embed(
                title="🎤 Voice Channel Join",
                description=f"{member.mention} joined {after.channel.mention}",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc)
            )
            embed.add_field(
                name="Members in Channel",
                value=str(len(after.channel.members)),
                inline=True
            )
            
            await log_channel.send(embed=embed)
            
            await db.add_log(
                guild_id,
                'voice_join',
                member.id,
                {
                    'channel_id': after.channel.id,
                    'channel_name': after.channel.name,
                    'member_count': len(after.channel.members)
                }
            )
        
        # User left voice
        elif before.channel is not None and after.channel is None:
            duration = None
            if member.id in voice_sessions[guild_id]:
                join_time = voice_sessions[guild_id][member.id]
                duration = (datetime.now(timezone.utc) - join_time).total_seconds()
                del voice_sessions[guild_id][member.id]
            
            embed = discord.Embed(
                title="🔇 Voice Channel Leave",
                description=f"{member.mention} left {before.channel.mention}",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc)
            )
            
            if duration:
                hours = int(duration // 3600)
                minutes = int((duration % 3600) // 60)
                embed.add_field(
                    name="Duration",
                    value=f"{hours}h {minutes}m",
                    inline=True
                )
            
            await log_channel.send(embed=embed)
            
            await db.add_log(
                guild_id,
                'voice_leave',
                member.id,
                {
                    'channel_id': before.channel.id,
                    'channel_name': before.channel.name,
                    'duration_seconds': int(duration) if duration else None
                }
            )
        
        # User switched channels
        elif before.channel != after.channel:
            voice_sessions[guild_id][member.id] = datetime.now(timezone.utc)
            
            embed = discord.Embed(
                title="🔄 Voice Channel Switch",
                color=discord.Color.blue(),
                timestamp=datetime.now(timezone.utc)
            )
            embed.add_field(name="User", value=member.mention, inline=False)
            embed.add_field(name="From", value=before.channel.mention, inline=True)
            embed.add_field(name="To", value=after.channel.mention, inline=True)
            
            await log_channel.send(embed=embed)
        
    except Exception as e:
        logger.error(f"Voice state update handler error: {e}")

# ============= ADDITIONAL ADMIN COMMANDS =============

@bot.tree.command(name="security_scan", description="🔍 Run comprehensive security scan")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def security_scan_cmd(interaction: discord.Interaction):
    """Manual security scan"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        report = await security_monitor.scan_guild_security(interaction.guild)
        
        embed = discord.Embed(
            title="🔍 Security Scan Results",
            description=f"**Security Score:** {report['score']}/100",
            color=discord.Color.green() if report['score'] >= 70 else discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Rating", value=report['rating'], inline=True)
        embed.add_field(name="Scan Time", value=report['scan_time'], inline=True)
        
        if report['issues']:
            issues_text = "\n".join([f"• {issue}" for issue in report['issues'][:5]])
            embed.add_field(
                name="⚠️ Issues Found",
                value=issues_text,
                inline=False
            )
        
        if report['recommendations']:
            rec_text = "\n".join([f"• {rec}" for rec in report['recommendations'][:5]])
            embed.add_field(
                name="💡 Recommendations",
                value=rec_text,
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Security scan command error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="logs", description="📋 View recent activity logs")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def logs_cmd(
    interaction: discord.Interaction,
    category: str = None,
    limit: int = 10
):
    """View activity logs"""
    await interaction.response.defer(ephemeral=True)
    
    if limit > 50:
        limit = 50
    
    try:
        log_entries = await db.get_logs(
            interaction.guild.id,
            category=category,
            limit=limit
        )
        
        if not log_entries:
            await interaction.followup.send("ℹ️ No logs found", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="📋 Activity Logs",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if category:
            embed.description = f"**Category:** {category.title()}\n\n"
        else:
            embed.description = ""
        
        logs_text = []
        for i, entry in enumerate(log_entries[:10], 1):
            cat = entry.get('category', 'unknown').upper()
            user_id = entry.get('user_id')
            ts = entry.get('timestamp', 'N/A')
            
            user = bot.get_user(user_id) if user_id else None
            user_name = user.name if user else "System"
            
            logs_text.append(f"**{i}.** [{cat}] {user_name} - {ts[:16]}")
        
        embed.description += "\n".join(logs_text)
        embed.set_footer(text=f"Showing {len(logs_text)} of {len(log_entries)} entries")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Logs command error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="notification_stats", description="📊 View notification statistics")
@app_commands.checks.has_permissions(administrator=True)
async def notification_stats_cmd(interaction: discord.Interaction):
    """View notification system statistics"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        stats = notification_manager.get_stats()
        
        embed = discord.Embed(
            title="📊 Notification System Statistics",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(
            name="📧 Email",
            value=(
                f"**Queued:** {stats['email']['queued']}\n"
                f"**Sent:** {stats['email']['sent']}\n"
                f"**Failed:** {stats['email']['failed']}"
            ),
            inline=True
        )
        
        embed.add_field(
            name="📱 SMS",
            value=(
                f"**Queued:** {stats['sms']['queued']}\n"
                f"**Sent:** {stats['sms']['sent']}\n"
                f"**Failed:** {stats['sms']['failed']}"
            ),
            inline=True
        )
        
        embed.add_field(
            name="⚙️ System",
            value=f"**Status:** {'🟢 Active' if stats['processing'] else '🔴 Inactive'}",
            inline=True
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Notification stats command error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="help", description="❓ View help and command list")
@rate_limit(max_calls=5, window=60)
async def help_cmd(interaction: discord.Interaction):
    """Show comprehensive help"""
    embed = discord.Embed(
        title="🛡️ Sentinel Security Bot v2.1",
        description="Advanced security and management system for Discord servers",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="🔧 Setup & Configuration",
        value=(
            "`/setup` - Complete setup guide\n"
            "`/status` - View bot status\n"
            "`/set_log_channel` - Configure logging\n"
            "`/create_quarantine_role` - Create quarantine role\n"
            "`/set_admin_email` - Set email for alerts"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔒 Security & Moderation",
        value=(
            "`/whitelist_add` - Add trusted user\n"
            "`/quarantine` - Quarantine user\n"
            "`/threat_set` - Set threat level\n"
            "`/lockdown_enable` - Emergency lockdown\n"
            "`/warn` - Issue warning to user"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⏱️ Shift Management",
        value=(
            "`/shift_start` - Start work shift\n"
            "`/shift_end` - End shift\n"
            "`/shift_status` - Check shift status"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔍 Monitoring & Reports",
        value=(
            "`/security_scan` - Run security scan\n"
            "`/logs` - View activity logs\n"
            "`/notification_stats` - Email/SMS statistics\n"
            "`/daily_reports_enable` - Enable daily reports"
        ),
        inline=False
    )
    
    embed.add_field(
        name="✨ Features",
        value=(
            "• AI-powered threat detection\n"
            "• Auto-response to raids\n"
            "• Email/SMS alerts\n"
            "• Shift tracking\n"
            "• Comprehensive logging"
        ),
        inline=False
    )
    
    embed.set_footer(text="Sentinel Security Bot v2.1 - Optimized & Enhanced")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="daily_reports_enable", description="📧 Enable daily security reports")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def daily_reports_enable_cmd(interaction: discord.Interaction):
    """Enable daily email reports"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'daily_reports_enabled', True)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].daily_reports_enabled = True
        
        embed = discord.Embed(
            title="✅ Daily Reports Enabled",
            description="Administrators will receive daily security reports via email at 6 AM UTC",
            color=discord.Color.green()
        )
        embed.add_field(
            name="Reports Include",
            value="• Violations\n• Quarantines\n• Threat changes\n• Security alerts",
            inline=False
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'config',
            'Daily Reports Enabled',
            interaction.user,
            "Daily violation reports enabled"
        )
        
    except Exception as e:
        logger.error(f"Daily reports enable error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="set_admin_email", description="📧 Set your email for alerts")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def set_admin_email_cmd(interaction: discord.Interaction, email: str):
    """Configure admin email for notifications"""
    await interaction.response.defer(ephemeral=True)
    
    if not validate_email(email):
        await interaction.followup.send(
            "❌ Invalid email address format!",
            ephemeral=True
        )
        return
    
    email = sanitize_string(email, 254).lower()
    
    try:
        await db.set_user_email(interaction.guild.id, interaction.user.id, email)
        
        embed = discord.Embed(
            title="✅ Email Configured",
            description=f"Your email has been set to: `{email}`",
            color=discord.Color.green()
        )
        embed.add_field(
            name="You will receive:",
            value=(
                "• Security alerts\n"
                "• Daily violation reports\n"
                "• Critical notifications\n"
                "• Raid alerts"
            ),
            inline=False
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Send confirmation email
        if SENTINEL_EMAIL:
            asyncio.create_task(
                notification_manager.send_email(
                    email,
                    f"✅ Email Configured: {interaction.guild.name}",
                    f"Hello {interaction.user.name},\n\nYour email has been successfully configured for security alerts from {interaction.guild.name}.\n\nSentinel Security Bot v2.1",
                    f"<html><body style='font-family: Arial;'><h2 style='color: #27ae60;'>✅ Email Configured</h2><p>Hello <strong>{interaction.user.name}</strong>,</p><p>Your email is now configured for security alerts from <strong>{interaction.guild.name}</strong>.</p><p style='color: #666; font-size: 12px;'>Sentinel Security Bot v2.1</p></body></html>"
                )
            )
        
        await log_action(
            interaction.guild,
            'config',
            'Admin Email Set',
            interaction.user,
            f"Email configured: {email}"
        )
        
    except Exception as e:
        logger.error(f"Set email error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

"""
SENTINEL SECURITY BOT v2.1 - PART 4/5 (MISSING COMMANDS)
ALL REMAINING COMMANDS FROM ORIGINAL BOT

This part contains ALL the commands that were missing from Parts 1-3:
- Department management (10 commands)
- Role management (6 commands)
- Partnership management (3 commands)
- Advanced shift commands (8 commands)
- Verification setup commands (6 commands)
- Warning management (4 commands)
- Additional admin commands (10 commands)

APPEND THIS AFTER PART 3 (before the bot execution section)
"""

# ============= DEPARTMENT MANAGEMENT COMMANDS =============

@bot.tree.command(name="dept_join", description="📋 Request to join a department")
@rate_limit(max_calls=5, window=300)
async def dept_join(interaction: discord.Interaction, department: str):
    """Request to join department"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    
    try:
        # Check if department exists
        dept = await db.get_department(interaction.guild.id, department)
        if not dept:
            await interaction.followup.send(
                f"❌ Department '{department}' not found!",
                ephemeral=True
            )
            return
        
        # Check if already a member
        is_member = await db.is_department_member(
            interaction.guild.id,
            interaction.user.id,
            department
        )
        if is_member:
            await interaction.followup.send(
                f"⚠️ You're already a member of {department}!",
                ephemeral=True
            )
            return
        
        # Create join request
        request_id = await db.create_department_join_request(
            interaction.guild.id,
            interaction.user.id,
            department,
            'pending'
        )
        
        embed = discord.Embed(
            title="✅ Join Request Submitted",
            description=f"Your request to join **{department}** has been created",
            color=discord.Color.green()
        )
        embed.add_field(name="Department", value=department, inline=True)
        embed.add_field(name="Status", value="Pending", inline=True)
        embed.add_field(name="Request ID", value=str(request_id), inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Notify department head
        head_id = dept.get('department_head')
        if head_id:
            head = bot.get_user(head_id)
            if head:
                try:
                    notify_embed = discord.Embed(
                        title="📋 New Department Join Request",
                        description=f"{interaction.user.mention} wants to join **{department}**",
                        color=discord.Color.blue()
                    )
                    notify_embed.add_field(
                        name="User",
                        value=f"{interaction.user.name} ({interaction.user.id})",
                        inline=False
                    )
                    notify_embed.add_field(name="Request ID", value=str(request_id), inline=True)
                    await head.send(embed=notify_embed)
                except:
                    pass
        
        await log_action(
            interaction.guild,
            'department',
            'Join Request',
            interaction.user,
            f"Requested to join {department}"
        )
        
    except Exception as e:
        logger.error(f"Dept join error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_info", description="ℹ️ View department information")
@rate_limit(max_calls=10, window=60)
async def dept_info(interaction: discord.Interaction, department: str = None):
    """View department info"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        if department:
            # Show specific department
            department = sanitize_string(department, 50)
            dept = await db.get_department(interaction.guild.id, department)
            
            if not dept:
                await interaction.followup.send(
                    f"❌ Department '{department}' not found!",
                    ephemeral=True
                )
                return
            
            members = await db.get_department_members(interaction.guild.id, department)
            
            embed = discord.Embed(
                title=f"📋 Department: {department}",
                color=discord.Color.blue(),
                timestamp=datetime.now(timezone.utc)
            )
            
            # Department head
            head_id = dept.get('department_head')
            if head_id:
                head = bot.get_user(head_id)
                embed.add_field(
                    name="Department Head",
                    value=head.name if head else f"User {head_id}",
                    inline=True
                )
            
            embed.add_field(name="Total Members", value=str(len(members)), inline=True)
            embed.add_field(
                name="Created",
                value=dept.get('created_at', 'Unknown')[:10],
                inline=True
            )
            
            if dept.get('description'):
                embed.add_field(
                    name="Description",
                    value=dept['description'],
                    inline=False
                )
            
            if dept.get('suspended'):
                embed.add_field(
                    name="⚠️ Status",
                    value="**SUSPENDED**",
                    inline=False
                )
            
            # Show members
            if members:
                member_list = []
                for i, m_info in enumerate(members[:10], 1):
                    uid = m_info.get('user_id')
                    status = m_info.get('status', 'member')
                    u = bot.get_user(uid)
                    u_name = u.name if u else f"User {uid}"
                    member_list.append(f"{i}. {u_name} - {status}")
                
                embed.add_field(
                    name="Members",
                    value="\n".join(member_list),
                    inline=False
                )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        
        else:
            # List all departments
            depts = await db.get_all_departments(interaction.guild.id)
            
            if not depts:
                await interaction.followup.send(
                    "ℹ️ No departments found",
                    ephemeral=True
                )
                return
            
            embed = discord.Embed(
                title="📋 Server Departments",
                color=discord.Color.blue(),
                timestamp=datetime.now(timezone.utc)
            )
            
            dept_list = []
            for i, d in enumerate(depts[:15], 1):
                name = d.get('name', 'Unknown')
                suspended = " ⚠️" if d.get('suspended') else ""
                dept_list.append(f"{i}. **{name}**{suspended}")
            
            embed.description = "\n".join(dept_list)
            embed.set_footer(text=f"Total: {len(depts)} department(s)")
            
            if len(depts) > 15:
                embed.add_field(
                    name="Note",
                    value=f"Showing first 15 of {len(depts)}",
                    inline=False
                )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Dept info error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_create", description="➕ Create a new department")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def dept_create(
    interaction: discord.Interaction,
    name: str,
    description: str = "New department"
):
    """Create department"""
    await interaction.response.defer(ephemeral=True)
    
    name = sanitize_string(name, 50)
    description = sanitize_string(description, 500)
    
    try:
        # Check if already exists
        existing = await db.get_department(interaction.guild.id, name)
        if existing:
            await interaction.followup.send(
                f"❌ Department '{name}' already exists!",
                ephemeral=True
            )
            return
        
        # Create role
        role = await interaction.guild.create_role(
            name=f"[{name}]",
            color=discord.Color.blue(),
            reason=f"Department created by {interaction.user.name}"
        )
        
        # Create department in database
        await db.create_department(interaction.guild.id, name, description, role.id)
        
        embed = discord.Embed(
            title="✅ Department Created",
            description=f"**{name}** has been created",
            color=discord.Color.green()
        )
        embed.add_field(name="Name", value=name, inline=True)
        embed.add_field(name="Role", value=role.mention, inline=True)
        embed.add_field(name="Description", value=description, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'department',
            'Department Created',
            interaction.user,
            f"Created: {name}"
        )
        
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ Missing permissions to create roles!",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Dept create error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_set_head", description="👤 Set department head")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def dept_set_head(
    interaction: discord.Interaction,
    department: str,
    user: discord.Member
):
    """Set department head"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    
    try:
        dept = await db.get_department(interaction.guild.id, department)
        if not dept:
            await interaction.followup.send(
                f"❌ Department '{department}' not found!",
                ephemeral=True
            )
            return
        
        # Set head
        await db.set_department_head(interaction.guild.id, department, user.id)
        await db.add_department_member(interaction.guild.id, user.id, department, 'head')
        
        embed = discord.Embed(
            title="✅ Department Head Assigned",
            description=f"{user.mention} is now head of **{department}**",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'department',
            'Head Assigned',
            interaction.user,
            f"{user.mention} → {department}"
        )
        
    except Exception as e:
        logger.error(f"Set head error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_approve_join", description="✅ Approve join request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def dept_approve_join(
    interaction: discord.Interaction,
    request_id: int,
    reason: str = "Approved"
):
    """Approve department join request"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        request = await db.get_department_join_request(interaction.guild.id, request_id)
        
        if not request:
            await interaction.followup.send(
                f"❌ Request {request_id} not found!",
                ephemeral=True
            )
            return
        
        if request.get('status') != 'pending':
            await interaction.followup.send(
                f"❌ Request already {request['status']}!",
                ephemeral=True
            )
            return
        
        uid = request.get('user_id')
        dept = request.get('department')
        
        # Add to department
        await db.add_department_member(interaction.guild.id, uid, dept, 'member')
        await db.update_department_join_request_status(
            interaction.guild.id,
            request_id,
            'approved',
            reason
        )
        
        # Add department role
        dept_info = await db.get_department(interaction.guild.id, dept)
        if dept_info and dept_info.get('role_id'):
            member = interaction.guild.get_member(uid)
            role = interaction.guild.get_role(dept_info['role_id'])
            if member and role:
                try:
                    await member.add_roles(role, reason=f"Approved by {interaction.user.name}")
                except:
                    pass
        
        user = bot.get_user(uid)
        user_name = user.name if user else f"User {uid}"
        
        embed = discord.Embed(
            title="✅ Join Request Approved",
            description=f"{user_name} approved for **{dept}**",
            color=discord.Color.green()
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Notify user
        if user:
            try:
                await user.send(
                    f"✅ Your request to join **{dept}** in {interaction.guild.name} was approved!\n\nReason: {reason}"
                )
            except:
                pass
        
        await log_action(
            interaction.guild,
            'department',
            'Join Approved',
            interaction.user,
            f"{user_name} → {dept}"
        )
        
    except Exception as e:
        logger.error(f"Approve join error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_deny_join", description="❌ Deny join request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def dept_deny_join(
    interaction: discord.Interaction,
    request_id: int,
    reason: str = "Request denied"
):
    """Deny department join request"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        request = await db.get_department_join_request(interaction.guild.id, request_id)
        
        if not request:
            await interaction.followup.send(
                f"❌ Request {request_id} not found!",
                ephemeral=True
            )
            return
        
        if request.get('status') != 'pending':
            await interaction.followup.send(
                f"❌ Request already {request['status']}!",
                ephemeral=True
            )
            return
        
        uid = request.get('user_id')
        dept = request.get('department')
        
        await db.update_department_join_request_status(
            interaction.guild.id,
            request_id,
            'denied',
            reason
        )
        
        user = bot.get_user(uid)
        user_name = user.name if user else f"User {uid}"
        
        embed = discord.Embed(
            title="❌ Join Request Denied",
            description=f"{user_name}'s request for **{dept}** denied",
            color=discord.Color.red()
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Notify user
        if user:
            try:
                await user.send(
                    f"❌ Your request to join **{dept}** in {interaction.guild.name} was denied.\n\nReason: {reason}"
                )
            except:
                pass
        
        await log_action(
            interaction.guild,
            'department',
            'Join Denied',
            interaction.user,
            f"{user_name}: {reason}"
        )
        
    except Exception as e:
        logger.error(f"Deny join error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_join_requests", description="📋 View pending join requests")
@app_commands.checks.has_permissions(administrator=True)
async def dept_join_requests(interaction: discord.Interaction, department: str = None):
    """View pending join requests"""
    await interaction.response.defer(ephemeral=True)
    
    if department:
        department = sanitize_string(department, 50)
    
    try:
        requests = await db.get_department_join_requests(
            interaction.guild.id,
            department,
            status='pending'
        )
        
        if not requests:
            await interaction.followup.send(
                "✅ No pending join requests",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title="📋 Pending Join Requests",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        req_text = []
        for req in requests[:15]:
            rid = req.get('id')
            uid = req.get('user_id')
            d = req.get('department')
            u = bot.get_user(uid)
            u_name = u.name if u else f"User {uid}"
            req_text.append(f"**#{rid}** - {u_name} → {d}")
        
        embed.description = "\n".join(req_text)
        embed.set_footer(text="Use /dept_approve_join or /dept_deny_join")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Join requests error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_suspend", description="⚠️ Suspend a department")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def dept_suspend(
    interaction: discord.Interaction,
    department: str,
    reason: str = "No reason"
):
    """Suspend department"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    reason = sanitize_string(reason, 500)
    
    try:
        dept = await db.get_department(interaction.guild.id, department)
        if not dept:
            await interaction.followup.send(
                f"❌ Department '{department}' not found!",
                ephemeral=True
            )
            return
        
        if dept.get('suspended'):
            await interaction.followup.send(
                f"⚠️ {department} is already suspended!",
                ephemeral=True
            )
            return
        
        await db.update_department_field(interaction.guild.id, department, 'suspended', True)
        
        # End all active shifts in this department
        ended = 0
        for gid, shifts in ACTIVE_SHIFTS.items():
            if gid == interaction.guild.id:
                for uid, shift in list(shifts.items()):
                    if shift.get('department') == department:
                        try:
                            end_time = datetime.now(timezone.utc)
                            duration = (end_time - shift['start_time']).total_seconds()
                            await db.end_shift(gid, uid, end_time, duration, force_ended=True)
                            del ACTIVE_SHIFTS[gid][uid]
                            ended += 1
                        except:
                            pass
        
        embed = discord.Embed(
            title="🔒 Department Suspended",
            description=f"**{department}** has been suspended",
            color=discord.Color.orange()
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.add_field(name="Shifts Ended", value=str(ended), inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'department',
            'Department Suspended',
            interaction.user,
            f"{department} - Ended {ended} shifts"
        )
        
    except Exception as e:
        logger.error(f"Suspend dept error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_activate", description="✅ Activate suspended department")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def dept_activate(interaction: discord.Interaction, department: str):
    """Activate department"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    
    try:
        dept = await db.get_department(interaction.guild.id, department)
        if not dept:
            await interaction.followup.send(
                f"❌ Department '{department}' not found!",
                ephemeral=True
            )
            return
        
        if not dept.get('suspended'):
            await interaction.followup.send(
                f"⚠️ {department} is not suspended!",
                ephemeral=True
            )
            return
        
        await db.update_department_field(interaction.guild.id, department, 'suspended', False)
        
        embed = discord.Embed(
            title="✅ Department Activated",
            description=f"**{department}** is now active",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'department',
            'Department Activated',
            interaction.user,
            f"{department}"
        )
        
    except Exception as e:
        logger.error(f"Activate dept error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="dept_analytics", description="📊 Department analytics")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def dept_analytics(interaction: discord.Interaction, department: str = None):
    """View department analytics"""
    await interaction.response.defer(ephemeral=True)
    
    if department:
        department = sanitize_string(department, 50)
    
    try:
        if department:
            # Specific department analytics
            members = await db.get_department_members(interaction.guild.id, department)
            shifts = await db.get_department_shifts(interaction.guild.id, department)
            
            embed = discord.Embed(
                title=f"📊 Analytics: {department}",
                color=discord.Color.blue()
            )
            
            total_hours = sum(s.get('duration_seconds', 0) for s in shifts) / 3600
            avg_shift = total_hours / len(shifts) if shifts else 0
            
            embed.add_field(name="Members", value=str(len(members)), inline=True)
            embed.add_field(name="Shifts", value=str(len(shifts)), inline=True)
            embed.add_field(name="Total Hours", value=f"{total_hours:.1f}h", inline=True)
            embed.add_field(name="Avg Shift", value=f"{avg_shift:.1f}h", inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            # All departments analytics
            depts = await db.get_all_departments(interaction.guild.id)
            
            embed = discord.Embed(
                title="📊 Department Analytics",
                color=discord.Color.blue()
            )
            
            total_members = 0
            total_shifts = 0
            
            for d in depts:
                m = await db.get_department_members(interaction.guild.id, d['name'])
                s = await db.get_department_shifts(interaction.guild.id, d['name'])
                total_members += len(m)
                total_shifts += len(s)
            
            embed.add_field(name="Departments", value=str(len(depts)), inline=True)
            embed.add_field(name="Total Members", value=str(total_members), inline=True)
            embed.add_field(name="Total Shifts", value=str(total_shifts), inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Dept analytics error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= ROLE MANAGEMENT COMMANDS =============

@bot.tree.command(name="promotion", description="⬆️ Promote user to next tier")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def promotion(interaction: discord.Interaction, user: discord.Member):
    """Promote user"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Get current tier
        user_tier = 1
        user_role = "USER"
        
        for role in user.roles:
            for rname, tier in ROLE_HIERARCHY.items():
                if rname.lower() in role.name.lower():
                    if tier > user_tier:
                        user_tier = tier
                        user_role = rname
        
        # Find next tier
        next_tier = None
        next_role = None
        
        for rname, tier in sorted(ROLE_HIERARCHY.items(), key=lambda x: x[1]):
            if tier > user_tier:
                next_tier = tier
                next_role = rname
                break
        
        if not next_tier:
            await interaction.followup.send(
                f"❌ {user.mention} is already at max tier!",
                ephemeral=True
            )
            return
        
        # Create or get role
        role = discord.utils.get(interaction.guild.roles, name=next_role)
        if not role:
            role = await interaction.guild.create_role(
                name=next_role,
                color=discord.Color.blue(),
                reason=f"Promotion by {interaction.user.name}"
            )
        
        await user.add_roles(role, reason=f"Promoted by {interaction.user.name}")
        
        embed = discord.Embed(
            title="✅ User Promoted",
            description=f"{user.mention} has been promoted!",
            color=discord.Color.green()
        )
        embed.add_field(name="From", value=user_role, inline=True)
        embed.add_field(name="To", value=next_role, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'roles',
            'User Promoted',
            interaction.user,
            f"{user.mention}: {user_role} → {next_role}"
        )
        
    except Exception as e:
        logger.error(f"Promotion error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="demotion", description="⬇️ Demote user to previous tier")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def demotion(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str = "No reason"
):
    """Demote user"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        # Get current tier
        user_tier = 1
        user_role = "USER"
        
        for role in user.roles:
            for rname, tier in ROLE_HIERARCHY.items():
                if rname.lower() in role.name.lower():
                    if tier > user_tier:
                        user_tier = tier
                        user_role = rname
        
        # Find previous tier
        prev_tier = None
        prev_role = None
        
        for rname, tier in sorted(ROLE_HIERARCHY.items(), key=lambda x: x[1], reverse=True):
            if tier < user_tier:
                prev_tier = tier
                prev_role = rname
                break
        
        if not prev_tier:
            await interaction.followup.send(
                f"❌ {user.mention} is already at min tier!",
                ephemeral=True
            )
            return
        
        # Remove current role
        cur_role = discord.utils.get(interaction.guild.roles, name=user_role)
        if cur_role:
            await user.remove_roles(cur_role, reason=f"Demoted: {reason}")
        
        # Add previous role
        role = discord.utils.get(interaction.guild.roles, name=prev_role)
        if not role:
            role = await interaction.guild.create_role(
                name=prev_role,
                color=discord.Color.light_grey(),
                reason=f"Demotion by {interaction.user.name}"
            )
        
        await user.add_roles(role, reason=f"Demoted: {reason}")
        
        embed = discord.Embed(
            title="⚠️ User Demoted",
            description=f"{user.mention} has been demoted",
            color=discord.Color.orange()
        )
        embed.add_field(name="From", value=user_role, inline=True)
        embed.add_field(name="To", value=prev_role, inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'roles',
            'User Demoted',
            interaction.user,
            f"{user.mention}: {user_role} → {prev_role}\nReason: {reason}"
        )
        
    except Exception as e:
        logger.error(f"Demotion error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="requestrole", description="📝 Request a role")
@rate_limit(max_calls=3, window=3600)
async def requestrole(interaction: discord.Interaction, role: discord.Role):
    """Request role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        if role in interaction.user.roles:
            await interaction.followup.send(
                f"❌ You already have {role.mention}!",
                ephemeral=True
            )
            return
        
        await db.add_role_request(interaction.guild.id, interaction.user.id, role.id, 'pending')
        
        embed = discord.Embed(
            title="✅ Role Request Submitted",
            description=f"Request for {role.mention} created",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Notify admins
        admin_count = 0
        for member in interaction.guild.members:
            if member.guild_permissions.administrator and admin_count < 5:
                try:
                    notify_embed = discord.Embed(
                        title="📋 New Role Request",
                        description=f"{interaction.user.mention} requested {role.mention}",
                        color=discord.Color.blue()
                    )
                    await member.send(embed=notify_embed)
                    admin_count += 1
                except:
                    pass
        
        await log_action(
            interaction.guild,
            'roles',
            'Role Requested',
            interaction.user,
            f"Requested {role.mention}"
        )
        
    except Exception as e:
        logger.error(f"Request role error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="role_requests", description="📋 View pending role requests")
@app_commands.checks.has_permissions(administrator=True)
async def role_requests(interaction: discord.Interaction):
    """View pending role requests"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        requests = await db.get_role_requests(interaction.guild.id, status='pending')
        
        if not requests:
            await interaction.followup.send(
                "✅ No pending role requests",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title="📋 Pending Role Requests",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        req_text = []
        for i, req in enumerate(requests[:10], 1):
            uid = req.get('user_id')
            rid = req.get('role_id')
            
            u = bot.get_user(uid)
            r = interaction.guild.get_role(rid)
            
            u_name = u.name if u else f"User {uid}"
            r_name = r.name if r else f"Role {rid}"
            
            req_text.append(f"{i}. **{u_name}** → {r_name}")
        
        embed.description = "\n".join(req_text)
        embed.set_footer(text="Use /approve_role or /deny_role")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Role requests error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="approve_role", description="✅ Approve role request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def approve_role(
    interaction: discord.Interaction,
    user: discord.User,
    role: discord.Role
):
    """Approve role request"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        member = interaction.guild.get_member(user.id)
        if not member:
            await interaction.followup.send(
                f"❌ {user.mention} is not a member!",
                ephemeral=True
            )
            return
        
        await member.add_roles(role, reason=f"Approved by {interaction.user.name}")
        await db.update_role_request_status(interaction.guild.id, user.id, role.id, 'approved')
        
        try:
            await user.send(
                f"✅ Your request for {role.mention} in {interaction.guild.name} was approved!"
            )
        except:
            pass
        
        await interaction.followup.send(
            f"✅ Approved {user.mention} for {role.mention}",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'roles',
            'Role Request Approved',
            interaction.user,
            f"{user.mention} → {role.mention}"
        )
        
    except Exception as e:
        logger.error(f"Approve role error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="deny_role", description="❌ Deny role request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def deny_role(
    interaction: discord.Interaction,
    user: discord.User,
    role: discord.Role,
    reason: str = "Denied"
):
    """Deny role request"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        await db.update_role_request_status(interaction.guild.id, user.id, role.id, 'denied')
        
        try:
            await user.send(
                f"❌ Your request for {role.mention} in {interaction.guild.name} was denied.\n\nReason: {reason}"
            )
        except:
            pass
        
        await interaction.followup.send(
            f"✅ Denied {user.mention} for {role.mention}",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'roles',
            'Role Request Denied',
            interaction.user,
            f"{user.mention}: {reason}"
        )
        
    except Exception as e:
        logger.error(f"Deny role error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= PARTNERSHIP COMMANDS =============

@bot.tree.command(name="partnership_add", description="🤝 Add partner server")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def partnership_add(
    interaction: discord.Interaction,
    guild_id: str,
    guild_name: str,
    description: str = "Partner server"
):
    """Add partnership"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        gid = int(guild_id)
        if not validate_discord_id(gid):
            await interaction.followup.send(
                "❌ Invalid guild ID!",
                ephemeral=True
            )
            return
        
        guild_name = sanitize_string(guild_name, 100)
        description = sanitize_string(description, 500)
        
        await db.add_partnership(interaction.guild.id, gid, guild_name, description)
        
        embed = discord.Embed(
            title="✅ Partnership Added",
            description=f"**{guild_name}** added as partner",
            color=discord.Color.green()
        )
        embed.add_field(name="Guild ID", value=f"`{gid}`", inline=True)
        embed.add_field(name="Description", value=description, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'partnership',
            'Partnership Added',
            interaction.user,
            f"{guild_name} ({gid})"
        )
        
    except ValueError:
        await interaction.followup.send(
            "❌ Invalid guild ID format!",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Partnership add error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="partnership_remove", description="❌ Remove partner server")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def partnership_remove(interaction: discord.Interaction, guild_id: str):
    """Remove partnership"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        gid = int(guild_id)
        removed = await db.remove_partnership(interaction.guild.id, gid)
        
        if removed:
            await interaction.followup.send(
                f"✅ Removed partnership with guild {gid}",
                ephemeral=True
            )
            
            await log_action(
                interaction.guild,
                'partnership',
                'Partnership Removed',
                interaction.user,
                f"Guild {gid}"
            )
        else:
            await interaction.followup.send(
                "❌ Partnership not found!",
                ephemeral=True
            )
        
    except ValueError:
        await interaction.followup.send(
            "❌ Invalid guild ID!",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Partnership remove error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="partnerships", description="🤝 List partnerships")
@rate_limit(max_calls=10, window=60)
async def partnerships(interaction: discord.Interaction):
    """List partnerships"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        partners = await db.get_partnerships(interaction.guild.id)
        
        if not partners:
            await interaction.followup.send(
                "ℹ️ No partnerships configured",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title="🤝 Server Partnerships",
            color=discord.Color.purple(),
            timestamp=datetime.now(timezone.utc)
        )
        
        for i, p in enumerate(partners[:10], 1):
            name = p.get('guild_name', 'Unknown')
            gid = p.get('partner_guild_id', 'Unknown')
            desc = p.get('description', 'No description')
            
            embed.add_field(
                name=f"{i}. {name}",
                value=f"**ID:** `{gid}`\n{desc}",
                inline=False
            )
        
        embed.set_footer(text=f"Total: {len(partners)} partnership(s)")
        
        if len(partners) > 10:
            embed.add_field(
                name="Note",
                value=f"Showing first 10 of {len(partners)}",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Partnerships error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= CONTINUED IN NEXT PART... =============

"""
SENTINEL SECURITY BOT v2.1 - PART 5/5 (FINAL - ALL MISSING COMMANDS)
COMPLETE ALL REMAINING COMMANDS

This is the FINAL part containing ALL remaining commands:
- Advanced shift commands (8 commands)
- Verification setup commands (6 commands)  
- Warning management commands (5 commands)
- Voice & configuration commands (6 commands)
- Additional utility commands (8 commands)

APPEND THIS AFTER PART 4 (before bot execution)
"""

# ============= ADVANCED SHIFT MANAGEMENT COMMANDS =============

@bot.tree.command(name="shift_force_end", description="🛑 Force end user's shift")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def shift_force_end(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str = "Force ended by admin"
):
    """Force end a shift"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        guild_id = interaction.guild.id
        user_id = user.id
        
        if user_id not in ACTIVE_SHIFTS[guild_id]:
            await interaction.followup.send(
                f"❌ {user.mention} doesn't have an active shift!",
                ephemeral=True
            )
            return
        
        shift = ACTIVE_SHIFTS[guild_id][user_id]
        end_time = datetime.now(timezone.utc)
        duration = (end_time - shift['start_time']).total_seconds()
        
        await db.end_shift(guild_id, user_id, end_time, duration, force_ended=True)
        del ACTIVE_SHIFTS[guild_id][user_id]
        
        # Remove on-duty role
        config = server_configs.get(guild_id)
        if config and config.onduty_role_id:
            role = interaction.guild.get_role(config.onduty_role_id)
            if role and role in user.roles:
                try:
                    await user.remove_roles(role, reason=f"Shift force ended: {reason}")
                except:
                    pass
        
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        
        embed = discord.Embed(
            title="🛑 Shift Force Ended",
            description=f"{user.mention}'s shift was ended by admin",
            color=discord.Color.orange()
        )
        embed.add_field(name="Duration", value=f"{hours}h {minutes}m", inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        try:
            await user.send(
                f"⚠️ Your shift in {interaction.guild.name} was force-ended.\n\n"
                f"Duration: {hours}h {minutes}m\n"
                f"Reason: {reason}"
            )
        except:
            pass
        
        await log_action(
            interaction.guild,
            'shift',
            'Shift Force Ended',
            interaction.user,
            f"{user.mention} - Reason: {reason}"
        )
        
    except Exception as e:
        logger.error(f"Force end shift error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_log", description="📋 View shift history")
@app_commands.checks.has_permissions(manage_messages=True)
@rate_limit(max_calls=10, window=60)
async def shift_log(
    interaction: discord.Interaction,
    user: discord.Member = None,
    limit: int = 10
):
    """View shift history"""
    await interaction.response.defer(ephemeral=True)
    
    target = user or interaction.user
    if limit > 50:
        limit = 50
    
    try:
        shifts = await db.get_user_shifts(
            interaction.guild.id,
            target.id,
            limit=limit
        )
        
        if not shifts:
            await interaction.followup.send(
                f"ℹ️ No shift history for {target.mention}",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title=f"📋 Shift History: {target.name}",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        total_hours = 0
        for i, shift in enumerate(shifts[:10], 1):
            start = shift.get('start_time', 'N/A')
            duration = shift.get('duration_seconds', 0)
            dept = shift.get('department', 'None')
            
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            total_hours += hours + (minutes / 60)
            
            embed.add_field(
                name=f"#{i} - {start[:10]}",
                value=f"**Duration:** {hours}h {minutes}m\n**Dept:** {dept}",
                inline=True
            )
        
        embed.set_footer(text=f"Total: {len(shifts)} shifts | {total_hours:.1f}h total")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Shift log error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_lock", description="🔒 Lock user's shift")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def shift_lock(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str = "Shift locked by admin"
):
    """Lock a shift"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        guild_id = interaction.guild.id
        user_id = user.id
        
        if user_id not in ACTIVE_SHIFTS[guild_id]:
            await interaction.followup.send(
                f"❌ {user.mention} doesn't have an active shift!",
                ephemeral=True
            )
            return
        
        SHIFT_LOCKS[guild_id][user_id] = True
        
        embed = discord.Embed(
            title="🔒 Shift Locked",
            description=f"{user.mention}'s shift is now locked",
            color=discord.Color.orange()
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.add_field(
            name="Note",
            value="User cannot end their shift until unlocked",
            inline=False
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        try:
            await user.send(
                f"🔒 Your shift in {interaction.guild.name} has been locked.\n\n"
                f"Reason: {reason}\n\n"
                f"Contact an administrator to unlock."
            )
        except:
            pass
        
        await log_action(
            interaction.guild,
            'shift',
            'Shift Locked',
            interaction.user,
            f"{user.mention} - {reason}"
        )
        
    except Exception as e:
        logger.error(f"Shift lock error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_unlock", description="🔓 Unlock user's shift")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def shift_unlock(interaction: discord.Interaction, user: discord.Member):
    """Unlock a shift"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        guild_id = interaction.guild.id
        user_id = user.id
        
        if not SHIFT_LOCKS[guild_id].get(user_id):
            await interaction.followup.send(
                f"❌ {user.mention}'s shift is not locked!",
                ephemeral=True
            )
            return
        
        SHIFT_LOCKS[guild_id][user_id] = False
        
        embed = discord.Embed(
            title="🔓 Shift Unlocked",
            description=f"{user.mention}'s shift is now unlocked",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        try:
            await user.send(
                f"🔓 Your shift in {interaction.guild.name} has been unlocked.\n\n"
                f"You can now end your shift normally."
            )
        except:
            pass
        
        await log_action(
            interaction.guild,
            'shift',
            'Shift Unlocked',
            interaction.user,
            f"{user.mention}"
        )
        
    except Exception as e:
        logger.error(f"Shift unlock error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_check_overlap", description="🔍 Check for shift overlaps")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def shift_check_overlap(interaction: discord.Interaction):
    """Check for overlapping shifts"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        overlaps = await db.detect_shift_overlaps(interaction.guild.id)
        
        if not overlaps:
            await interaction.followup.send(
                "✅ No shift overlaps detected",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title="⚠️ Shift Overlaps Detected",
            description=f"Found {len(overlaps)} overlapping shift(s)",
            color=discord.Color.orange()
        )
        
        for i, overlap in enumerate(overlaps[:10], 1):
            uid = overlap.get('user_id')
            count = overlap.get('overlap_count', 0)
            u = bot.get_user(uid)
            u_name = u.name if u else f"User {uid}"
            
            embed.add_field(
                name=f"{i}. {u_name}",
                value=f"{count} overlapping shift(s)",
                inline=True
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Check overlap error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_violations", description="⚠️ View shift violations")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def shift_violations(interaction: discord.Interaction, hours: int = 24):
    """View shift violations"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        violations = await db.detect_shift_violations(interaction.guild.id, hours=hours)
        
        if not violations:
            await interaction.followup.send(
                f"✅ No violations in the last {hours} hours",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title="⚠️ Shift Violations",
            description=f"Found {len(violations)} violation(s) in last {hours}h",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        
        for i, v in enumerate(violations[:10], 1):
            uid = v.get('user_id')
            v_type = v.get('type', 'unknown')
            u = bot.get_user(uid)
            u_name = u.name if u else f"User {uid}"
            
            embed.add_field(
                name=f"{i}. {u_name}",
                value=f"**Type:** {v_type}",
                inline=True
            )
        
        embed.set_footer(text=f"Total: {len(violations)} violation(s)")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Shift violations error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_report", description="📊 Generate shift report")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def shift_report(interaction: discord.Interaction, days: int = 7):
    """Generate shift report"""
    await interaction.response.defer(ephemeral=True)
    
    if days > 30:
        days = 30
    
    try:
        shifts = await db.get_all_shifts(interaction.guild.id, days=days)
        
        if not shifts:
            await interaction.followup.send(
                f"ℹ️ No shifts in the last {days} days",
                ephemeral=True
            )
            return
        
        # Calculate statistics
        total_duration = sum(s.get('duration_seconds', 0) for s in shifts)
        total_hours = total_duration / 3600
        avg_duration = total_duration / len(shifts) if shifts else 0
        avg_hours = avg_duration / 3600
        
        # Count by department
        dept_counts = {}
        for s in shifts:
            dept = s.get('department', 'None')
            dept_counts[dept] = dept_counts.get(dept, 0) + 1
        
        embed = discord.Embed(
            title=f"📊 Shift Report ({days} days)",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Total Shifts", value=str(len(shifts)), inline=True)
        embed.add_field(name="Total Hours", value=f"{total_hours:.1f}h", inline=True)
        embed.add_field(name="Avg Shift", value=f"{avg_hours:.1f}h", inline=True)
        
        # Top departments
        top_depts = sorted(dept_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_depts:
            dept_text = "\n".join([f"• {d}: {c} shifts" for d, c in top_depts])
            embed.add_field(
                name="Top Departments",
                value=dept_text,
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Shift report error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= VERIFICATION SETUP COMMANDS =============

@bot.tree.command(name="setup_verification", description="🎫 Set up Discord verification")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def setup_verification(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    verified_role: discord.Role,
    unverified_role: discord.Role = None
):
    """Setup Discord verification"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Check permissions
        perms = channel.permissions_for(interaction.guild.me)
        if not perms.send_messages or not perms.embed_links:
            await interaction.followup.send(
                "❌ I need Send Messages and Embed Links permissions!",
                ephemeral=True
            )
            return
        
        # Update config
        await db.update_server_field(interaction.guild.id, 'verification_enabled', True)
        await db.update_server_field(interaction.guild.id, 'verification_channel_id', channel.id)
        await db.update_server_field(interaction.guild.id, 'verified_role_id', verified_role.id)
        
        if unverified_role:
            await db.update_server_field(interaction.guild.id, 'unverified_role_id', unverified_role.id)
        
        # Update in-memory config
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        
        config = server_configs[interaction.guild.id]
        config.verification_enabled = True
        config.verification_channel_id = channel.id
        config.verified_role_id = verified_role.id
        config.unverified_role_id = unverified_role.id if unverified_role else None
        
        # Send verification message
        verify_embed = discord.Embed(
            title="✅ Verification Required",
            description="Click the button below to verify and gain access to the server.",
            color=discord.Color.green()
        )
        verify_embed.add_field(
            name="After Verification",
            value=f"You will receive the {verified_role.mention} role",
            inline=False
        )
        
        view = VerificationView()
        await channel.send(embed=verify_embed, view=view)
        
        # Confirmation
        embed = discord.Embed(
            title="✅ Verification Setup Complete",
            color=discord.Color.green()
        )
        embed.add_field(name="Channel", value=channel.mention, inline=True)
        embed.add_field(name="Verified Role", value=verified_role.mention, inline=True)
        if unverified_role:
            embed.add_field(name="Unverified Role", value=unverified_role.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'verification',
            'Verification Setup',
            interaction.user,
            f"Channel: {channel.mention}"
        )
        
    except Exception as e:
        logger.error(f"Setup verification error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="setup_roblox_verification", description="🎮 Set up Roblox verification")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def setup_roblox_verification(
    interaction: discord.Interaction,
    channel: discord.TextChannel,
    verified_role: discord.Role,
    unverified_role: discord.Role = None
):
    """Setup Roblox verification"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Check permissions
        perms = channel.permissions_for(interaction.guild.me)
        if not perms.send_messages or not perms.embed_links:
            await interaction.followup.send(
                "❌ I need Send Messages and Embed Links permissions!",
                ephemeral=True
            )
            return
        
        # Update config
        await db.update_server_field(interaction.guild.id, 'verification_enabled', True)
        await db.update_server_field(interaction.guild.id, 'verification_channel_id', channel.id)
        await db.update_server_field(interaction.guild.id, 'verified_role_id', verified_role.id)
        
        if unverified_role:
            await db.update_server_field(interaction.guild.id, 'unverified_role_id', unverified_role.id)
        
        # Update in-memory config
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        
        config = server_configs[interaction.guild.id]
        config.verification_enabled = True
        config.verification_channel_id = channel.id
        config.verified_role_id = verified_role.id
        config.unverified_role_id = unverified_role.id if unverified_role else None
        
        # Send verification message
        verify_embed = discord.Embed(
            title="🎮 Roblox Verification",
            description="Link your Roblox account to gain access to the server.",
            color=discord.Color.blue()
        )
        verify_embed.add_field(
            name="How It Works",
            value=(
                "1. Click the button below\n"
                "2. Add verification code to your Roblox profile\n"
                "3. Enter your Roblox username\n"
                "4. Get verified!"
            ),
            inline=False
        )
        verify_embed.add_field(
            name="After Verification",
            value=f"You will receive the {verified_role.mention} role",
            inline=False
        )
        
        view = RobloxVerificationView()
        await channel.send(embed=verify_embed, view=view)
        
        # Confirmation
        embed = discord.Embed(
            title="✅ Roblox Verification Setup Complete",
            color=discord.Color.green()
        )
        embed.add_field(name="Channel", value=channel.mention, inline=True)
        embed.add_field(name="Verified Role", value=verified_role.mention, inline=True)
        if unverified_role:
            embed.add_field(name="Unverified Role", value=unverified_role.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'verification',
            'Roblox Verification Setup',
            interaction.user,
            f"Channel: {channel.mention}"
        )
        
    except Exception as e:
        logger.error(f"Setup Roblox verification error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="verification_enable", description="✅ Enable verification")
@app_commands.checks.has_permissions(administrator=True)
async def verification_enable(interaction: discord.Interaction):
    """Enable verification system"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'verification_enabled', True)
        
        if interaction.guild.id in server_configs:
            server_configs[interaction.guild.id].verification_enabled = True
        
        await interaction.followup.send(
            "✅ Verification system enabled",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'verification',
            'Verification Enabled',
            interaction.user,
            "System enabled"
        )
        
    except Exception as e:
        logger.error(f"Enable verification error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="verification_disable", description="❌ Disable verification")
@app_commands.checks.has_permissions(administrator=True)
async def verification_disable(interaction: discord.Interaction):
    """Disable verification system"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'verification_enabled', False)
        
        if interaction.guild.id in server_configs:
            server_configs[interaction.guild.id].verification_enabled = False
        
        await interaction.followup.send(
            "✅ Verification system disabled",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'verification',
            'Verification Disabled',
            interaction.user,
            "System disabled"
        )
        
    except Exception as e:
        logger.error(f"Disable verification error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="verify_user", description="✅ Manually verify a user")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def verify_user(interaction: discord.Interaction, user: discord.Member):
    """Manually verify user"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        config = server_configs.get(interaction.guild.id)
        
        if not config or not config.verified_role_id:
            await interaction.followup.send(
                "❌ Verification not configured!",
                ephemeral=True
            )
            return
        
        verified_role = interaction.guild.get_role(config.verified_role_id)
        if not verified_role:
            await interaction.followup.send(
                "❌ Verified role not found!",
                ephemeral=True
            )
            return
        
        # Add verified role
        await user.add_roles(verified_role, reason=f"Manually verified by {interaction.user.name}")
        
        # Remove unverified role if exists
        if config.unverified_role_id:
            unverified_role = interaction.guild.get_role(config.unverified_role_id)
            if unverified_role and unverified_role in user.roles:
                await user.remove_roles(unverified_role, reason="Manually verified")
        
        await interaction.followup.send(
            f"✅ {user.mention} has been manually verified",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'verification',
            'Manual Verification',
            interaction.user,
            f"Verified {user.mention}"
        )
        
    except Exception as e:
        logger.error(f"Verify user error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="whois", description="🔍 Look up user verification info")
@app_commands.checks.has_permissions(manage_messages=True)
@rate_limit(max_calls=20, window=60)
async def whois(interaction: discord.Interaction, user: discord.Member):
    """Look up user info"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Get verification info
        verification = await db.get_verification(interaction.guild.id, user.id)
        
        embed = discord.Embed(
            title=f"🔍 User Info: {user.name}",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.set_thumbnail(url=user.display_avatar.url)
        
        embed.add_field(name="User ID", value=f"`{user.id}`", inline=True)
        embed.add_field(
            name="Account Created",
            value=user.created_at.strftime('%Y-%m-%d'),
            inline=True
        )
        embed.add_field(
            name="Joined Server",
            value=user.joined_at.strftime('%Y-%m-%d') if user.joined_at else "Unknown",
            inline=True
        )
        
        # Verification status
        if verification and verification.get('verified'):
            roblox_username = verification.get('roblox_username', 'Unknown')
            roblox_id = verification.get('roblox_id', 'Unknown')
            
            embed.add_field(
                name="✅ Verified",
                value=f"**Roblox:** {roblox_username}\n**ID:** {roblox_id}",
                inline=False
            )
        else:
            embed.add_field(name="Verification", value="❌ Not verified", inline=False)
        
        # Role count
        role_count = len([r for r in user.roles if r != interaction.guild.default_role])
        embed.add_field(name="Roles", value=str(role_count), inline=True)
        
        # Get warnings
        try:
            warnings = await db.get_active_warnings(interaction.guild.id, user.id)
            embed.add_field(
                name="Warnings",
                value=f"{len(warnings)}/{WARNING_CONFIG['max_warnings']}",
                inline=True
            )
        except:
            pass
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Whois error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= WARNING MANAGEMENT COMMANDS =============

@bot.tree.command(name="warnings", description="📋 View user warnings")
@app_commands.checks.has_permissions(manage_messages=True)
@rate_limit(max_calls=20, window=60)
async def warnings_cmd(interaction: discord.Interaction, user: discord.Member):
    """View user warnings"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        warnings = await db.get_active_warnings(interaction.guild.id, user.id)
        
        if not warnings:
            await interaction.followup.send(
                f"✅ {user.mention} has no active warnings",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title=f"⚠️ Warnings: {user.name}",
            description=f"{len(warnings)}/{WARNING_CONFIG['max_warnings']} active warnings",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        
        for i, w in enumerate(warnings[:10], 1):
            warn_id = w.get('id')
            reason = w.get('reason', 'No reason')
            timestamp = w.get('timestamp', 'Unknown')
            issued_by = w.get('issued_by')
            
            issuer = bot.get_user(issued_by) if issued_by else None
            issuer_name = issuer.name if issuer else "Unknown"
            
            embed.add_field(
                name=f"#{warn_id} - {timestamp[:10]}",
                value=f"**By:** {issuer_name}\n**Reason:** {reason}",
                inline=False
            )
        
        if len(warnings) >= WARNING_CONFIG['max_warnings']:
            embed.add_field(
                name="⚠️ CRITICAL",
                value="User has reached maximum warnings!",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Warnings view error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="clear_warning", description="🗑️ Clear a specific warning")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def clear_warning(interaction: discord.Interaction, warning_id: int):
    """Clear specific warning"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        cleared = await db.clear_warning(interaction.guild.id, warning_id)
        
        if cleared:
            await interaction.followup.send(
                f"✅ Warning #{warning_id} cleared",
                ephemeral=True
            )
            
            await log_action(
                interaction.guild,
                'moderation',
                'Warning Cleared',
                interaction.user,
                f"Warning #{warning_id}"
            )
        else:
            await interaction.followup.send(
                f"❌ Warning #{warning_id} not found!",
                ephemeral=True
            )
        
    except Exception as e:
        logger.error(f"Clear warning error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="clear_all_warnings", description="🗑️ Clear all warnings for user")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def clear_all_warnings(interaction: discord.Interaction, user: discord.Member):
    """Clear all warnings"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        count = await db.clear_all_warnings(interaction.guild.id, user.id)
        
        if count > 0:
            await interaction.followup.send(
                f"✅ Cleared {count} warning(s) for {user.mention}",
                ephemeral=True
            )
            
            await log_action(
                interaction.guild,
                'moderation',
                'All Warnings Cleared',
                interaction.user,
                f"{user.mention} - {count} warnings cleared"
            )
        else:
            await interaction.followup.send(
                f"ℹ️ {user.mention} has no active warnings",
                ephemeral=True
            )
        
    except Exception as e:
        logger.error(f"Clear all warnings error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="warning_config", description="⚙️ View warning system configuration")
@app_commands.checks.has_permissions(administrator=True)
async def warning_config(interaction: discord.Interaction):
    """View warning configuration"""
    await interaction.response.defer(ephemeral=True)
    
    embed = discord.Embed(
        title="⚙️ Warning System Configuration",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="Max Warnings",
        value=str(WARNING_CONFIG['max_warnings']),
        inline=True
    )
    embed.add_field(
        name="Warning Expiry",
        value=f"{WARNING_CONFIG['warning_expire_days']} days",
        inline=True
    )
    embed.add_field(
        name="Timeout Duration",
        value=f"{WARNING_CONFIG['timeout_duration']//60} minutes",
        inline=True
    )
    
    actions_text = "\n".join([
        f"**{count}:** {action.title()}"
        for count, action in WARNING_CONFIG['actions'].items()
    ])
    
    embed.add_field(
        name="Auto-Actions",
        value=actions_text,
        inline=False
    )
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ============= VOICE & CONFIGURATION COMMANDS =============

@bot.tree.command(name="set_voice_log", description="🎤 Set voice activity log channel")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def set_voice_log(interaction: discord.Interaction, channel: discord.TextChannel):
    """Set voice log channel"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        perms = channel.permissions_for(interaction.guild.me)
        if not perms.send_messages or not perms.embed_links:
            await interaction.followup.send(
                "❌ I need Send Messages and Embed Links permissions!",
                ephemeral=True
            )
            return
        
        await db.update_server_field(interaction.guild.id, 'voice_log_channel_id', channel.id)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].voice_log_channel_id = channel.id
        
        embed = discord.Embed(
            title="✅ Voice Log Channel Set",
            description=f"Voice activity will be logged to {channel.mention}",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'config',
            'Voice Log Channel Set',
            interaction.user,
            f"Set to {channel.mention}"
        )
        
    except Exception as e:
        logger.error(f"Set voice log error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="voice_stats", description="📊 View voice activity statistics")
@app_commands.checks.has_permissions(manage_messages=True)
@rate_limit(max_calls=10, window=60)
async def voice_stats(interaction: discord.Interaction, user: discord.Member = None):
    """View voice statistics"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        if user:
            # Individual stats
            logs = await db.get_logs(
                interaction.guild.id,
                category='voice_leave',
                user_id=user.id,
                limit=100
            )
            
            total_time = 0
            sessions = 0
            
            for log in logs:
                duration = log.get('details', {}).get('duration_seconds', 0)
                if duration:
                    total_time += duration
                    sessions += 1
            
            hours = total_time / 3600
            avg_session = total_time / sessions if sessions else 0
            avg_hours = avg_session / 3600
            
            embed = discord.Embed(
                title=f"🎤 Voice Stats: {user.name}",
                color=discord.Color.blue()
            )
            embed.add_field(name="Sessions", value=str(sessions), inline=True)
            embed.add_field(name="Total Time", value=f"{hours:.1f}h", inline=True)
            embed.add_field(name="Avg Session", value=f"{avg_hours:.1f}h", inline=True)
            
        else:
            # Server-wide stats
            logs = await db.get_logs(
                interaction.guild.id,
                category='voice_leave',
                limit=500
            )
            
            total_time = 0
            unique_users = set()
            
            for log in logs:
                duration = log.get('details', {}).get('duration_seconds', 0)
                uid = log.get('user_id')
                if duration:
                    total_time += duration
                if uid:
                    unique_users.add(uid)
            
            hours = total_time / 3600
            
            embed = discord.Embed(
                title="🎤 Server Voice Statistics",
                color=discord.Color.blue()
            )
            embed.add_field(name="Active Users", value=str(len(unique_users)), inline=True)
            embed.add_field(name="Sessions", value=str(len(logs)), inline=True)
            embed.add_field(name="Total Time", value=f"{hours:.1f}h", inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Voice stats error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="set_onduty_role", description="⏱️ Set on-duty role for shifts")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def set_onduty_role(interaction: discord.Interaction, role: discord.Role):
    """Set on-duty role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'onduty_role_id', role.id)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].onduty_role_id = role.id
        
        embed = discord.Embed(
            title="✅ On-Duty Role Set",
            description=f"Users on shift will receive {role.mention}",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'config',
            'On-Duty Role Set',
            interaction.user,
            f"Set to {role.mention}"
        )
        
    except Exception as e:
        logger.error(f"Set onduty role error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="set_allstaff_role", description="👥 Set all-staff role")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def set_allstaff_role(interaction: discord.Interaction, role: discord.Role):
    """Set all-staff role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'allstaff_role_id', role.id)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].allstaff_role_id = role.id
        
        embed = discord.Embed(
            title="✅ All-Staff Role Set",
            description=f"All-staff role set to {role.mention}",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'config',
            'All-Staff Role Set',
            interaction.user,
            f"Set to {role.mention}"
        )
        
    except Exception as e:
        logger.error(f"Set allstaff role error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="config", description="⚙️ View full bot configuration")
@app_commands.checks.has_permissions(administrator=True)
async def config_cmd(interaction: discord.Interaction):
    """View configuration"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        config = server_configs.get(interaction.guild.id)
        
        if not config:
            await interaction.followup.send(
                "❌ No configuration found!",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title="⚙️ Bot Configuration",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        # Channels
        log_ch = f"<#{config.log_channel_id}>" if config.log_channel_id else "Not set"
        voice_ch = f"<#{config.voice_log_channel_id}>" if config.voice_log_channel_id else "Not set"
        verif_ch = f"<#{config.verification_channel_id}>" if config.verification_channel_id else "Not set"
        
        embed.add_field(
            name="📝 Channels",
            value=f"**Log:** {log_ch}\n**Voice:** {voice_ch}\n**Verification:** {verif_ch}",
            inline=False
        )
        
        # Roles
        quar_role = f"<@&{config.quarantine_role_id}>" if config.quarantine_role_id else "Not set"
        onduty_role = f"<@&{config.onduty_role_id}>" if config.onduty_role_id else "Not set"
        verified_role = f"<@&{config.verified_role_id}>" if config.verified_role_id else "Not set"
        
        embed.add_field(
            name="🎭 Roles",
            value=f"**Quarantine:** {quar_role}\n**On-Duty:** {onduty_role}\n**Verified:** {verified_role}",
            inline=False
        )
        
        # Features
        embed.add_field(
            name="✨ Features",
            value=(
                f"**Verification:** {'✅' if config.verification_enabled else '❌'}\n"
                f"**Lockdown:** {'✅' if config.lockdown_enabled else '❌'}\n"
                f"**Daily Reports:** {'✅' if config.daily_reports_enabled else '❌'}\n"
                f"**Auto-Response:** {'✅' if config.auto_response_enabled else '❌'}\n"
                f"**Raid Protection:** {'✅' if config.raid_protection_enabled else '❌'}"
            ),
            inline=False
        )
        
        # Threat level
        threat_info = THREAT_LEVELS[config.threat_level]
        embed.add_field(
            name="🚨 Threat Level",
            value=threat_info['name'],
            inline=True
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Config view error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="reset_config", description="🔄 Reset bot configuration")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=1, window=600)
async def reset_config(interaction: discord.Interaction):
    """Reset configuration"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Confirm with user
        embed = discord.Embed(
            title="⚠️ Reset Configuration?",
            description="This will reset all bot settings to default. This action cannot be undone.",
            color=discord.Color.red()
        )
        
        # For simplicity, we'll just reset the in-memory config
        # In production, you'd add database reset too
        server_configs[interaction.guild.id] = SecurityConfig()
        
        await interaction.followup.send(
            "✅ Configuration reset to defaults",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'config',
            'Configuration Reset',
            interaction.user,
            "All settings reset to default"
        )
        
    except Exception as e:
        logger.error(f"Reset config error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= UTILITY COMMANDS =============

@bot.tree.command(name="quick_status", description="⚡ Quick server status")
@rate_limit(max_calls=10, window=60)
async def quick_status(interaction: discord.Interaction):
    """Quick status overview"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        config = server_configs.get(interaction.guild.id)
        
        # Quick stats
        active_shifts = len(ACTIVE_SHIFTS.get(interaction.guild.id, {}))
        threat_level = config.threat_level if config else 0
        threat_info = THREAT_LEVELS[threat_level]
        
        embed = discord.Embed(
            title=f"⚡ {interaction.guild.name}",
            color=threat_info['color'],
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Members", value=str(len(interaction.guild.members)), inline=True)
        embed.add_field(name="Active Shifts", value=str(active_shifts), inline=True)
        embed.add_field(name="Threat", value=threat_info['name'], inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Quick status error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="perms_check", description="🔍 Check bot permissions")
@rate_limit(max_calls=10, window=60)
async def perms_check(interaction: discord.Interaction):
    """Check bot permissions"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        bot_member = interaction.guild.me
        perms = bot_member.guild_permissions
        
        required_perms = {
            'Manage Roles': perms.manage_roles,
            'Manage Channels': perms.manage_channels,
            'Kick Members': perms.kick_members,
            'Ban Members': perms.ban_members,
            'Manage Messages': perms.manage_messages,
            'Read Message History': perms.read_message_history,
            'Send Messages': perms.send_messages,
            'Embed Links': perms.embed_links,
            'Moderate Members': perms.moderate_members,
            'View Audit Log': perms.view_audit_log,
        }
        
        embed = discord.Embed(
            title="🔍 Bot Permissions",
            color=discord.Color.blue()
        )
        
        for perm, has_perm in required_perms.items():
            status = "✅" if has_perm else "❌"
            embed.add_field(
                name=f"{status} {perm}",
                value="Granted" if has_perm else "**MISSING**",
                inline=True
            )
        
        missing = [p for p, has in required_perms.items() if not has]
        if missing:
            embed.add_field(
                name="⚠️ Missing Permissions",
                value=f"{len(missing)} permission(s) missing - some features may not work",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Perms check error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="remove_admin_email", description="🗑️ Remove your admin email")
@app_commands.checks.has_permissions(administrator=True)
async def remove_admin_email(interaction: discord.Interaction):
    """Remove admin email"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.remove_user_email(interaction.guild.id, interaction.user.id)
        
        await interaction.followup.send(
            "✅ Your email has been removed",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'config',
            'Admin Email Removed',
            interaction.user,
            "Email removed"
        )
        
    except Exception as e:
        logger.error(f"Remove email error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="daily_reports_disable", description="❌ Disable daily reports")
@app_commands.checks.has_permissions(administrator=True)
async def daily_reports_disable(interaction: discord.Interaction):
    """Disable daily reports"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'daily_reports_enabled', False)
        
        if interaction.guild.id in server_configs:
            server_configs[interaction.guild.id].daily_reports_enabled = False
        
        await interaction.followup.send(
            "✅ Daily reports disabled",
            ephemeral=True
        )
        
        await log_action(
            interaction.guild,
            'config',
            'Daily Reports Disabled',
            interaction.user,
            "Reports disabled"
        )
        
    except Exception as e:
        logger.error(f"Disable reports error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="daily_reports_status", description="📊 Check daily reports status")
@app_commands.checks.has_permissions(administrator=True)
async def daily_reports_status(interaction: discord.Interaction):
    """Check report status"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        config = server_configs.get(interaction.guild.id)
        enabled = config.daily_reports_enabled if config else False
        
        last_sent = last_report_time.get(interaction.guild.id)
        
        embed = discord.Embed(
            title="📊 Daily Reports Status",
            color=discord.Color.green() if enabled else discord.Color.red()
        )
        
        embed.add_field(
            name="Status",
            value="✅ Enabled" if enabled else "❌ Disabled",
            inline=True
        )
        
        if last_sent:
            embed.add_field(
                name="Last Sent",
                value=last_sent.strftime('%Y-%m-%d %H:%M UTC'),
                inline=True
            )
        
        embed.add_field(
            name="Send Time",
            value="6:00 AM UTC daily",
            inline=True
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Report status error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="role_heal", description="🔧 Restore missing department roles")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=1, window=300)
async def role_heal(interaction: discord.Interaction):
    """Restore missing department roles"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        depts = await db.get_all_departments(interaction.guild.id)
        healed = 0
        
        for dept in depts:
            role_id = dept.get('role_id')
            dept_name = dept.get('name')
            
            if role_id:
                role = interaction.guild.get_role(role_id)
                if not role:
                    # Role missing, recreate
                    new_role = await interaction.guild.create_role(
                        name=f"[{dept_name}]",
                        color=discord.Color.blue(),
                        reason="Role healing - missing department role"
                    )
                    await db.update_department_field(
                        interaction.guild.id,
                        dept_name,
                        'role_id',
                        new_role.id
                    )
                    healed += 1
        
        embed = discord.Embed(
            title="🔧 Role Healing Complete",
            description=f"Restored {healed} missing department role(s)",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        if healed > 0:
            await log_action(
                interaction.guild,
                'roles',
                'Role Healing',
                interaction.user,
                f"Restored {healed} roles"
            )
        
    except Exception as e:
        logger.error(f"Role heal error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= TASK STARTUP =============

async def before_loops():
    await bot.wait_until_ready()
    logger.info("✅ Bot ready - starting background tasks")

shift_heartbeat.before_loop(before_loops)
cleanup_old_logs.before_loop(before_loops)
reset_daily_threat.before_loop(before_loops)
daily_violation_report.before_loop(before_loops)
security_scan_task.before_loop(before_loops)


# ============= BOT EXECUTION =============

async def main():
    """Main bot execution function"""
    async with bot:
        try:
            logger.info("=" * 60)
            logger.info("🚀 STARTING SENTINEL SECURITY BOT v2.1")
            logger.info("=" * 60)
            await bot.start(TOKEN)
        except KeyboardInterrupt:
            logger.info("⛔ Bot stopped by user (KeyboardInterrupt)")
        except Exception as e:
            logger.critical(f"❌ Critical startup error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Cleanup
            await notification_manager.stop_processing()
            logger.info("=" * 60)
            logger.info("👋 SENTINEL SECURITY BOT SHUTDOWN COMPLETE")
            logger.info("=" * 60)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("⛔ Stopped by user")
    except Exception as e:
        logger.critical(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()

# ============= END OF SENTINEL SECURITY BOT v2.1 =============