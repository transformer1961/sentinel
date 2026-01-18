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
twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        from twilio.rest import Client
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
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
    
"""
SENTINEL SECURITY BOT v2.1 - PART 3/5
COMMAND IMPLEMENTATIONS

This part contains:
- Setup and configuration commands
- Whitelist management commands
- Quarantine commands
- Threat level commands
- Lockdown commands
- Shift management commands
"""

# ============= BOT EVENT HANDLERS =============

@bot.event
async def on_ready():
    """Bot startup and initialization"""
    logger.info(f'🤖 {bot.user} connected!')
    logger.info(f'📊 Monitoring {len(bot.guilds)} servers')
    
    # Initialize database
    try:
        await db.init_database()
        logger.info('✅ Database initialized')
    except Exception as e:
        logger.critical(f'❌ Database initialization failed: {e}')
        return
    
    # Load configurations and whitelists
    try:
        global server_configs, whitelists
        
        # Load all server configs
        raw_configs = await db.load_all_configs()
        server_configs = {}
        
        for guild_id, config_dict in raw_configs.items():
            server_configs[guild_id] = SecurityConfig(**config_dict)
        
        # Load whitelists
        raw_whitelists = await db.load_all_whitelists()
        whitelists = defaultdict(set)
        for guild_id, user_ids in raw_whitelists.items():
            whitelists[guild_id] = set(user_ids)
        
        logger.info(f'✅ Loaded {len(server_configs)} server configs')
        logger.info(f'✅ Loaded whitelists for {len(whitelists)} servers')
        
    except Exception as e:
        logger.error(f'⚠️ Configuration load error: {e}')
    
    # Add persistent views for verification
    bot.add_view(VerificationView())
    bot.add_view(RobloxVerificationView())
    logger.info('✅ Persistent views registered')
    
    # Start notification processing
    await notification_manager.start_processing()
    
    # Start background tasks
    if not shift_heartbeat.is_running():
        shift_heartbeat.start()
    if not cleanup_old_logs.is_running():
        cleanup_old_logs.start()
    if not reset_daily_threat.is_running():
        reset_daily_threat.start()
    if not daily_violation_report.is_running():
        daily_violation_report.start()
    if not security_scan_task.is_running():
        security_scan_task.start()
    
    logger.info('✅ Background tasks started')
    
    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        logger.info(f'✅ Synced {len(synced)} slash commands')
    except Exception as e:
        logger.error(f'⚠️ Command sync error: {e}')
    
    logger.info('🔍 Sentinel Security Bot v2.1 is now monitoring...')

@bot.event
async def on_guild_join(guild: discord.Guild):
    """Handle bot joining a new guild"""
    logger.info(f'➕ Joined new guild: {guild.name} ({guild.id})')
    
    # Create default config
    server_configs[guild.id] = SecurityConfig()
    
    # Send welcome message to owner or first channel
    try:
        owner = guild.owner
        if owner:
            embed = discord.Embed(
                title="🛡️ Sentinel Security Bot - Welcome!",
                description=(
                    f"Thank you for adding Sentinel to **{guild.name}**!\n\n"
                    "**Quick Start:**\n"
                    "1. `/setup` - View setup guide\n"
                    "2. `/set_log_channel` - Configure logging\n"
                    "3. `/create_quarantine_role` - Set up quarantine\n"
                    "4. `/whitelist_add` - Add trusted users\n\n"
                    "**Features:**\n"
                    "• Advanced threat detection\n"
                    "• Auto-response to raids\n"
                    "• Shift management\n"
                    "• Email/SMS alerts\n"
                    "• Comprehensive logging\n\n"
                    "Need help? Use `/help` anytime!"
                ),
                color=discord.Color.blue()
            )
            await owner.send(embed=embed)
    except:
        pass

@bot.event
async def on_guild_remove(guild: discord.Guild):
    """Handle bot leaving a guild"""
    logger.info(f'➖ Left guild: {guild.name} ({guild.id})')
    
    # Cleanup tracking data
    if guild.id in server_configs:
        del server_configs[guild.id]
    if guild.id in whitelists:
        del whitelists[guild.id]
    action_tracker.cleanup_guild(guild.id)

# ============= SETUP COMMANDS =============

@bot.tree.command(name="setup", description="🛡️ View complete setup guide")
@rate_limit(max_calls=3, window=300)
async def setup(interaction: discord.Interaction):
    """Show setup guide"""
    embed = discord.Embed(
        title="🛡️ Sentinel Security Bot - Setup Guide",
        description="Follow these steps to secure your server:",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    
    embed.add_field(
        name="1️⃣ Configure Logging",
        value="`/set_log_channel #channel` - Set where alerts are sent",
        inline=False
    )
    
    embed.add_field(
        name="2️⃣ Create Quarantine Role",
        value="`/create_quarantine_role` - Auto-creates restricted role",
        inline=False
    )
    
    embed.add_field(
        name="3️⃣ Whitelist Trusted Staff",
        value="`/whitelist_add @user` - Bypass security checks",
        inline=False
    )
    
    embed.add_field(
        name="4️⃣ Set Up Email Alerts (Optional)",
        value="`/set_admin_email your@email.com` - Get email notifications",
        inline=False
    )
    
    embed.add_field(
        name="5️⃣ Enable Features",
        value=(
            "`/setup_verification` - Member verification\n"
            "`/set_onduty_role` - Shift tracking\n"
            "`/daily_reports_enable` - Daily security reports"
        ),
        inline=False
    )
    
    embed.add_field(
        name="📊 Check Status",
        value="`/status` - View current configuration",
        inline=False
    )
    
    embed.set_footer(text="Need help? Contact a Sentinel developer")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="status", description="📊 View bot status and configuration")
@rate_limit(max_calls=5, window=60)
async def status(interaction: discord.Interaction):
    """Show comprehensive status"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id)
    
    embed = discord.Embed(
        title=f"📊 Status: {interaction.guild.name}",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    
    # Configuration status
    log_status = "✅" if config and config.log_channel_id else "❌"
    quar_status = "✅" if config and config.quarantine_role_id else "❌"
    verif_status = "✅" if config and config.verification_enabled else "❌"
    
    embed.add_field(
        name="⚙️ Configuration",
        value=f"{log_status} Log Channel\n{quar_status} Quarantine Role\n{verif_status} Verification",
        inline=True
    )
    
    # Security status
    wl_count = len(whitelists.get(interaction.guild.id, set()))
    threat_level = config.threat_level if config else 0
    threat_info = THREAT_LEVELS[threat_level]
    
    embed.add_field(
        name="🔒 Security",
        value=(
            f"Whitelisted: {wl_count}\n"
            f"Threat: {threat_info['name']}\n"
            f"Auto-Response: {'✅' if config and config.auto_response_enabled else '❌'}"
        ),
        inline=True
    )
    
    # Server stats
    embed.add_field(
        name="📈 Server Stats",
        value=(
            f"Members: {len(interaction.guild.members)}\n"
            f"Channels: {len(interaction.guild.channels)}\n"
            f"Roles: {len(interaction.guild.roles)}"
        ),
        inline=True
    )
    
    # Active shifts
    active_shifts = len(ACTIVE_SHIFTS.get(interaction.guild.id, {}))
    if active_shifts > 0:
        embed.add_field(
            name="⏱️ Active Shifts",
            value=f"{active_shifts} user(s) on duty",
            inline=True
        )
    
    # Notification stats
    notif_stats = notification_manager.get_stats()
    embed.add_field(
        name="📧 Notifications",
        value=(
            f"Email Queue: {notif_stats['email']['queued']}\n"
            f"Sent: {notif_stats['email']['sent']}\n"
            f"Failed: {notif_stats['email']['failed']}"
        ),
        inline=True
    )
    
    # Action tracker stats
    tracker_stats = action_tracker.get_stats()
    embed.add_field(
        name="📊 Monitoring",
        value=(
            f"Guilds: {tracker_stats['guilds']}\n"
            f"Trackers: {tracker_stats['trackers']}\n"
            f"Actions: {tracker_stats['actions']}"
        ),
        inline=True
    )
    
    embed.set_footer(text=f"Guild ID: {interaction.guild.id}")
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="set_log_channel", description="📝 Set security log channel")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    """Configure log channel"""
    await interaction.response.defer(ephemeral=True)
    
    # Check permissions
    perms = channel.permissions_for(interaction.guild.me)
    if not perms.send_messages or not perms.embed_links:
        await interaction.followup.send(
            "❌ I need **Send Messages** and **Embed Links** permissions in that channel!",
            ephemeral=True
        )
        return
    
    try:
        # Update database
        await db.update_server_field(interaction.guild.id, 'log_channel_id', channel.id)
        
        # Update config
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].log_channel_id = channel.id
        
        # Send confirmation
        embed = discord.Embed(
            title="✅ Log Channel Configured",
            description=f"Security logs will be sent to {channel.mention}",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Send test message
        test_embed = discord.Embed(
            title="🧪 Test Message",
            description="Log channel successfully configured!",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        await channel.send(embed=test_embed)
        
        await log_action(
            interaction.guild,
            'config',
            'Log Channel Set',
            interaction.user,
            f"Set to {channel.mention}"
        )
        
    except Exception as e:
        logger.error(f"Set log channel error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="create_quarantine_role", description="🔒 Create quarantine role")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=1, window=600)
async def create_quarantine_role(interaction: discord.Interaction):
    """Create and configure quarantine role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        # Check if role already exists
        existing = discord.utils.get(interaction.guild.roles, name="Quarantined")
        if existing:
            await interaction.followup.send(
                f"⚠️ Quarantine role already exists: {existing.mention}",
                ephemeral=True
            )
            return
        
        # Create role
        role = await interaction.guild.create_role(
            name="Quarantined",
            color=discord.Color.dark_grey(),
            permissions=discord.Permissions.none(),
            reason=f"Quarantine role created by {interaction.user}"
        )
        
        # Configure channel permissions
        locked_count = 0
        
        for channel in interaction.guild.text_channels:
            try:
                await channel.set_permissions(
                    role,
                    send_messages=False,
                    add_reactions=False,
                    create_public_threads=False,
                    create_private_threads=False,
                    send_messages_in_threads=False
                )
                locked_count += 1
            except:
                pass
        
        for channel in interaction.guild.voice_channels:
            try:
                await channel.set_permissions(
                    role,
                    connect=False,
                    speak=False
                )
                locked_count += 1
            except:
                pass
        
        # Update database and config
        await db.update_server_field(interaction.guild.id, 'quarantine_role_id', role.id)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].quarantine_role_id = role.id
        
        # Send confirmation
        embed = discord.Embed(
            title="✅ Quarantine Role Created",
            description=(
                f"**Role:** {role.mention}\n"
                f"**Permissions set on:** {locked_count} channels\n\n"
                "Users with this role cannot:\n"
                "• Send messages\n"
                "• Add reactions\n"
                "• Join voice channels"
            ),
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'setup',
            'Quarantine Role Created',
            interaction.user,
            f"Created with {locked_count} channels configured"
        )
        
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ I don't have permission to create roles!",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Create quarantine role error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= WHITELIST COMMANDS =============

@bot.tree.command(name="whitelist_add", description="✅ Add user to whitelist")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def whitelist_add(interaction: discord.Interaction, user: discord.User):
    """Add user to whitelist"""
    await interaction.response.defer(ephemeral=True)
    
    if user.bot:
        await interaction.followup.send("❌ Cannot whitelist bots!", ephemeral=True)
        return
    
    if await is_whitelisted(interaction.guild.id, user.id):
        await interaction.followup.send(
            f"⚠️ {user.mention} is already whitelisted!",
            ephemeral=True
        )
        return
    
    success = await add_to_whitelist(interaction.guild.id, user.id, interaction.user.id)
    
    if success:
        embed = discord.Embed(
            title="✅ User Whitelisted",
            description=f"{user.mention} has been added to the whitelist",
            color=discord.Color.green()
        )
        embed.add_field(
            name="Benefits",
            value="• Bypasses security checks\n• Won't trigger auto-quarantine\n• Trusted for sensitive actions",
            inline=False
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'whitelist',
            'User Whitelisted',
            interaction.user,
            f"{user.mention} added by {interaction.user.mention}"
        )
    else:
        await interaction.followup.send("❌ Failed to whitelist user", ephemeral=True)

@bot.tree.command(name="whitelist_remove", description="❌ Remove user from whitelist")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def whitelist_remove(interaction: discord.Interaction, user: discord.User):
    """Remove user from whitelist"""
    await interaction.response.defer(ephemeral=True)
    
    success = await remove_from_whitelist(interaction.guild.id, user.id)
    
    if success:
        embed = discord.Embed(
            title="✅ User Removed from Whitelist",
            description=f"{user.mention} is no longer whitelisted",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'whitelist',
            'User Removed from Whitelist',
            interaction.user,
            f"{user.mention} removed by {interaction.user.mention}"
        )
    else:
        await interaction.followup.send(
            "❌ User was not whitelisted!",
            ephemeral=True
        )

@bot.tree.command(name="whitelist_list", description="📋 List whitelisted users")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def whitelist_list(interaction: discord.Interaction):
    """List all whitelisted users"""
    await interaction.response.defer(ephemeral=True)
    
    wl = whitelists.get(interaction.guild.id, set())
    
    if not wl:
        await interaction.followup.send("ℹ️ No users are whitelisted", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="✅ Whitelisted Users",
        color=discord.Color.green(),
        timestamp=datetime.now(timezone.utc)
    )
    
    users_text = []
    for user_id in list(wl)[:25]:
        user = bot.get_user(user_id)
        if user:
            users_text.append(f"• {user.mention} (`{user.name}`)")
        else:
            users_text.append(f"• User ID: `{user_id}`")
    
    embed.description = "\n".join(users_text)
    embed.set_footer(text=f"Total: {len(wl)} user(s)")
    
    if len(wl) > 25:
        embed.add_field(
            name="Note",
            value=f"Showing first 25 of {len(wl)} whitelisted users",
            inline=False
        )
    
    await interaction.followup.send(embed=embed, ephemeral=True)

# ============= QUARANTINE COMMANDS =============

@bot.tree.command(name="quarantine", description="🔒 Quarantine a user")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def quarantine_cmd(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str = "Manual quarantine"
):
    """Manually quarantine a user"""
    await interaction.response.defer(ephemeral=True)
    
    if user.guild_permissions.administrator:
        await interaction.followup.send(
            "❌ Cannot quarantine administrators!",
            ephemeral=True
        )
        return
    
    if await is_whitelisted(interaction.guild.id, user.id):
        await interaction.followup.send(
            "❌ Cannot quarantine whitelisted users!",
            ephemeral=True
        )
        return
    
    reason = sanitize_string(reason, 500)
    success = await quarantine_user(interaction.guild, user, reason)
    
    if success:
        embed = discord.Embed(
            title="✅ User Quarantined",
            description=f"{user.mention} has been quarantined",
            color=discord.Color.orange()
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    else:
        await interaction.followup.send(
            "❌ Failed to quarantine user!",
            ephemeral=True
        )

@bot.tree.command(name="unquarantine", description="🔓 Remove quarantine from user")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def unquarantine_cmd(interaction: discord.Interaction, user: discord.Member):
    """Remove quarantine from a user"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id)
    
    if not config or not config.quarantine_role_id:
        await interaction.followup.send(
            "❌ Quarantine role not configured!",
            ephemeral=True
        )
        return
    
    qrole = interaction.guild.get_role(config.quarantine_role_id)
    if not qrole:
        await interaction.followup.send(
            "❌ Quarantine role not found!",
            ephemeral=True
        )
        return
    
    if qrole not in user.roles:
        await interaction.followup.send(
            f"❌ {user.mention} is not quarantined!",
            ephemeral=True
        )
        return
    
    try:
        await user.remove_roles(qrole, reason=f"Unquarantined by {interaction.user.name}")
        
        embed = discord.Embed(
            title="✅ User Unquarantined",
            description=f"{user.mention} has been released from quarantine",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await send_alert(
            interaction.guild,
            f"✅ {user.mention} was unquarantined by {interaction.user.mention}",
            user,
            color=discord.Color.green()
        )
        
        await log_action(
            interaction.guild,
            'quarantine',
            'User Unquarantined',
            interaction.user,
            f"{user.mention} released"
        )
        
    except discord.Forbidden:
        await interaction.followup.send(
            "❌ Missing permissions to remove role!",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Unquarantine error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="quarantine_list", description="📋 List quarantined users")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def quarantine_list(interaction: discord.Interaction):
    """List all quarantined users"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id)
    
    if not config or not config.quarantine_role_id:
        await interaction.followup.send(
            "❌ Quarantine role not configured!",
            ephemeral=True
        )
        return
    
    qrole = interaction.guild.get_role(config.quarantine_role_id)
    if not qrole:
        await interaction.followup.send(
            "❌ Quarantine role not found!",
            ephemeral=True
        )
        return
    
    quarantined = [m for m in interaction.guild.members if qrole in m.roles]
    
    if not quarantined:
        await interaction.followup.send(
            "✅ No users are currently quarantined",
            ephemeral=True
        )
        return
    
    embed = discord.Embed(
        title="🔒 Quarantined Users",
        color=discord.Color.dark_grey(),
        timestamp=datetime.now(timezone.utc)
    )
    
    users_text = "\n".join([
        f"• {m.mention} (`{m.name}`)"
        for m in quarantined[:25]
    ])
    
    embed.description = users_text
    embed.set_footer(text=f"Total: {len(quarantined)} user(s)")
    
    if len(quarantined) > 25:
        embed.add_field(
            name="Note",
            value=f"Showing first 25 of {len(quarantined)} quarantined users",
            inline=False
        )
    
    await interaction.followup.send(embed=embed, ephemeral=True)

# ============= THREAT LEVEL COMMANDS =============

@bot.tree.command(name="threat_set", description="🚨 Set server threat level (0-3)")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def threat_set(interaction: discord.Interaction, level: int):
    """Set threat level"""
    await interaction.response.defer(ephemeral=True)
    
    if not 0 <= level <= 3:
        await interaction.followup.send(
            "❌ Threat level must be between 0 and 3!",
            ephemeral=True
        )
        return
    
    try:
        # Update database
        await db.set_threat_level(interaction.guild.id, level)
        
        # Update config
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].threat_level = level
        
        threat_info = THREAT_LEVELS[level]
        
        embed = discord.Embed(
            title="🚨 Threat Level Changed",
            description=threat_info['description'],
            color=threat_info['color'],
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="New Level", value=threat_info['name'], inline=True)
        embed.add_field(name="Changed By", value=interaction.user.mention, inline=True)
        
        if threat_info['actions']:
            embed.add_field(
                name="Active Measures",
                value="\n".join([f"• {action.replace('_', ' ').title()}" for action in threat_info['actions']]),
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Send alert if elevated
        if level >= 2:
            await send_alert(
                interaction.guild,
                f"🚨 Threat level raised to **{threat_info['name']}**\n\n{threat_info['description']}",
                email_admins=True
            )
        
        await log_action(
            interaction.guild,
            'threat',
            'Threat Level Changed',
            interaction.user,
            f"Changed to {threat_info['name']}"
        )
        
    except Exception as e:
        logger.error(f"Threat set error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="threat_status", description="📊 View current threat level")
@rate_limit(max_calls=10, window=60)
async def threat_status(interaction: discord.Interaction):
    """View threat status"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        threat_data = await db.get_current_threat_level(interaction.guild.id)
        level = threat_data.get('threat_level', 0) if threat_data else 0
        
        config = server_configs.get(interaction.guild.id)
        if config:
            level = config.threat_level
        
        threat_info = THREAT_LEVELS[level]
        
        embed = discord.Embed(
            title="🚨 Server Threat Status",
            description=threat_info['description'],
            color=threat_info['color'],
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Current Level", value=threat_info['name'], inline=True)
        embed.add_field(name="Numeric Level", value=str(level), inline=True)
        
        if threat_info['actions']:
            embed.add_field(
                name="⚠️ Active Measures",
                value="\n".join([f"• {action.replace('_', ' ').title()}" for action in threat_info['actions']]),
                inline=False
            )
        
        # Show recent alerts
        recent_alerts = await db.get_recent_alerts(interaction.guild.id, hours=24)
        if recent_alerts:
            embed.add_field(
                name="📋 Recent Alerts (24h)",
                value=f"{len(recent_alerts)} security alert(s)",
                inline=True
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Threat status error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

        """
SENTINEL SECURITY BOT v2.1 - PART 4/5
SHIFT, DEPARTMENT, AND VERIFICATION SYSTEMS

This part contains:
- Shift management commands
- Department management
- Verification systems (Discord + Roblox)
- Warning/moderation system
- Voice monitoring
"""

# ============= LOCKDOWN COMMANDS =============

@bot.tree.command(name="lockdown_enable", description="🔒 Enable emergency lockdown")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=2, window=300)
async def lockdown_enable(
    interaction: discord.Interaction,
    reason: str = "Emergency lockdown"
):
    """Enable server lockdown"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    locked_count = 0
    
    try:
        # Lock text channels
        for channel in interaction.guild.text_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    send_messages=False,
                    add_reactions=False,
                    create_instant_invite=False,
                    reason=f"Lockdown: {reason}"
                )
                locked_count += 1
            except:
                pass
        
        # Lock voice channels
        for channel in interaction.guild.voice_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    connect=False,
                    speak=False,
                    reason=f"Lockdown: {reason}"
                )
                locked_count += 1
            except:
                pass
        
        # Update config
        await db.update_server_field(interaction.guild.id, 'lockdown_enabled', True)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].lockdown_enabled = True
        
        embed = discord.Embed(
            title="🔒 LOCKDOWN ACTIVE",
            description=f"**Locked {locked_count} channels**\n\n**Reason:** {reason}",
            color=discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(
            name="⚠️ Restrictions",
            value="• No messages\n• No reactions\n• No voice access",
            inline=False
        )
        
        embed.add_field(name="Initiated By", value=interaction.user.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await send_alert(
            interaction.guild,
            f"🔒 **SERVER LOCKDOWN ACTIVATED**\n\n**Reason:** {reason}\n**Locked:** {locked_count} channels",
            email_admins=True
        )
        
        await log_action(
            interaction.guild,
            'lockdown',
            'Lockdown Enabled',
            interaction.user,
            f"Reason: {reason}\nLocked {locked_count} channels"
        )
        
    except Exception as e:
        logger.error(f"Lockdown enable error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="lockdown_disable", description="🔓 Disable lockdown")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=2, window=300)
async def lockdown_disable(interaction: discord.Interaction):
    """Disable lockdown"""
    await interaction.response.defer(ephemeral=True)
    
    unlocked_count = 0
    
    try:
        # Unlock text channels
        for channel in interaction.guild.text_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    send_messages=None,
                    add_reactions=None,
                    create_instant_invite=None
                )
                unlocked_count += 1
            except:
                pass
        
        # Unlock voice channels
        for channel in interaction.guild.voice_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    connect=None,
                    speak=None
                )
                unlocked_count += 1
            except:
                pass
        
        # Update config
        await db.update_server_field(interaction.guild.id, 'lockdown_enabled', False)
        
        config = server_configs.get(interaction.guild.id)
        if config:
            config.lockdown_enabled = False
        
        embed = discord.Embed(
            title="🔓 LOCKDOWN LIFTED",
            description=f"**Unlocked {unlocked_count} channels**\n\nNormal permissions restored",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Lifted By", value=interaction.user.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'lockdown',
            'Lockdown Disabled',
            interaction.user,
            f"Unlocked {unlocked_count} channels"
        )
        
    except Exception as e:
        logger.error(f"Lockdown disable error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= SHIFT MANAGEMENT =============

@bot.tree.command(name="shift_start", description="⏱️ Start a work shift")
@rate_limit(max_calls=5, window=60)
async def shift_start(
    interaction: discord.Interaction,
    department: str = None,
    callsign: str = None
):
    """Start a shift"""
    await interaction.response.defer(ephemeral=True)
    
    if department:
        department = sanitize_string(department, 50)
    if callsign:
        callsign = sanitize_string(callsign, 50)
    
    try:
        user_id = interaction.user.id
        guild_id = interaction.guild.id
        
        # Check if already on shift
        if user_id in ACTIVE_SHIFTS[guild_id]:
            await interaction.followup.send(
                "❌ You already have an active shift! Use `/shift_end` first.",
                ephemeral=True
            )
            return
        
        # Check if department is suspended
        if department:
            dept = await db.get_department(guild_id, department)
            if dept and dept.get('suspended'):
                await interaction.followup.send(
                    f"❌ Department '{department}' is suspended!",
                    ephemeral=True
                )
                return
        
        # Create shift
        start_time = datetime.now(timezone.utc)
        ACTIVE_SHIFTS[guild_id][user_id] = {
            'start_time': start_time,
            'department': department,
            'callsign': callsign,
            'status': 'active'
        }
        
        await db.create_shift(guild_id, user_id, department, start_time, callsign=callsign)
        
        # Add on-duty role
        config = server_configs.get(guild_id)
        if config and config.onduty_role_id:
            member = interaction.guild.get_member(user_id)
            role = interaction.guild.get_role(config.onduty_role_id)
            if member and role:
                try:
                    await member.add_roles(role, reason="Shift started")
                except:
                    pass
        
        # Send confirmation
        embed = discord.Embed(
            title="✅ Shift Started",
            description=f"{interaction.user.mention} is now on duty",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if department:
            embed.add_field(name="Department", value=department, inline=True)
        if callsign:
            embed.add_field(name="Callsign", value=callsign, inline=True)
        
        embed.add_field(
            name="Start Time",
            value=start_time.strftime('%H:%M:%S UTC'),
            inline=True
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'shift',
            'Shift Started',
            interaction.user,
            f"Department: {department or 'None'}, Callsign: {callsign or 'None'}"
        )
        
    except Exception as e:
        logger.error(f"Shift start error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_end", description="⏱️ End your shift")
@rate_limit(max_calls=5, window=60)
async def shift_end(interaction: discord.Interaction):
    """End shift"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        user_id = interaction.user.id
        guild_id = interaction.guild.id
        
        # Check if on shift
        if user_id not in ACTIVE_SHIFTS[guild_id]:
            await interaction.followup.send(
                "❌ You don't have an active shift!",
                ephemeral=True
            )
            return
        
        # Check if locked
        if SHIFT_LOCKS[guild_id][user_id]:
            await interaction.followup.send(
                "🔒 Your shift is locked! Contact an administrator.",
                ephemeral=True
            )
            return
        
        # End shift
        shift = ACTIVE_SHIFTS[guild_id][user_id]
        end_time = datetime.now(timezone.utc)
        duration = (end_time - shift['start_time']).total_seconds()
        
        await db.end_shift(guild_id, user_id, end_time, duration)
        del ACTIVE_SHIFTS[guild_id][user_id]
        
        # Remove on-duty role
        config = server_configs.get(guild_id)
        if config and config.onduty_role_id:
            member = interaction.guild.get_member(user_id)
            role = interaction.guild.get_role(config.onduty_role_id)
            if member and role:
                try:
                    await member.remove_roles(role, reason="Shift ended")
                except:
                    pass
        
        # Calculate duration
        hours = int(duration // 3600)
        minutes = int((duration % 3600) // 60)
        
        embed = discord.Embed(
            title="✅ Shift Ended",
            description=f"{interaction.user.mention}'s shift is complete",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="Duration", value=f"{hours}h {minutes}m", inline=True)
        
        if shift.get('department'):
            embed.add_field(name="Department", value=shift['department'], inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'shift',
            'Shift Ended',
            interaction.user,
            f"Duration: {hours}h {minutes}m"
        )
        
    except Exception as e:
        logger.error(f"Shift end error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="shift_status", description="📊 Check shift status")
@rate_limit(max_calls=10, window=60)
async def shift_status(interaction: discord.Interaction, user: discord.Member = None):
    """Check shift status"""
    await interaction.response.defer(ephemeral=True)
    
    target = user or interaction.user
    user_id = target.id
    guild_id = interaction.guild.id
    
    try:
        if user_id in ACTIVE_SHIFTS[guild_id]:
            shift = ACTIVE_SHIFTS[guild_id][user_id]
            elapsed = (datetime.now(timezone.utc) - shift['start_time']).total_seconds()
            
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            
            embed = discord.Embed(
                title="🟢 Shift Active",
                description=f"{target.mention} is currently on duty",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc)
            )
            
            embed.add_field(name="Elapsed Time", value=f"{hours}h {minutes}m {seconds}s", inline=True)
            
            if shift.get('department'):
                embed.add_field(name="Department", value=shift['department'], inline=True)
            
            if shift.get('callsign'):
                embed.add_field(name="Callsign", value=shift['callsign'], inline=True)
            
            is_locked = SHIFT_LOCKS[guild_id].get(user_id, False)
            embed.add_field(
                name="Status",
                value="🔒 Locked" if is_locked else "🔓 Active",
                inline=True
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            embed = discord.Embed(
                title="❌ No Active Shift",
                description=f"{target.mention} is not currently on duty",
                color=discord.Color.red()
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
    except Exception as e:
        logger.error(f"Shift status error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= VERIFICATION VIEWS =============

class VerificationView(discord.ui.View):
    """Simple verification button"""
    
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(
        label="✅ Verify",
        style=discord.ButtonStyle.green,
        custom_id="verify_button"
    )
    async def verify_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):
        """Handle verification"""
        config = server_configs.get(interaction.guild.id)
        
        if not config or not config.verified_role_id:
            await interaction.response.send_message(
                "❌ Verification not configured!",
                ephemeral=True
            )
            return
        
        verified_role = interaction.guild.get_role(config.verified_role_id)
        unverified_role = interaction.guild.get_role(config.unverified_role_id) if config.unverified_role_id else None
        
        member = interaction.user
        
        # Check if already verified
        if verified_role and verified_role in member.roles:
            await interaction.response.send_message(
                "✅ You're already verified!",
                ephemeral=True
            )
            return
        
        try:
            # Add verified role
            if verified_role:
                await member.add_roles(verified_role, reason="Member verified")
            
            # Remove unverified role
            if unverified_role and unverified_role in member.roles:
                await member.remove_roles(unverified_role, reason="Member verified")
            
            await interaction.response.send_message(
                "✅ You have been verified!",
                ephemeral=True
            )
            
            await log_action(
                interaction.guild,
                'verification',
                'User Verified',
                member,
                f"{member.mention} verified via button"
            )
            
            await db.add_log(
                interaction.guild.id,
                'member_verified',
                member.id,
                {'verification_method': 'button'}
            )
            
        except discord.Forbidden:
            await interaction.response.send_message(
                "❌ Missing permissions!",
                ephemeral=True
            )
        except Exception as e:
            logger.error(f"Verification error: {e}")
            await interaction.response.send_message(
                "❌ Verification failed!",
                ephemeral=True
            )

class RobloxVerificationView(discord.ui.View):
    """Roblox verification system"""
    
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(
        label="🎮 Start Verification",
        style=discord.ButtonStyle.green,
        custom_id="roblox_verify_start"
    )
    async def start_verification(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):
        """Start Roblox verification"""
        try:
            # Check if already verified
            verification = await db.get_verification(
                interaction.guild.id,
                interaction.user.id
            )
            
            if verification and verification.get('verified'):
                await interaction.response.send_message(
                    "✅ You're already verified!",
                    ephemeral=True
                )
                return
            
            # Generate code
            code = f"VERIFY-{generate_verification_code()}"
            
            # Create verification
            await db.create_verification(
                interaction.guild.id,
                interaction.user.id,
                code
            )
            
            # Send instructions
            embed = discord.Embed(
                title="🎮 Roblox Verification",
                description=(
                    f"**Your verification code:** `{code}`\n\n"
                    "**Steps:**\n"
                    "1. Go to [Roblox Settings](https://www.roblox.com/my/account#!/info)\n"
                    "2. Add the code to your **About** section\n"
                    "3. Click 'I've added the code' below\n"
                    "4. Enter your Roblox username\n\n"
                    "⏰ Code expires in 5 minutes"
                ),
                color=discord.Color.blue()
            )
            
            view = RobloxVerificationConfirmView()
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
            
        except Exception as e:
            logger.error(f"Roblox verification start error: {e}")
            await interaction.response.send_message(
                "❌ Verification failed!",
                ephemeral=True
            )

class RobloxVerificationConfirmView(discord.ui.View):
    """Confirmation view for Roblox verification"""
    
    def __init__(self):
        super().__init__(timeout=VERIFICATION_TIMEOUT)
    
    @discord.ui.button(
        label="I've added the code",
        style=discord.ButtonStyle.green,
        custom_id="roblox_verify_confirm"
    )
    async def confirm_verification(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button
    ):
        """Confirm and complete verification"""
        await interaction.response.defer(ephemeral=True)
        
        try:
            verification = await db.get_verification(
                interaction.guild.id,
                interaction.user.id
            )
            
            if not verification:
                await interaction.followup.send(
                    "❌ No verification in progress!",
                    ephemeral=True
                )
                return
            
            if verification.get('verified'):
                await interaction.followup.send(
                    "✅ Already verified!",
                    ephemeral=True
                )
                return
            
            # Ask for username
            await interaction.followup.send(
                "Please reply with your **Roblox username**:",
                ephemeral=True
            )
            
            def check(m):
                return m.author == interaction.user and isinstance(m.channel, discord.DMChannel)
            
            try:
                msg = await bot.wait_for('message', timeout=60.0, check=check)
                roblox_username = sanitize_string(msg.content.strip(), 20)
                
                # Fetch Roblox profile
                await interaction.followup.send(
                    "🔍 Checking your Roblox profile...",
                    ephemeral=True
                )
                
                roblox_data = await get_roblox_user_info(roblox_username)
                
                if not roblox_data:
                    await interaction.followup.send(
                        f"❌ Roblox user '{roblox_username}' not found!",
                        ephemeral=True
                    )
                    return
                
                # Verify code
                if verification['verification_code'] not in roblox_data['description']:
                    await interaction.followup.send(
                        "❌ Verification code not found in your profile description!",
                        ephemeral=True
                    )
                    return
                
                # Complete verification
                await db.complete_verification(
                    interaction.guild.id,
                    interaction.user.id,
                    roblox_data['id'],
                    roblox_data['username']
                )
                
                # Add roles
                config = server_configs.get(interaction.guild.id)
                member = interaction.guild.get_member(interaction.user.id)
                
                if config and member:
                    if config.verified_role_id:
                        verified_role = interaction.guild.get_role(config.verified_role_id)
                        if verified_role:
                            await member.add_roles(verified_role, reason="Roblox verification")
                    
                    if config.unverified_role_id:
                        unverified_role = interaction.guild.get_role(config.unverified_role_id)
                        if unverified_role and unverified_role in member.roles:
                            await member.remove_roles(unverified_role, reason="Roblox verification")
                
                # Success
                embed = discord.Embed(
                    title="✅ Verification Complete!",
                    description=(
                        f"**Roblox Account:** {roblox_data['username']}\n"
                        f"**Roblox ID:** {roblox_data['id']}\n\n"
                        "You are now verified!"
                    ),
                    color=discord.Color.green()
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
                await log_action(
                    interaction.guild,
                    'verification',
                    'Roblox Verified',
                    interaction.user,
                    f"Verified as {roblox_data['username']}"
                )
                
            except asyncio.TimeoutError:
                await interaction.followup.send(
                    "❌ Verification timeout!",
                    ephemeral=True
                )
                
        except Exception as e:
            logger.error(f"Roblox verification confirm error: {e}")
            await interaction.followup.send(
                "❌ Verification failed!",
                ephemeral=True
            )

def generate_verification_code() -> str:
    """Generate random verification code"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=VERIFICATION_CODE_LENGTH))

async def get_roblox_user_info(username: str) -> Optional[Dict[str, Any]]:
    """Fetch Roblox user information"""
    username = sanitize_string(username, 20)
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            # Get user ID
            async with session.post(
                'https://users.roblox.com/v1/usernames/users',
                json={'usernames': [username], 'excludeBannedUsers': True}
            ) as resp:
                if resp.status != 200:
                    return None
                
                data = await resp.json()
                if not data.get('data') or len(data['data']) == 0:
                    return None
                
                user_data = data['data'][0]
                user_id = user_data['id']
                
                # Get profile details
                async with session.get(
                    f'https://users.roblox.com/v1/users/{user_id}'
                ) as profile_resp:
                    if profile_resp.status == 200:
                        profile_data = await profile_resp.json()
                        return {
                            'id': user_id,
                            'username': user_data['name'],
                            'displayName': user_data['displayName'],
                            'description': profile_data.get('description', '')[:2000]
                        }
        
        return None
        
    except asyncio.TimeoutError:
        logger.error('Roblox API timeout')
        return None
    except Exception as e:
        logger.error(f'Roblox API error: {e}')
        return None

# ============= WARNING SYSTEM =============

@bot.tree.command(name="warn", description="⚠️ Issue warning to user")
@app_commands.checks.has_permissions(manage_messages=True)
@rate_limit(max_calls=10, window=60)
async def warn(
    interaction: discord.Interaction,
    user: discord.Member,
    reason: str
):
    """Warn a user"""
    await interaction.response.defer(ephemeral=True)
    
    if user.bot:
        await interaction.followup.send("❌ Cannot warn bots!", ephemeral=True)
        return
    
    if user.guild_permissions.administrator:
        await interaction.followup.send(
            "❌ Cannot warn administrators!",
            ephemeral=True
        )
        return
    
    if await is_whitelisted(interaction.guild.id, user.id):
        await interaction.followup.send(
            "❌ Cannot warn whitelisted users!",
            ephemeral=True
        )
        return
    
    reason = sanitize_string(reason, 500)
    
    try:
        # Add warning
        warning_id = await db.add_warning(
            interaction.guild.id,
            user.id,
            interaction.user.id,
            reason
        )
        
        # Get total warnings
        warnings = await db.get_active_warnings(interaction.guild.id, user.id)
        warning_count = len(warnings)
        
        embed = discord.Embed(
            title="⚠️ Warning Issued",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(name="User", value=user.mention, inline=True)
        embed.add_field(name="Warned By", value=interaction.user.mention, inline=True)
        embed.add_field(
            name="Warning Count",
            value=f"{warning_count}/{WARNING_CONFIG['max_warnings']}",
            inline=True
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.add_field(name="Warning ID", value=f"`{warning_id}`", inline=True)
        
        # Auto-actions
        action_taken = None
        
        if warning_count >= WARNING_CONFIG['max_warnings']:
            # QUARANTINE
            success = await quarantine_user(
                interaction.guild,
                user,
                f"Exceeded warning limit ({warning_count} warnings)"
            )
            if success:
                action_taken = "🔒 User quarantined (max warnings)"
                embed.color = discord.Color.red()
        
        elif warning_count == 2:
            # TIMEOUT
            try:
                timeout_until = datetime.now(timezone.utc) + timedelta(
                    seconds=WARNING_CONFIG['timeout_duration']
                )
                await user.timeout(
                    timeout_until,
                    reason=f"Warning #{warning_count}: {reason}"
                )
                action_taken = f"⏰ User timed out for {WARNING_CONFIG['timeout_duration']//60} minutes"
            except:
                action_taken = "⚠️ Failed to timeout user"
        
        if action_taken:
            embed.add_field(name="Auto-Action", value=action_taken, inline=False)
        
        if warning_count >= WARNING_CONFIG['max_warnings']:
            embed.add_field(
                name="⚠️ CRITICAL",
                value="User has reached maximum warnings!",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # DM user
        try:
            dm_embed = discord.Embed(
                title=f"⚠️ Warning in {interaction.guild.name}",
                color=discord.Color.orange()
            )
            dm_embed.add_field(name="Reason", value=reason, inline=False)
            dm_embed.add_field(
                name="Warnings",
                value=f"{warning_count}/{WARNING_CONFIG['max_warnings']}",
                inline=True
            )
            
            if action_taken:
                dm_embed.add_field(name="Action Taken", value=action_taken, inline=False)
            
            await user.send(embed=dm_embed)
        except:
            pass
        
        await log_action(
            interaction.guild,
            'moderation',
            'Warning Issued',
            interaction.user,
            f"{user.mention} warned\nReason: {reason}\nTotal: {warning_count}"
        )
        
    except Exception as e:
        logger.error(f"Warning error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= BACKGROUND TASKS =============

@tasks.loop(minutes=5)
async def shift_heartbeat():
    """Monitor active shifts"""
    try:
        for guild_id, shifts in ACTIVE_SHIFTS.items():
            for user_id, shift in list(shifts.items()):
                elapsed = (datetime.now(timezone.utc) - shift['start_time']).total_seconds()
                
                await db.add_log(
                    guild_id,
                    'shift_heartbeat',
                    user_id,
                    {'elapsed_seconds': int(elapsed)}
                )
    except Exception as e:
        logger.error(f"Shift heartbeat error: {e}")

@tasks.loop(hours=1)
async def cleanup_old_logs():
    """Clean up old logs"""
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        await db.delete_old_logs(cutoff)
        logger.info("✅ Cleaned up old logs")
    except Exception as e:
        logger.error(f"Log cleanup error: {e}")

"""
SENTINEL SECURITY BOT v2.1 - PART 5/5
EVENT HANDLERS, MONITORING, AND BOT EXECUTION

This part contains:
- Event handlers (joins, leaves, role changes, etc.)
- Security monitoring events
- Voice monitoring
- Daily reporting system
- Bot execution
"""

# ============= CONTINUED BACKGROUND TASKS =============

logger.error(f"Log cleanup error: {e}")

@tasks.loop(hours=6)
async def reset_daily_threat():
    """Auto-reset threat level if no incidents"""
    try:
        for guild_id, config in server_configs.items():
            if config.threat_level > 0:
                # Check for recent incidents
                recent_alerts = await db.get_recent_alerts(guild_id, hours=6)
                
                if not recent_alerts:
                    # Reset to clear
                    await db.set_threat_level(guild_id, 0)
                    config.threat_level = 0
                    logger.info(f"✅ Auto-reset threat level for guild {guild_id}")
    except Exception as e:
        logger.error(f"Threat reset error: {e}")

@tasks.loop(hours=24)
async def security_scan_task():
    """Daily security scan"""
    try:
        for guild in bot.guilds:
            report = await security_monitor.scan_guild_security(guild)
            
            if report['score'] < 70:
                # Send report to admins
                config = server_configs.get(guild.id)
                if config and config.log_channel_id:
                    channel = guild.get_channel(config.log_channel_id)
                    if channel:
                        embed = discord.Embed(
                            title="🔍 Daily Security Scan",
                            description=f"**Security Score:** {report['score']}/100 {report['rating']}",
                            color=discord.Color.orange() if report['score'] < 50 else discord.Color.gold()
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
        
        logger.info("✅ Daily security scan complete")
    except Exception as e:
        logger.error(f"Security scan error: {e}")

@tasks.loop(minutes=5)
async def daily_violation_report():
    """Send daily violation reports"""
    try:
        now = datetime.now(timezone.utc)
        current_time = now.time()
        
        # Send at 6 AM UTC
        report_time_start = time(6, 0, 0)
        report_time_end = time(6, 5, 0)
        
        if not (report_time_start <= current_time < report_time_end):
            return
        
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
                
                for email in admin_emails[:MAX_EMAIL_RECIPIENTS]:
                    await send_violation_report_email(email, guild.name, report)
                
                last_report_time[guild_id] = now
                
                await log_action(
                    guild,
                    'daily_report',
                    'Daily Violation Report Sent',
                    None,
                    f"Sent to {len(admin_emails)} admin(s)"
                )
                
            except Exception as e:
                logger.error(f"Report error for {guild.name}: {e}")
        
        logger.info("✅ Daily violation reports sent")
        
    except Exception as e:
        logger.error(f"Daily report task error: {e}")

async def generate_violation_report(
    guild: discord.Guild,
    violations: List[Dict],
    quarantine_logs: List[Dict],
    threat_logs: List[Dict]
) -> Dict[str, Any]:
    """Generate violation report"""
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
    """Send violation report via email"""
    try:
        subject = f"🛡️ Sentinel Daily Report - {guild_name}"
        
        text = f"""
SENTINEL SECURITY BOT - DAILY VIOLATION REPORT

Server: {guild_name}
Date: {report['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}
Period: Last 24 Hours

SUMMARY
-------
Violations: {report['summary']['total_violations']}
Quarantines: {report['summary']['total_quarantines']}
Threat Changes: {report['summary']['total_threats']}

VIOLATIONS
----------
"""
        
        for v in report['violations'][:5]:
            text += f"• {v['user']} - {v['type']} ({v['timestamp']})\n"
        
        text += "\n---\nSentinel Security Bot v2.1\n"
        
        html = f"""
        <html>
        <body style="font-family: Arial; background: #f5f5f5; padding: 20px;">
            <div style="max-width: 700px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px;">
                <h1 style="color: #667eea;">🛡️ Daily Security Report</h1>
                <p><strong>Server:</strong> {guild_name}</p>
                <p><strong>Date:</strong> {report['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                
                <div style="background: #f0f0f0; padding: 15px; border-radius: 6px; margin: 20px 0;">
                    <h3>Summary</h3>
                    <p>Violations: {report['summary']['total_violations']}</p>
                    <p>Quarantines: {report['summary']['total_quarantines']}</p>
                    <p>Threat Changes: {report['summary']['total_threats']}</p>
                </div>
                
                <p style="color: #666; font-size: 12px;">Sentinel Security Bot v2.1</p>
            </div>
        </body>
        </html>
        """
        
        await notification_manager.send_email(email, subject, text, html)
        return True
        
    except Exception as e:
        logger.error(f"Violation email error: {e}")
        return False

# ============= EVENT HANDLERS =============

@bot.event
async def on_member_join(member: discord.Member):
    """Monitor member joins"""
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
        
        logger.info(f"Member joined: {member.name} in {guild.name}")
        
    except Exception as e:
        logger.error(f"Member join error: {e}")

@bot.event
async def on_member_remove(member: discord.Member):
    """Monitor member leaves"""
    try:
        await db.add_log(
            member.guild.id,
            'member_remove',
            member.id,
            {'username': member.name}
        )
        
        logger.info(f"Member left: {member.name} from {member.guild.name}")
        
    except Exception as e:
        logger.error(f"Member remove error: {e}")

@bot.event
async def on_guild_role_delete(role: discord.Role):
    """Monitor role deletions"""
    try:
        await asyncio.sleep(1)
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
                        f"⚠️ **MASS ROLE DELETION**\n{user.mention} deleted {count} roles in {threshold['window']} seconds!",
                        user,
                        email_admins=True
                    )
                    
                    await security_monitor.auto_response(guild, 'mass_delete', user, severity=2)
                
                break
                
    except Exception as e:
        logger.error(f"Role delete event error: {e}")

@bot.event
async def on_guild_channel_delete(channel):
    """Monitor channel deletions"""
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
                        f"⚠️ **MASS CHANNEL DELETION**\n{user.mention} deleted {count} channels in {threshold['window']} seconds!",
                        user,
                        email_admins=True
                    )
                    
                    await security_monitor.auto_response(guild, 'mass_delete', user, severity=2)
                
                break
                
    except Exception as e:
        logger.error(f"Channel delete event error: {e}")

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Monitor role changes"""
    try:
        if before.roles != after.roles:
            added = [r for r in after.roles if r not in before.roles]
            removed = [r for r in before.roles if r not in after.roles]
            
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
        logger.error(f"Member update error: {e}")

@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    """Monitor voice activity"""
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
                title="🎤 Voice Join",
                description=f"{member.mention} joined {after.channel.mention}",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc)
            )
            
            await log_channel.send(embed=embed)
            
            await db.add_log(
                guild_id,
                'voice_join',
                member.id,
                {
                    'channel_id': after.channel.id,
                    'channel_name': after.channel.name
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
                title="🔇 Voice Leave",
                description=f"{member.mention} left {before.channel.mention}",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc)
            )
            
            if duration:
                hours = int(duration // 3600)
                minutes = int((duration % 3600) // 60)
                embed.add_field(name="Duration", value=f"{hours}h {minutes}m", inline=True)
            
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
        
    except Exception as e:
        logger.error(f"Voice state update error: {e}")

# ============= ADMIN COMMANDS =============

@bot.tree.command(name="security_scan", description="🔍 Run security scan")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def security_scan_cmd(interaction: discord.Interaction):
    """Manual security scan"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        report = await security_monitor.scan_guild_security(interaction.guild)
        
        embed = discord.Embed(
            title="🔍 Security Scan Results",
            description=f"**Score:** {report['score']}/100 {report['rating']}",
            color=discord.Color.green() if report['score'] >= 70 else discord.Color.orange(),
            timestamp=datetime.now(timezone.utc)
        )
        
        if report['issues']:
            embed.add_field(
                name="⚠️ Issues",
                value="\n".join([f"• {issue}" for issue in report['issues'][:5]]),
                inline=False
            )
        
        if report['recommendations']:
            embed.add_field(
                name="💡 Recommendations",
                value="\n".join([f"• {rec}" for rec in report['recommendations'][:5]]),
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Security scan error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="logs", description="📋 View recent logs")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def logs_cmd(
    interaction: discord.Interaction,
    category: str = None,
    limit: int = 10
):
    """View logs"""
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
            embed.description = f"**Category:** {category}\n\n"
        
        logs_text = []
        for i, entry in enumerate(log_entries[:10], 1):
            cat = entry.get('category', 'unknown').upper()
            user_id = entry.get('user_id')
            ts = entry.get('timestamp', 'N/A')
            
            user = bot.get_user(user_id) if user_id else None
            user_name = user.name if user else f"User {user_id}"
            
            logs_text.append(f"**{i}.** [{cat}] {user_name} - {ts}")
        
        embed.description = (embed.description or "") + "\n".join(logs_text)
        embed.set_footer(text=f"Showing {len(logs_text)} of {len(log_entries)} entries")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Logs error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="notification_stats", description="📊 View notification statistics")
@app_commands.checks.has_permissions(administrator=True)
async def notification_stats_cmd(interaction: discord.Interaction):
    """View notification stats"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        stats = notification_manager.get_stats()
        
        embed = discord.Embed(
            title="📊 Notification Statistics",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc)
        )
        
        embed.add_field(
            name="📧 Email",
            value=(
                f"Queued: {stats['email']['queued']}\n"
                f"Sent: {stats['email']['sent']}\n"
                f"Failed: {stats['email']['failed']}"
            ),
            inline=True
        )
        
        embed.add_field(
            name="📱 SMS",
            value=(
                f"Queued: {stats['sms']['queued']}\n"
                f"Sent: {stats['sms']['sent']}\n"
                f"Failed: {stats['sms']['failed']}"
            ),
            inline=True
        )
        
        embed.add_field(
            name="Status",
            value="🟢 Active" if stats['processing'] else "🔴 Inactive",
            inline=True
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Notification stats error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="help", description="❓ View help and documentation")
@rate_limit(max_calls=5, window=60)
async def help_cmd(interaction: discord.Interaction):
    """Show help"""
    embed = discord.Embed(
        title="🛡️ Sentinel Security Bot - Help",
        description="Advanced security and management bot for Discord servers",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="🔧 Setup Commands",
        value=(
            "`/setup` - Setup guide\n"
            "`/status` - Bot status\n"
            "`/set_log_channel` - Configure logging\n"
            "`/create_quarantine_role` - Create quarantine role"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔒 Security Commands",
        value=(
            "`/whitelist_add` - Add trusted user\n"
            "`/quarantine` - Quarantine user\n"
            "`/threat_set` - Set threat level\n"
            "`/lockdown_enable` - Emergency lockdown"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⏱️ Shift Commands",
        value=(
            "`/shift_start` - Start shift\n"
            "`/shift_end` - End shift\n"
            "`/shift_status` - Check status"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⚠️ Moderation",
        value=(
            "`/warn` - Issue warning\n"
            "`/warnings` - View warnings"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔍 Monitoring",
        value=(
            "`/security_scan` - Security scan\n"
            "`/logs` - View logs\n"
            "`/notification_stats` - Email/SMS stats"
        ),
        inline=False
    )
    
    embed.set_footer(text="Sentinel Security Bot v2.1")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="daily_reports_enable", description="📧 Enable daily reports")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def daily_reports_enable_cmd(interaction: discord.Interaction):
    """Enable daily reports"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'daily_reports_enabled', True)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = SecurityConfig()
        server_configs[interaction.guild.id].daily_reports_enabled = True
        
        embed = discord.Embed(
            title="✅ Daily Reports Enabled",
            description="Admins will receive daily violation reports at 6 AM UTC",
            color=discord.Color.green()
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

@bot.tree.command(name="set_admin_email", description="📧 Set your admin email")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def set_admin_email_cmd(interaction: discord.Interaction, email: str):
    """Set admin email"""
    await interaction.response.defer(ephemeral=True)
    
    if not validate_email(email):
        await interaction.followup.send("❌ Invalid email address!", ephemeral=True)
        return
    
    email = sanitize_string(email, 254).lower()
    
    try:
        await db.set_user_email(interaction.guild.id, interaction.user.id, email)
        
        embed = discord.Embed(
            title="✅ Email Configured",
            description=f"Email set to: `{email}`",
            color=discord.Color.green()
        )
        embed.add_field(
            name="You will receive:",
            value="• Security alerts\n• Daily reports\n• Critical notifications",
            inline=False
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        # Send confirmation email
        if SENTINEL_EMAIL:
            asyncio.create_task(
                notification_manager.send_email(
                    email,
                    f"✅ Email Configured: {interaction.guild.name}",
                    f"Your email has been configured for security alerts from {interaction.guild.name}.",
                    f"<html><body><h2>Email Configured</h2><p>You will now receive security alerts from {interaction.guild.name}</p></body></html>"
                )
            )
        
    except Exception as e:
        logger.error(f"Set email error: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= BOT EXECUTION =============

@shift_heartbeat.before_loop
@cleanup_old_logs.before_loop
@reset_daily_threat.before_loop
@daily_violation_report.before_loop
@security_scan_task.before_loop
async def before_loops():
    """Wait for bot to be ready"""
    await bot.wait_until_ready()

async def main():
    """Main execution function"""
    async with bot:
        try:
            logger.info("🚀 Starting Sentinel Security Bot v2.1...")
            await bot.start(TOKEN)
        except KeyboardInterrupt:
            logger.info("⛔ Bot stopped by user")
        except Exception as e:
            logger.critical(f"❌ Critical error: {e}")
        finally:
            # Cleanup
            await notification_manager.stop_processing()
            logger.info("👋 Sentinel Security Bot shutting down...")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("⛔ Stopped by user")
    except Exception as e:
        logger.critical(f"❌ Fatal error: {e}")