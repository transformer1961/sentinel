"""
SENTINEL SECURITY BOT v2.0 - PART 1/4 (Lines 1-900)
Complete role hierarchy, permissions, email, shifts, departments
"""

import discord
from discord.ext import commands
from discord import app_commands
import os
from dotenv import load_dotenv
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import aiohttp
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
from typing import Optional, List, Dict, Any
from functools import wraps
import time
from discord.ext import tasks
from datetime import datetime, timezone

try:
    import database as db
except ImportError:
    print("ERROR: database.py not found!")
    exit(1)

# ============= LOGGING =============
import sys

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_bot.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('SecurityBot')

# ============= CONFIG =============
load_dotenv()

TOKEN = os.getenv('DISCORD_TOKEN')
if not TOKEN:
    logger.critical("DISCORD_TOKEN not found!")
    raise ValueError("DISCORD_TOKEN required")

SENTINEL_EMAIL = os.getenv('SENTINEL_EMAIL')
SENTINEL_EMAIL_PASS = os.getenv('SENTINEL_EMAIL_PASS')

if SENTINEL_EMAIL and not SENTINEL_EMAIL_PASS:
    logger.warning("Email incomplete - features disabled")

intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True
intents.moderation = True

bot = commands.Bot(command_prefix='!', intents=intents)

# ============= CONSTANTS =============
MAX_PARTNERSHIPS_DISPLAY = 10
VERIFICATION_CODE_LENGTH = 8
VERIFICATION_TIMEOUT = 300
MAX_EMAIL_RECIPIENTS = 10
MAX_AUDIT_LOG_CHECKS = 5
RATE_LIMIT_WINDOW = 60
MAX_ACTIONS_PER_WINDOW = 10

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
DISCORD_ID_MIN = 100000000000000000
DISCORD_ID_MAX = 999999999999999999

DEFAULT_THRESHOLDS = {
    'channel_delete': {'count': 3, 'seconds': 10},
    'channel_create': {'count': 5, 'seconds': 10},
    'role_delete': {'count': 3, 'seconds': 10},
    'member_ban': {'count': 5, 'seconds': 30},
}

THREAT_LEVELS = {
    0: {"name": "🟢 Clear", "color": discord.Color.green(), "description": "Normal operations"},
    1: {"name": "🟡 Elevated", "color": discord.Color.gold(), "description": "Minor threat"},
    2: {"name": "🟠 High", "color": discord.Color.orange(), "description": "Serious threat"},
    3: {"name": "🔴 Alpha", "color": discord.Color.red(), "description": "FULL BREACH"}
}

ROLE_HIERARCHY = {
    'OWNER': 9, 'DIRECTOR': 9, 'MANAGEMENT': 8, 'INTERNAL_AFFAIRS': 7,
    'ADMINISTRATOR': 6, 'MODERATOR': 5, 'DEPARTMENT_HEAD': 4,
    'SUPERVISOR': 3, 'MEMBER': 2, 'USER': 1
}

# ============= STORAGE =============
server_configs = {}
whitelists = defaultdict(set)
action_tracker = defaultdict(lambda: defaultdict(list))
rate_limit_tracker = defaultdict(list)
ACTIVE_SHIFTS = defaultdict(dict)
SHIFT_LOCKS = defaultdict(lambda: defaultdict(bool))

# ============= PERMISSIONS =============

async def get_user_tier(guild_id: int, user_id: int) -> int:
    """Get user tier"""
    try:
        data = await db.get_member_tier(guild_id, user_id)
        return data.get('tier', 1) if data else 1
    except:
        return 1

async def check_permission(guild_id: int, user_id: int, required_tier: int) -> bool:
    """Check permission"""
    tier = await get_user_tier(guild_id, user_id)
    return tier >= required_tier

def require_permission(min_tier: int):
    """Permission decorator"""
    def decorator(func):
        @wraps(func)
        async def wrapper(interaction: discord.Interaction, *args, **kwargs):
            has = await check_permission(interaction.guild.id, interaction.user.id, min_tier)
            if not has:
                tier_names = [k for k, v in ROLE_HIERARCHY.items() if v == min_tier]
                await interaction.response.send_message(
                    f"❌ Permission denied. Required: {tier_names[0] if tier_names else min_tier}",
                    ephemeral=True
                )
                return
            return await func(interaction, *args, **kwargs)
        return wrapper
    return decorator

# ============= RATE LIMIT =============

def rate_limit(max_calls: int = MAX_ACTIONS_PER_WINDOW, window: int = RATE_LIMIT_WINDOW):
    """Rate limit"""
    def decorator(func):
        @wraps(func)
        async def wrapper(interaction: discord.Interaction, *args, **kwargs):
            uid = interaction.user.id
            now = time.time()
            
            rate_limit_tracker[uid] = [t for t in rate_limit_tracker[uid] if now - t < window]
            
            if len(rate_limit_tracker[uid]) >= max_calls:
                await interaction.response.send_message(f"⏳ Rate limited", ephemeral=True)
                return
            
            rate_limit_tracker[uid].append(now)
            return await func(interaction, *args, **kwargs)
        return wrapper
    return decorator

# ============= VALIDATION =============

def validate_email(email: str) -> bool:
    """Validate email"""
    if not email or len(email) > 254:
        return False
    return EMAIL_REGEX.match(email) is not None

def validate_discord_id(did: int) -> bool:
    """Validate Discord ID"""
    return DISCORD_ID_MIN <= did <= DISCORD_ID_MAX

def sanitize_string(text: str, max_length: int = 2000) -> str:
    """Sanitize"""
    if not text:
        return ""
    return text.replace('\x00', '')[:max_length]

def track_action(guild_id: int, user_id: int, action_type: str) -> int:
    """Track user actions for rate limiting and breach detection"""
    now = time.time()
    threshold = DEFAULT_THRESHOLDS.get(action_type, {'count': 10, 'seconds': 60})
    window = threshold['seconds']
    
    # Clean old entries
    action_tracker[guild_id][action_type] = [
        (t, uid) for t, uid in action_tracker[guild_id][action_type]
        if now - t < window
    ]
    
    # Add new action
    action_tracker[guild_id][action_type].append((now, user_id))
    
    # Count actions by this user in window
    count = sum(1 for _, uid in action_tracker[guild_id][action_type] if uid == user_id)
    return count

# ============= EMAIL =============

async def send_sentinel_mail(to: str, subject: str, text: str, html: str = None) -> bool:
    """Send email"""
    if not SENTINEL_EMAIL or not SENTINEL_EMAIL_PASS:
        return False
    
    if not validate_email(to):
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Sentinel <{SENTINEL_EMAIL}>"
        msg['To'] = to
        msg['Subject'] = sanitize_string(subject, 200)
        
        text_part = MIMEText(sanitize_string(text, 10000), 'plain')
        msg.attach(text_part)
        
        if html:
            html_part = MIMEText(sanitize_string(html, 20000), 'html')
            msg.attach(html_part)
        
        await asyncio.to_thread(_send_email_sync, msg, to)
        logger.info(f"Email → {to}")
        return True
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False

def _send_email_sync(msg, to):
    """Sync email"""
    try:
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.starttls()
            server.login(SENTINEL_EMAIL, SENTINEL_EMAIL_PASS)
            server.send_message(msg)
    except Exception as e:
        logger.error(f"SMTP: {e}")
        raise

async def send_admin_email(guild: discord.Guild, subject: str, message: str):
    """Email admins"""
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
        html = f"""<html><body style="font-family: Arial; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px;">
                <h2 style="color: #e74c3c;">🚨 Sentinel Alert</h2>
                <p><b>Server:</b> {guild.name}</p>
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0;">
                    <p>{message.replace(chr(10), '<br>')}</p>
                </div>
                <p style="color: #7f8c8d; font-size: 12px;">Sentinel Security Bot</p>
            </div>
        </body></html>"""
        asyncio.create_task(send_sentinel_mail(email, subject, message, html))

# ============= HELPERS =============

async def is_whitelisted(guild_id: int, user_id: int) -> bool:
    """Check whitelist"""
    try:
        if user_id in whitelists.get(guild_id, set()):
            return True
        is_wl = await db.is_whitelisted(guild_id, user_id)
        if is_wl:
            if guild_id not in whitelists:
                whitelists[guild_id] = set()
            whitelists[guild_id].add(user_id)
        return is_wl
    except Exception as e:
        logger.error(f"Whitelist error: {e}")
        return False

async def send_alert(guild: discord.Guild, message: str, user: Optional[discord.User] = None, color: discord.Color = discord.Color.red(), email_admins: bool = False):
    """Send alert"""
    config = server_configs.get(guild.id, {})
    log_id = config.get('log_channel_id')
    
    embed = discord.Embed(
        title="🚨 Security Alert",
        description=sanitize_string(message, 2000),
        color=color,
        timestamp=datetime.now()
    )
    
    if user:
        embed.add_field(name="User", value=f"{user.mention} ({user.id})", inline=False)
    
    try:
        await db.add_log(guild.id, 'security_alert', user.id if user else None, {'message': message})
    except Exception as e:
        logger.error(f"Log error: {e}")
    
    if log_id:
        try:
            ch = guild.get_channel(log_id)
            if ch:
                await ch.send(embed=embed)
        except Exception as e:
            logger.error(f"Alert send: {e}")
    
    if email_admins:
        await send_admin_email(guild, "🚨 Security Alert", message)

async def log_action(guild: discord.Guild, category: str, title: str, user: Optional[discord.User], description: str, extra: Optional[Dict] = None):
    """Log action"""
    config = server_configs.get(guild.id, {})
    log_id = config.get('log_channel_id')
    
    embed = discord.Embed(
        title=f"📋 {title}",
        description=description,
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Category", value=category, inline=True)
    embed.add_field(name="User", value=user.mention if user else "System", inline=True)
    
    if extra:
        for k, v in list(extra.items())[:3]:
            embed.add_field(name=str(k), value=str(v)[:1000], inline=True)
    
    try:
        await db.add_log(guild.id, category, user.id if user else None, {'title': title, 'description': description, **(extra or {})})
    except Exception as e:
        logger.error(f"Log error: {e}")
    
    if log_id:
        try:
            ch = guild.get_channel(log_id)
            if ch:
                await ch.send(embed=embed)
        except Exception as e:
            logger.error(f"Send error: {e}")

async def quarantine_user(guild: discord.Guild, user: discord.User, reason: str) -> bool:
    """Quarantine"""
    config = server_configs.get(guild.id, {})
    qid = config.get('quarantine_role_id')
    
    if not qid:
        return False
    
    qrole = guild.get_role(qid)
    if not qrole:
        return False
    
    member = guild.get_member(user.id)
    if not member:
        return False
    
    if qrole in member.roles:
        return True
    
    try:
        roles = [r for r in member.roles if r != guild.default_role]
        if roles:
            await member.remove_roles(*roles, reason=f"Quarantine: {reason}", atomic=False)
        await member.add_roles(qrole, reason=f"Quarantine: {reason}")
        await send_alert(guild, f"✅ Quarantined {user.mention}\n{reason}", user, email_admins=True)
        try:
            await member.send(f"⚠️ Quarantined in {guild.name}\n\nReason: {reason}")
        except:
            pass
        return True
    except Exception as e:
        logger.error(f"Quarantine error: {e}")
        return False

@bot.event
async def on_ready():
    """Startup"""
    logger.info(f'{bot.user} connected!')
    logger.info(f'In {len(bot.guilds)} servers')
    
    try:
        await db.init_database()
        logger.info('✅ DB initialized')
    except Exception as e:
        logger.critical(f'DB init failed: {e}')
        return
    
    try:
        global server_configs, whitelists
        server_configs = await db.load_all_configs()
        whitelists = await db.load_all_whitelists()
        logger.info('✅ Loaded configs')
    except Exception as e:
        logger.error(f'Load error: {e}')
    
    # Add persistent views
    bot.add_view(VerificationView())
    bot.add_view(RobloxVerificationView())
    logger.info('✅ Added persistent views')
    
    # Start background tasks
    if not shift_heartbeat.is_running():
        shift_heartbeat.start()
    if not cleanup_old_logs.is_running():
        cleanup_old_logs.start()
    if not reset_daily_threat.is_running():
        reset_daily_threat.start()
    if not daily_violation_report.is_running():
        daily_violation_report.start()
    logger.info('✅ Background tasks started')
    
    try:
        synced = await bot.tree.sync()
        logger.info(f'✅ Synced {len(synced)} commands')
    except Exception as e:
        logger.error(f'Sync error: {e}')
    
    logger.info('🔍 Monitoring...')

# ============= SETUP COMMANDS =============

@bot.tree.command(name="setup", description="Initial setup")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def setup(interaction: discord.Interaction):
    """Setup"""
    await interaction.response.defer(ephemeral=True)
    embed = discord.Embed(title="🛡️ Setup", description="Configure your server", color=discord.Color.blue())
    embed.add_field(name="1", value="`/set_log_channel #channel`", inline=False)
    embed.add_field(name="2", value="`/create_quarantine_role`", inline=False)
    embed.add_field(name="3", value="`/whitelist_add @user`", inline=False)
    embed.add_field(name="4", value="`/set_admin_email email@example.com`", inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="status", description="Bot status")
@rate_limit(max_calls=5, window=60)
async def status(interaction: discord.Interaction):
    """Status"""
    await interaction.response.defer(ephemeral=True)
    config = server_configs.get(interaction.guild.id, {})
    embed = discord.Embed(title="🛡️ Status", color=discord.Color.blue(), timestamp=datetime.now())
    embed.add_field(name="Log Channel", value="✅" if config.get('log_channel_id') else "❌", inline=True)
    embed.add_field(name="Quarantine", value="✅" if config.get('quarantine_role_id') else "❌", inline=True)
    embed.add_field(name="Whitelisted", value=str(len(whitelists.get(interaction.guild.id, set()))), inline=True)
    embed.add_field(name="Members", value=str(len(interaction.guild.members)), inline=True)
    embed.add_field(name="Channels", value=str(len(interaction.guild.channels)), inline=True)
    try:
        threat = await db.get_current_threat_level(interaction.guild.id)
        level = threat.get('threat_level', 0) if threat else 0
        info = THREAT_LEVELS.get(level, THREAT_LEVELS[0])
        embed.add_field(name="Threat", value=info['name'], inline=True)
    except:
        embed.add_field(name="Threat", value="🟢 Clear", inline=True)
    embed.set_footer(text=f"Guild: {interaction.guild.id}")
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="set_log_channel", description="Set log channel")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    """Set logs"""
    await interaction.response.defer(ephemeral=True)
    perms = channel.permissions_for(interaction.guild.me)
    if not perms.send_messages or not perms.embed_links:
        await interaction.followup.send("❌ Missing perms", ephemeral=True)
        return
    try:
        await db.update_server_field(interaction.guild.id, 'log_channel_id', channel.id)
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id]['log_channel_id'] = channel.id
        embed = discord.Embed(title="✅ Log Channel Set", description=f"Logs → {channel.mention}", color=discord.Color.green())
        await interaction.followup.send(embed=embed, ephemeral=True)
        await channel.send(embed=discord.Embed(title="🧪 Test", description="Log channel configured!", color=discord.Color.green()))
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="create_quarantine_role", description="Create quarantine role")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=1, window=600)
async def create_quarantine_role(interaction: discord.Interaction):
    """Quarantine"""
    await interaction.response.defer(ephemeral=True)
    try:
        existing = discord.utils.get(interaction.guild.roles, name="Quarantined")
        if existing:
            await interaction.followup.send(f"⚠️ Role exists: {existing.mention}", ephemeral=True)
            return
        
        role = await interaction.guild.create_role(
            name="Quarantined",
            color=discord.Color.dark_grey(),
            permissions=discord.Permissions.none(),
            reason=f"Quarantine by {interaction.user}"
        )
        
        count = 0
        for ch in interaction.guild.channels:
            try:
                if isinstance(ch, discord.TextChannel):
                    await ch.set_permissions(role, send_messages=False, add_reactions=False)
                    count += 1
                elif isinstance(ch, discord.VoiceChannel):
                    await ch.set_permissions(role, connect=False)
                    count += 1
            except:
                pass
        
        await db.update_server_field(interaction.guild.id, 'quarantine_role_id', role.id)
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id]['quarantine_role_id'] = role.id
        
        embed = discord.Embed(title="✅ Quarantine Role Created", description=f"{role.mention}\nPermissions set on {count} channels", color=discord.Color.green())
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'setup', 'Quarantine Role Created', interaction.user, f"Created with {count} channels configured")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="set_admin_email", description="Set your email for alerts")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def set_admin_email(interaction: discord.Interaction, email: str):
    """Set email"""
    await interaction.response.defer(ephemeral=True)
    if not validate_email(email):
        await interaction.followup.send("❌ Invalid email", ephemeral=True)
        return
    email = sanitize_string(email, 254).lower()
    try:
        await db.set_user_email(interaction.guild.id, interaction.user.id, email)
        embed = discord.Embed(title="✅ Email Set", description=f"Email: `{email}`", color=discord.Color.green())
        await interaction.followup.send(embed=embed, ephemeral=True)
        if SENTINEL_EMAIL:
            asyncio.create_task(send_sentinel_mail(
                email,
                f"✅ Configured: {interaction.guild.name}",
                f"Hello {interaction.user.name},\n\nYour email has been configured for security alerts from {interaction.guild.name}.",
                f"<html><body style='font-family: Arial;'><h2 style='color: #27ae60;'>✅ Email Configured</h2><p>Hello <strong>{interaction.user.name}</strong>,</p><p>Your email is now configured for alerts from {interaction.guild.name}</p></body></html>"
            ))
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="remove_admin_email", description="Remove your email")
@app_commands.checks.has_permissions(administrator=True)
async def remove_admin_email(interaction: discord.Interaction):
    """Remove email"""
    await interaction.response.defer(ephemeral=True)
    try:
        removed = await db.remove_user_email(interaction.guild.id, interaction.user.id)
        await interaction.followup.send("✅ Email removed" if removed else "❌ No email found", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)


# ============= WHITELIST COMMANDS =============

@bot.tree.command(name="whitelist_add", description="Add to whitelist")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def whitelist_add(interaction: discord.Interaction, user: discord.User):
    """Add whitelist"""
    await interaction.response.defer(ephemeral=True)
    if user.bot:
        await interaction.followup.send("❌ Cannot whitelist bots", ephemeral=True)
        return
    if await is_whitelisted(interaction.guild.id, user.id):
        await interaction.followup.send(f"⚠️ {user.mention} already whitelisted", ephemeral=True)
        return
    try:
        await db.add_to_whitelist(interaction.guild.id, user.id, 'user', interaction.user.id)
        if interaction.guild.id not in whitelists:
            whitelists[interaction.guild.id] = set()
        whitelists[interaction.guild.id].add(user.id)
        await log_action(interaction.guild, 'whitelist', 'User Whitelisted', interaction.user, f"{user.mention} added to whitelist")
        await interaction.followup.send(f"✅ Added {user.mention}", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="whitelist_remove", description="Remove from whitelist")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def whitelist_remove(interaction: discord.Interaction, user: discord.User):
    """Remove whitelist"""
    await interaction.response.defer(ephemeral=True)
    try:
        removed = await db.remove_from_whitelist(interaction.guild.id, user.id)
        if interaction.guild.id in whitelists and user.id in whitelists[interaction.guild.id]:
            whitelists[interaction.guild.id].remove(user.id)
        if removed:
            await log_action(interaction.guild, 'whitelist', 'User Removed', interaction.user, f"{user.mention} removed from whitelist")
            await interaction.followup.send(f"✅ Removed {user.mention}", ephemeral=True)
        else:
            await interaction.followup.send("❌ User not whitelisted", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="whitelist_list", description="List whitelisted users")
@app_commands.checks.has_permissions(administrator=True)
async def whitelist_list(interaction: discord.Interaction):
    """List whitelist"""
    await interaction.response.defer(ephemeral=True)
    try:
        wl = whitelists.get(interaction.guild.id, set())
        if not wl:
            await interaction.followup.send("✅ No users whitelisted", ephemeral=True)
            return
        embed = discord.Embed(title="✅ Whitelisted Users", color=discord.Color.green(), timestamp=datetime.now())
        users = []
        for uid in list(wl)[:25]:
            u = bot.get_user(uid)
            users.append(f"• {u.mention if u else f'User {uid}'}")
        embed.description = "\n".join(users)
        embed.set_footer(text=f"Total: {len(wl)} user(s)")
        if len(wl) > 25:
            embed.add_field(name="Note", value=f"Showing first 25 of {len(wl)}", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# PART 2/4 - ADD THIS AFTER PART 1

# ============= QUARANTINE COMMANDS =============

@bot.tree.command(name="quarantine", description="Quarantine a user")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def quarantine_cmd(interaction: discord.Interaction, user: discord.Member, reason: str = "Manual quarantine"):
    """Quarantine user"""
    await interaction.response.defer(ephemeral=True)
    
    if user.guild_permissions.administrator:
        await interaction.followup.send("❌ Cannot quarantine administrators", ephemeral=True)
        return
    
    if await is_whitelisted(interaction.guild.id, user.id):
        await interaction.followup.send("❌ Cannot quarantine whitelisted users", ephemeral=True)
        return
    
    reason = sanitize_string(reason, 500)
    success = await quarantine_user(interaction.guild, user, reason)
    
    if success:
        await interaction.followup.send(f"✅ Successfully quarantined {user.mention}", ephemeral=True)
        await log_action(interaction.guild, 'security', 'User Quarantined', interaction.user, f"{user.mention} quarantined\nReason: {reason}")
    else:
        await interaction.followup.send(f"❌ Failed to quarantine {user.mention}", ephemeral=True)

@bot.tree.command(name="unquarantine", description="Remove quarantine from a user")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def unquarantine_cmd(interaction: discord.Interaction, user: discord.Member):
    """Unquarantine user"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id, {})
    qid = config.get('quarantine_role_id')
    
    if not qid:
        await interaction.followup.send("❌ Quarantine role not configured", ephemeral=True)
        return
    
    qrole = interaction.guild.get_role(qid)
    if not qrole:
        await interaction.followup.send("❌ Quarantine role not found", ephemeral=True)
        return
    
    if qrole not in user.roles:
        await interaction.followup.send(f"❌ {user.mention} is not quarantined", ephemeral=True)
        return
    
    try:
        await user.remove_roles(qrole, reason=f"Unquarantined by {interaction.user.name}")
        await send_alert(interaction.guild, f"✅ {user.mention} was unquarantined", color=discord.Color.green())
        await interaction.followup.send(f"✅ Successfully unquarantined {user.mention}", ephemeral=True)
        await log_action(interaction.guild, 'security', 'User Unquarantined', interaction.user, f"{user.mention} unquarantined")
    except discord.Forbidden:
        await interaction.followup.send("❌ Missing permissions", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="quarantine_list", description="List quarantined users")
@app_commands.checks.has_permissions(administrator=True)
async def quarantine_list(interaction: discord.Interaction):
    """List quarantined"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id, {})
    qid = config.get('quarantine_role_id')
    
    if not qid:
        await interaction.followup.send("❌ Quarantine role not configured", ephemeral=True)
        return
    
    qrole = interaction.guild.get_role(qid)
    if not qrole:
        await interaction.followup.send("❌ Quarantine role not found", ephemeral=True)
        return
    
    quarantined = [m for m in interaction.guild.members if qrole in m.roles]
    
    if not quarantined:
        await interaction.followup.send("✅ No users are quarantined", ephemeral=True)
        return
    
    embed = discord.Embed(title="🔒 Quarantined Users", color=discord.Color.dark_grey(), timestamp=datetime.now())
    users = "\n".join([f"• {m.mention} (`{m.name}`)" for m in quarantined[:25]])
    embed.description = users
    embed.set_footer(text=f"Total: {len(quarantined)} user(s)")
    
    if len(quarantined) > 25:
        embed.add_field(name="Note", value=f"Showing first 25 of {len(quarantined)}", inline=False)
    
    await interaction.followup.send(embed=embed, ephemeral=True)

# ============= THREAT LEVEL COMMANDS =============

@bot.tree.command(name="threat_set", description="Set threat level (0-3)")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def threat_set(interaction: discord.Interaction, level: int):
    """Set threat"""
    await interaction.response.defer(ephemeral=True)
    
    if not 0 <= level <= 3:
        await interaction.followup.send("❌ Threat level must be 0-3", ephemeral=True)
        return
    
    try:
        await db.set_threat_level(interaction.guild.id, level)
        info = THREAT_LEVELS[level]
        
        embed = discord.Embed(
            title="🚨 Threat Level Changed",
            description=f"Level: **{info['name']}**\n{info['description']}",
            color=info['color'],
            timestamp=datetime.now()
        )
        embed.add_field(name="Changed by", value=interaction.user.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await send_alert(interaction.guild, f"Threat level set to {info['name']}", email_admins=True)
        await log_action(interaction.guild, 'threat', 'Threat Level Changed', interaction.user, f"Changed to {info['name']}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="threat_status", description="View current threat level")
@rate_limit(max_calls=10, window=60)
async def threat_status(interaction: discord.Interaction):
    """Show threat"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        threat = await db.get_current_threat_level(interaction.guild.id)
        level = threat.get('threat_level', 0) if threat else 0
        info = THREAT_LEVELS.get(level, THREAT_LEVELS[0])
        
        embed = discord.Embed(
            title="🚨 Server Threat Status",
            description=info['description'],
            color=info['color'],
            timestamp=datetime.now()
        )
        embed.add_field(name="Current Level", value=info['name'], inline=True)
        embed.add_field(name="Numeric Level", value=str(level), inline=True)
        
        if level >= 2:
            embed.add_field(name="⚠️ Active Measures", value="🔒 Lockdown recommended\n📢 Admins notified\n🚫 Suspicious users monitored", inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= LOCKDOWN COMMANDS =============

@bot.tree.command(name="lockdown_enable", description="Enable emergency lockdown")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=2, window=300)
async def lockdown_enable(interaction: discord.Interaction, reason: str = "Emergency lockdown"):
    """Lock server"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    count = 0
    
    try:
        for channel in interaction.guild.text_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    send_messages=False,
                    add_reactions=False,
                    create_instant_invite=False,
                    reason=f"Lockdown: {reason}"
                )
                count += 1
            except:
                pass
        
        for channel in interaction.guild.voice_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    connect=False,
                    speak=False,
                    reason=f"Lockdown: {reason}"
                )
                count += 1
            except:
                pass
        
        await db.update_server_field(interaction.guild.id, 'lockdown_enabled', True)
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id]['lockdown_enabled'] = True
        
        embed = discord.Embed(
            title="🔒 LOCKDOWN ACTIVE",
            description=f"Locked {count} channels\nReason: {reason}",
            color=discord.Color.orange(),
            timestamp=datetime.now()
        )
        embed.add_field(name="All Members", value="Cannot send messages or reactions", inline=False)
        embed.add_field(name="Initiated by", value=interaction.user.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await send_alert(interaction.guild, f"🔒 SERVER LOCKDOWN ACTIVATED\nReason: {reason}", email_admins=True)
        await log_action(interaction.guild, 'security', 'Lockdown Enabled', interaction.user, f"Reason: {reason}\nLocked {count} channels")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="lockdown_disable", description="Disable lockdown")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=2, window=300)
async def lockdown_disable(interaction: discord.Interaction):
    """Unlock server"""
    await interaction.response.defer(ephemeral=True)
    
    count = 0
    
    try:
        for channel in interaction.guild.text_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    send_messages=None,
                    add_reactions=None,
                    create_instant_invite=None
                )
                count += 1
            except:
                pass
        
        for channel in interaction.guild.voice_channels:
            try:
                await channel.set_permissions(
                    interaction.guild.default_role,
                    connect=None,
                    speak=None
                )
                count += 1
            except:
                pass
        
        await db.update_server_field(interaction.guild.id, 'lockdown_enabled', False)
        if interaction.guild.id in server_configs:
            server_configs[interaction.guild.id]['lockdown_enabled'] = False
        
        embed = discord.Embed(
            title="🔓 LOCKDOWN LIFTED",
            description=f"Unlocked {count} channels\nNormal permissions restored",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        embed.add_field(name="Lifted by", value=interaction.user.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'security', 'Lockdown Disabled', interaction.user, f"Unlocked {count} channels")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= SHIFT SYSTEM COMMANDS =============

@bot.tree.command(name="shift-start", description="Start a work shift")
@rate_limit(max_calls=5, window=60)
async def shift_start(interaction: discord.Interaction, department: str = None, callsign: str = None):
    """Start shift"""
    await interaction.response.defer(ephemeral=True)
    
    if department:
        department = sanitize_string(department, 50)
    if callsign:
        callsign = sanitize_string(callsign, 50)
    
    try:
        uid = interaction.user.id
        gid = interaction.guild.id
        
        if uid in ACTIVE_SHIFTS[gid]:
            await interaction.followup.send("❌ You already have an active shift! Use `/shift-end` first.", ephemeral=True)
            return
        
        if department:
            dept = await db.get_department(gid, department)
            if dept and dept.get('suspended'):
                await interaction.followup.send(f"❌ Department '{department}' is suspended. Cannot start shifts.", ephemeral=True)
                return
        
        start_time = datetime.now()
        ACTIVE_SHIFTS[gid][uid] = {
            'start_time': start_time,
            'department': department,
            'callsign': callsign,
            'status': 'active'
        }
        
        await db.create_shift(gid, uid, department, start_time, callsign=callsign)
        
        config = server_configs.get(gid, {})
        onduty_id = config.get('onduty_role_id')
        if onduty_id:
            member = interaction.guild.get_member(uid)
            role = interaction.guild.get_role(onduty_id)
            if member and role:
                try:
                    await member.add_roles(role, reason="Shift started")
                except:
                    pass
        
        embed = discord.Embed(
            title="✅ Shift Started",
            description=f"{interaction.user.mention} is now on duty",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        if department:
            embed.add_field(name="Department", value=department, inline=True)
        if callsign:
            embed.add_field(name="Callsign", value=callsign, inline=True)
        embed.add_field(name="Start Time", value=start_time.strftime('%H:%M:%S UTC'), inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'shift', 'Shift Started', interaction.user, f"Department: {department or 'None'}, Callsign: {callsign or 'None'}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="shift-end", description="End your shift")
@rate_limit(max_calls=5, window=60)
async def shift_end(interaction: discord.Interaction):
    """End shift"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        uid = interaction.user.id
        gid = interaction.guild.id
        
        if uid not in ACTIVE_SHIFTS[gid]:
            await interaction.followup.send("❌ You do not have an active shift", ephemeral=True)
            return
        
        if SHIFT_LOCKS[gid][uid]:
            await interaction.followup.send("🔒 Your shift is locked. Contact an administrator.", ephemeral=True)
            return
        
        shift = ACTIVE_SHIFTS[gid][uid]
        end_time = datetime.now()
        duration = (end_time - shift['start_time']).total_seconds()
        
        await db.end_shift(gid, uid, end_time, duration)
        del ACTIVE_SHIFTS[gid][uid]
        
        config = server_configs.get(gid, {})
        onduty_id = config.get('onduty_role_id')
        if onduty_id:
            member = interaction.guild.get_member(uid)
            role = interaction.guild.get_role(onduty_id)
            if member and role:
                try:
                    await member.remove_roles(role, reason="Shift ended")
                except:
                    pass
        
        hours = int(duration // 3600)
        mins = int((duration % 3600) // 60)
        
        embed = discord.Embed(
            title="✅ Shift Ended",
            description=f"{interaction.user.mention}'s shift complete",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        embed.add_field(name="Duration", value=f"{hours}h {mins}m", inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'shift', 'Shift Ended', interaction.user, f"Duration: {hours}h {mins}m")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="shift-status", description="Check shift status")
@rate_limit(max_calls=10, window=60)
async def shift_status(interaction: discord.Interaction, user: discord.Member = None):
    """Shift status"""
    await interaction.response.defer(ephemeral=True)
    
    target = user or interaction.user
    uid = target.id
    gid = interaction.guild.id
    
    try:
        if uid in ACTIVE_SHIFTS[gid]:
            shift = ACTIVE_SHIFTS[gid][uid]
            elapsed = (datetime.now() - shift['start_time']).total_seconds()
            
            h = int(elapsed // 3600)
            m = int((elapsed % 3600) // 60)
            s = int(elapsed % 60)
            
            embed = discord.Embed(
                title="🟢 Shift Active",
                description=f"{target.mention} is currently on duty",
                color=discord.Color.green(),
                timestamp=datetime.now()
            )
            embed.add_field(name="Elapsed", value=f"{h}h {m}m {s}s", inline=True)
            if shift.get('department'):
                embed.add_field(name="Department", value=shift['department'], inline=True)
            if shift.get('callsign'):
                embed.add_field(name="Callsign", value=shift['callsign'], inline=True)
            is_locked = SHIFT_LOCKS[gid].get(uid, False)
            embed.add_field(name="Locked", value="🔒 Yes" if is_locked else "🔓 No", inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            embed = discord.Embed(
                title="❌ No Active Shift",
                description=f"{target.mention} does not have an active shift",
                color=discord.Color.red(),
                timestamp=datetime.now()
            )
            await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="shift-force-end", description="Force end a shift")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def shift_force_end(interaction: discord.Interaction, user: discord.Member, reason: str = "No reason provided"):
    """Force end shift"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        uid = user.id
        gid = interaction.guild.id
        
        if uid not in ACTIVE_SHIFTS[gid]:
            await interaction.followup.send(f"❌ {user.mention} does not have an active shift", ephemeral=True)
            return
        
        shift = ACTIVE_SHIFTS[gid][uid]
        end_time = datetime.now()
        duration = (end_time - shift['start_time']).total_seconds()
        
        await db.end_shift(gid, uid, end_time, duration, force_ended=True)
        del ACTIVE_SHIFTS[gid][uid]
        if uid in SHIFT_LOCKS[gid]:
            del SHIFT_LOCKS[gid][uid]
        
        h = int(duration // 3600)
        m = int((duration % 3600) // 60)
        
        embed = discord.Embed(
            title="⚠️ Shift Force Ended",
            description=f"{user.mention}'s shift has been forcefully ended",
            color=discord.Color.orange(),
            timestamp=datetime.now()
        )
        embed.add_field(name="User", value=user.mention, inline=True)
        embed.add_field(name="Duration", value=f"{h}h {m}m", inline=True)
        embed.add_field(name="Ended By", value=interaction.user.mention, inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'shift', 'Shift Force Ended', interaction.user, f"{user.mention}: {reason}\nDuration: {h}h {m}m")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="shift-log", description="View shift history")
@rate_limit(max_calls=10, window=60)
async def shift_log(interaction: discord.Interaction, user: discord.Member = None, limit: int = 10):
    """Shift logs"""
    await interaction.response.defer(ephemeral=True)
    
    target = user or interaction.user
    
    if limit > 50:
        limit = 50
    
    try:
        shifts = await db.get_shift_history(interaction.guild.id, target.id, limit=limit)
        
        if not shifts:
            await interaction.followup.send(f"ℹ️ No shift history found for {target.mention}", ephemeral=True)
            return
        
        embed = discord.Embed(
            title=f"📋 Shift History: {target.name}",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        total_hours = 0
        shifts_list = []
        
        for i, shift in enumerate(shifts[:10], 1):
            start = shift.get('start_time', 'Unknown')
            end = shift.get('end_time', 'Unknown')
            duration = shift.get('duration_seconds', 0)
            dept = shift.get('department', 'None')
            
            hours = int(duration // 3600)
            mins = int((duration % 3600) // 60)
            total_hours += hours
            
            shifts_list.append(f"{i}. {start} - {end} ({hours}h {mins}m) [{dept}]")
        
        embed.description = "\n".join(shifts_list)
        embed.add_field(name="Total Hours", value=f"{total_hours}h", inline=True)
        embed.add_field(name="Total Shifts", value=str(len(shifts)), inline=True)
        embed.set_footer(text=f"Showing {len(shifts_list)} of {len(shifts)} shifts")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# PART 3/4 - ADD THIS AFTER PART 2

# ============= DEPARTMENT COMMANDS =============

@bot.tree.command(name="dept-join", description="Request to join a department")
@rate_limit(max_calls=5, window=300)
async def dept_join(interaction: discord.Interaction, department: str):
    """Join department"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    
    try:
        dept = await db.get_department(interaction.guild.id, department)
        if not dept:
            await interaction.followup.send(f"❌ Department '{department}' not found", ephemeral=True)
            return
        
        is_member = await db.is_department_member(interaction.guild.id, interaction.user.id, department)
        if is_member:
            await interaction.followup.send(f"⚠️ You are already a member of {department}", ephemeral=True)
            return
        
        rid = await db.create_department_join_request(interaction.guild.id, interaction.user.id, department, 'pending')
        
        embed = discord.Embed(
            title="✅ Join Request Submitted",
            description=f"Your request to join **{department}** has been created",
            color=discord.Color.green()
        )
        embed.add_field(name="Department", value=department, inline=True)
        embed.add_field(name="Status", value="Pending", inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        head_id = dept.get('department_head')
        if head_id:
            head = bot.get_user(head_id)
            if head:
                try:
                    emb = discord.Embed(
                        title="📋 New Join Request",
                        description=f"{interaction.user.mention} has requested to join **{department}**",
                        color=discord.Color.blue()
                    )
                    emb.add_field(name="User", value=f"{interaction.user.name} ({interaction.user.id})", inline=False)
                    emb.add_field(name="Request ID", value=str(rid), inline=True)
                    await head.send(embed=emb)
                except:
                    pass
        
        await log_action(interaction.guild, 'department', 'Join Request Submitted', interaction.user, f"Requested {department}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-info", description="View department information")
@rate_limit(max_calls=10, window=60)
async def dept_info(interaction: discord.Interaction, department: str = None):
    """Department info"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        if department:
            department = sanitize_string(department, 50)
            dept = await db.get_department(interaction.guild.id, department)
            
            if not dept:
                await interaction.followup.send(f"❌ Department '{department}' not found", ephemeral=True)
                return
            
            members = await db.get_department_members(interaction.guild.id, department)
            
            embed = discord.Embed(
                title=f"📋 Department: {department}",
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            head_id = dept.get('department_head')
            if head_id:
                head = bot.get_user(head_id)
                head_name = head.name if head else f"User {head_id}"
                embed.add_field(name="Department Head", value=head_name, inline=True)
            
            embed.add_field(name="Total Members", value=str(len(members)), inline=True)
            embed.add_field(name="Created", value=dept.get('created_at', 'Unknown'), inline=True)
            
            if dept.get('description'):
                embed.add_field(name="Description", value=dept['description'], inline=False)
            
            if members:
                member_list = []
                for i, member_info in enumerate(members[:10], 1):
                    uid = member_info.get('user_id')
                    status = member_info.get('status', 'member')
                    u = bot.get_user(uid)
                    u_name = u.name if u else f"User {uid}"
                    member_list.append(f"{i}. {u_name} - {status}")
                
                embed.add_field(name="Members", value="\n".join(member_list), inline=False)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            depts = await db.get_all_departments(interaction.guild.id)
            
            if not depts:
                await interaction.followup.send("ℹ️ No departments found", ephemeral=True)
                return
            
            embed = discord.Embed(
                title="📋 Server Departments",
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            
            dept_list = []
            for i, d in enumerate(depts[:15], 1):
                d_name = d.get('name', 'Unknown')
                dept_list.append(f"{i}. **{d_name}**")
            
            embed.description = "\n".join(dept_list)
            embed.set_footer(text=f"Total: {len(depts)} department(s)")
            
            await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-create", description="Create a new department")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def dept_create(interaction: discord.Interaction, name: str, description: str = "New department"):
    """Create department"""
    await interaction.response.defer(ephemeral=True)
    
    name = sanitize_string(name, 50)
    description = sanitize_string(description, 500)
    
    try:
        existing = await db.get_department(interaction.guild.id, name)
        if existing:
            await interaction.followup.send(f"❌ Department '{name}' already exists", ephemeral=True)
            return
        
        role = await interaction.guild.create_role(
            name=f"[{name}]",
            color=discord.Color.blue(),
            reason=f"Department role by {interaction.user.name}"
        )
        
        await db.create_department(interaction.guild.id, name, description, role.id)
        
        embed = discord.Embed(
            title="✅ Department Created",
            description=f"**{name}** department has been created",
            color=discord.Color.green()
        )
        embed.add_field(name="Name", value=name, inline=True)
        embed.add_field(name="Description", value=description, inline=False)
        embed.add_field(name="Role", value=role.mention, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'department', 'Department Created', interaction.user, f"Created: {name}\n{description}")
    except discord.Forbidden:
        await interaction.followup.send("❌ Missing permissions", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-set-head", description="Set a department head")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def dept_set_head(interaction: discord.Interaction, department: str, user: discord.Member):
    """Set head"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    
    try:
        dept = await db.get_department(interaction.guild.id, department)
        if not dept:
            await interaction.followup.send(f"❌ Department '{department}' not found", ephemeral=True)
            return
        
        await db.set_department_head(interaction.guild.id, department, user.id)
        await db.add_department_member(interaction.guild.id, user.id, department, 'head')
        
        embed = discord.Embed(
            title="✅ Department Head Assigned",
            description=f"{user.mention} is now head of **{department}**",
            color=discord.Color.green()
        )
        embed.add_field(name="Department", value=department, inline=True)
        embed.add_field(name="Head", value=user.name, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'department', 'Head Assigned', interaction.user, f"{user.mention} → {department}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-approve-join", description="Approve a join request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def dept_approve_join(interaction: discord.Interaction, request_id: int, reason: str = "Approved"):
    """Approve join"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        request = await db.get_department_join_request(interaction.guild.id, request_id)
        
        if not request:
            await interaction.followup.send(f"❌ Request {request_id} not found", ephemeral=True)
            return
        
        if request.get('status') != 'pending':
            await interaction.followup.send(f"❌ Request already {request['status']}", ephemeral=True)
            return
        
        uid = request.get('user_id')
        dept = request.get('department')
        
        await db.add_department_member(interaction.guild.id, uid, dept, 'member')
        await db.update_department_join_request_status(interaction.guild.id, request_id, 'approved', reason)
        
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
        embed.add_field(name="Department", value=dept, inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        if user:
            try:
                await user.send(f"✅ Your request to join **{dept}** was approved!")
            except:
                pass
        
        await log_action(interaction.guild, 'department', 'Join Approved', interaction.user, f"{user_name} → {dept}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-deny-join", description="Deny a join request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def dept_deny_join(interaction: discord.Interaction, request_id: int, reason: str = "Request denied"):
    """Deny join"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        request = await db.get_department_join_request(interaction.guild.id, request_id)
        
        if not request:
            await interaction.followup.send(f"❌ Request {request_id} not found", ephemeral=True)
            return
        
        if request.get('status') != 'pending':
            await interaction.followup.send(f"❌ Request already {request['status']}", ephemeral=True)
            return
        
        uid = request.get('user_id')
        dept = request.get('department')
        
        await db.update_department_join_request_status(interaction.guild.id, request_id, 'denied', reason)
        
        user = bot.get_user(uid)
        user_name = user.name if user else f"User {uid}"
        
        embed = discord.Embed(
            title="❌ Join Request Denied",
            description=f"{user_name}'s request for **{dept}** denied",
            color=discord.Color.red()
        )
        embed.add_field(name="Department", value=dept, inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        if user:
            try:
                await user.send(f"❌ Your request to join **{dept}** was denied.\n\nReason: {reason}")
            except:
                pass
        
        await log_action(interaction.guild, 'department', 'Join Denied', interaction.user, f"{user_name}: {reason}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-join-requests", description="View pending join requests")
@app_commands.checks.has_permissions(administrator=True)
async def dept_join_requests(interaction: discord.Interaction, department: str = None):
    """Pending requests"""
    await interaction.response.defer(ephemeral=True)
    
    if department:
        department = sanitize_string(department, 50)
    
    try:
        requests = await db.get_department_join_requests(interaction.guild.id, department, status='pending')
        
        if not requests:
            await interaction.followup.send("✅ No pending join requests", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="📋 Pending Join Requests",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        req_text = []
        for req in requests[:15]:
            rid = req.get('id')
            uid = req.get('user_id')
            d = req.get('department')
            u = bot.get_user(uid)
            u_name = u.name if u else f"User {uid}"
            req_text.append(f"**{rid}.** {u_name} → {d}")
        
        embed.description = "\n".join(req_text)
        embed.set_footer(text="Use /dept-approve-join or /dept-deny-join")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-suspend", description="Suspend a department")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def dept_suspend(interaction: discord.Interaction, department: str, reason: str = "No reason"):
    """Suspend dept"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    reason = sanitize_string(reason, 500)
    
    try:
        dept = await db.get_department(interaction.guild.id, department)
        
        if not dept:
            await interaction.followup.send(f"❌ Department '{department}' not found", ephemeral=True)
            return
        
        if dept.get('suspended'):
            await interaction.followup.send(f"⚠️ {department} is already suspended", ephemeral=True)
            return
        
        await db.update_department_field(interaction.guild.id, department, 'suspended', True)
        
        ended = 0
        for gid, shifts in ACTIVE_SHIFTS.items():
            if gid == interaction.guild.id:
                for uid, shift in list(shifts.items()):
                    if shift.get('department') == department:
                        try:
                            end_time = datetime.now()
                            duration = (end_time - shift['start_time']).total_seconds()
                            await db.end_shift(gid, uid, end_time, duration, force_ended=True)
                            del ACTIVE_SHIFTS[gid][uid]
                            ended += 1
                        except Exception as e:
                            logger.error(f"Error: {e}")
        
        embed = discord.Embed(
            title="🔒 Department Suspended",
            description=f"**{department}** has been suspended",
            color=discord.Color.orange()
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        embed.add_field(name="Shifts Ended", value=str(ended), inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'department', 'Suspended', interaction.user, f"{department}\nEnded {ended} shifts")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-activate", description="Reactivate a suspended department")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def dept_activate(interaction: discord.Interaction, department: str):
    """Activate dept"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    
    try:
        dept = await db.get_department(interaction.guild.id, department)
        
        if not dept:
            await interaction.followup.send(f"❌ Department '{department}' not found", ephemeral=True)
            return
        
        if not dept.get('suspended'):
            await interaction.followup.send(f"⚠️ {department} is not suspended", ephemeral=True)
            return
        
        await db.update_department_field(interaction.guild.id, department, 'suspended', False)
        
        embed = discord.Embed(
            title="✅ Department Activated",
            description=f"**{department}** is now active",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'department', 'Activated', interaction.user, f"{department}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= ROLE MANAGEMENT COMMANDS =============

@bot.tree.command(name="promotion", description="Promote user to next tier")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def promotion(interaction: discord.Interaction, user: discord.Member):
    """Promote"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        user_tier = 1
        user_role = "USER"
        
        for role in user.roles:
            for rname, tier in ROLE_HIERARCHY.items():
                if rname.lower() in role.name.lower():
                    if tier > user_tier:
                        user_tier = tier
                        user_role = rname
        
        next_tier = None
        next_role = None
        
        for rname, tier in sorted(ROLE_HIERARCHY.items(), key=lambda x: x[1]):
            if tier > user_tier:
                next_tier = tier
                next_role = rname
                break
        
        if not next_tier:
            await interaction.followup.send(f"❌ {user.mention} is already at max tier!", ephemeral=True)
            return
        
        nrole = discord.utils.get(interaction.guild.roles, name=next_role)
        if not nrole:
            nrole = await interaction.guild.create_role(
                name=next_role,
                color=discord.Color.blue(),
                reason=f"Promotion by {interaction.user.name}"
            )
        
        await user.add_roles(nrole, reason=f"Promoted by {interaction.user.name}")
        
        embed = discord.Embed(
            title="✅ User Promoted",
            description=f"{user.mention} promoted!",
            color=discord.Color.green()
        )
        embed.add_field(name="From", value=user_role, inline=True)
        embed.add_field(name="To", value=next_role, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'roles', 'Promotion', interaction.user, f"{user.mention}: {user_role} → {next_role}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="demotion", description="Demote user to previous tier")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def demotion(interaction: discord.Interaction, user: discord.Member, reason: str = "No reason"):
    """Demote"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        user_tier = 1
        user_role = "USER"
        
        for role in user.roles:
            for rname, tier in ROLE_HIERARCHY.items():
                if rname.lower() in role.name.lower():
                    if tier > user_tier:
                        user_tier = tier
                        user_role = rname
        
        prev_tier = None
        prev_role = None
        
        for rname, tier in sorted(ROLE_HIERARCHY.items(), key=lambda x: x[1], reverse=True):
            if tier < user_tier:
                prev_tier = tier
                prev_role = rname
                break
        
        if not prev_tier:
            await interaction.followup.send(f"❌ {user.mention} is already at min tier!", ephemeral=True)
            return
        
        cur_role = discord.utils.get(interaction.guild.roles, name=user_role)
        if cur_role:
            await user.remove_roles(cur_role, reason=f"Demoted by {interaction.user.name}: {reason}")
        
        prole = discord.utils.get(interaction.guild.roles, name=prev_role)
        if not prole:
            prole = await interaction.guild.create_role(
                name=prev_role,
                color=discord.Color.light_grey(),
                reason=f"Demotion by {interaction.user.name}"
            )
        
        await user.add_roles(prole, reason=f"Demoted by {interaction.user.name}: {reason}")
        
        embed = discord.Embed(
            title="⚠️ User Demoted",
            description=f"{user.mention} demoted",
            color=discord.Color.orange()
        )
        embed.add_field(name="From", value=user_role, inline=True)
        embed.add_field(name="To", value=prev_role, inline=True)
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'roles', 'Demotion', interaction.user, f"{user.mention}: {user_role} → {prev_role}\nReason: {reason}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# PART 4/4 - FINAL - ADD THIS AFTER PART 3

# ============= ROLE REQUEST COMMANDS =============

@bot.tree.command(name="requestrole", description="Request a role")
@rate_limit(max_calls=3, window=3600)
async def requestrole(interaction: discord.Interaction, role: discord.Role):
    """Request role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        if role in interaction.user.roles:
            await interaction.followup.send(f"❌ You already have {role.mention}", ephemeral=True)
            return
        
        await db.add_role_request(interaction.guild.id, interaction.user.id, role.id, 'pending')
        
        embed = discord.Embed(
            title="✅ Role Request Submitted",
            description=f"Request for {role.mention} created",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        admin_count = 0
        for member in interaction.guild.members:
            if member.guild_permissions.administrator and admin_count < 5:
                try:
                    emb = discord.Embed(
                        title="📋 New Role Request",
                        description=f"{interaction.user.mention} requested {role.mention}",
                        color=discord.Color.blue()
                    )
                    emb.add_field(name="User", value=f"{interaction.user.name} ({interaction.user.id})", inline=False)
                    emb.add_field(name="Requested Role", value=role.mention, inline=True)
                    await member.send(embed=emb)
                    admin_count += 1
                except:
                    pass
        
        await log_action(interaction.guild, 'roles', 'Role Requested', interaction.user, f"Requested {role.mention}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="role_requests", description="View role requests")
@app_commands.checks.has_permissions(administrator=True)
async def role_requests(interaction: discord.Interaction):
    """Pending requests"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        requests = await db.get_role_requests(interaction.guild.id, status='pending')
        
        if not requests:
            await interaction.followup.send("✅ No pending requests", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="📋 Pending Role Requests",
            color=discord.Color.blue(),
            timestamp=datetime.now()
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
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="approve_role", description="Approve role request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def approve_role(interaction: discord.Interaction, user: discord.User, role: discord.Role):
    """Approve role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        member = interaction.guild.get_member(user.id)
        if not member:
            await interaction.followup.send(f"❌ {user.mention} not a member", ephemeral=True)
            return
        
        await member.add_roles(role, reason=f"Approved by {interaction.user.name}")
        
        await db.update_role_request_status(interaction.guild.id, user.id, role.id, 'approved')
        
        try:
            await user.send(f"✅ Your request for {role.mention} was approved!")
        except:
            pass
        
        await interaction.followup.send(f"✅ Approved {user.mention} for {role.mention}", ephemeral=True)
        await log_action(interaction.guild, 'roles', 'Request Approved', interaction.user, f"{user.mention} → {role.mention}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="deny_role", description="Deny role request")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=20, window=60)
async def deny_role(interaction: discord.Interaction, user: discord.User, role: discord.Role, reason: str = "Denied"):
    """Deny role"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        await db.update_role_request_status(interaction.guild.id, user.id, role.id, 'denied')
        
        try:
            await user.send(f"❌ Your request for {role.mention} was denied.\nReason: {reason}")
        except:
            pass
        
        await interaction.followup.send(f"✅ Denied {user.mention} for {role.mention}", ephemeral=True)
        await log_action(interaction.guild, 'roles', 'Request Denied', interaction.user, f"{user.mention}: {reason}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= PARTNERSHIP COMMANDS =============

@bot.tree.command(name="partnership_add", description="Add partner server")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def partnership_add(interaction: discord.Interaction, guild_id: str, guild_name: str, description: str = "Partner"):
    """Add partner"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        gid = int(guild_id)
        if not validate_discord_id(gid):
            await interaction.followup.send("❌ Invalid guild ID", ephemeral=True)
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
        await log_action(interaction.guild, 'partnership', 'Added', interaction.user, f"{guild_name} ({gid})")
    except ValueError:
        await interaction.followup.send("❌ Invalid guild ID (must be number)", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="partnership_remove", description="Remove partner")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def partnership_remove(interaction: discord.Interaction, guild_id: str):
    """Remove partner"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        gid = int(guild_id)
        removed = await db.remove_partnership(interaction.guild.id, gid)
        
        if removed:
            await interaction.followup.send(f"✅ Removed partnership {gid}", ephemeral=True)
            await log_action(interaction.guild, 'partnership', 'Removed', interaction.user, f"Guild {gid}")
        else:
            await interaction.followup.send("❌ Partnership not found", ephemeral=True)
    except ValueError:
        await interaction.followup.send("❌ Invalid guild ID", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="partnerships", description="List partnerships")
@rate_limit(max_calls=10, window=60)
async def partnerships(interaction: discord.Interaction):
    """Show partners"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        partners = await db.get_partnerships(interaction.guild.id)
        
        if not partners:
            await interaction.followup.send("ℹ️ No partnerships", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="🤝 Server Partnerships",
            color=discord.Color.purple(),
            timestamp=datetime.now()
        )
        
        for i, p in enumerate(partners[:MAX_PARTNERSHIPS_DISPLAY], 1):
            name = p.get('guild_name', 'Unknown')
            gid = p.get('partner_guild_id', 'Unknown')
            desc = p.get('description', 'No desc')
            embed.add_field(name=f"{i}. {name}", value=f"**ID:** `{gid}`\n{desc}", inline=False)
        
        if len(partners) > MAX_PARTNERSHIPS_DISPLAY:
            embed.set_footer(text=f"Showing {MAX_PARTNERSHIPS_DISPLAY} of {len(partners)}")
        else:
            embed.set_footer(text=f"Total: {len(partners)}")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= ADMIN COMMANDS =============

@bot.tree.command(name="logs", description="View activity logs")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def logs(interaction: discord.Interaction, category: str = None, limit: int = 10):
    """Logs"""
    await interaction.response.defer(ephemeral=True)
    
    if limit > 50:
        limit = 50
    
    try:
        log_entries = await db.get_logs(interaction.guild.id, category=category, limit=limit)
        
        if not log_entries:
            await interaction.followup.send("ℹ️ No logs", ephemeral=True)
            return
        
        embed = discord.Embed(
            title="📋 Activity Logs",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        if category:
            embed.description = f"Filtered: **{category}**\n\n"
        
        logs_text = []
        for i, entry in enumerate(log_entries[:10], 1):
            cat = entry.get('category', 'unknown').upper()
            uid = entry.get('user_id')
            ts = entry.get('timestamp', 'N/A')
            
            u = bot.get_user(uid) if uid else None
            u_name = u.name if u else f"User {uid}"
            
            logs_text.append(f"**{i}.** [{cat}] {u_name} - {ts}")
        
        embed.description = (embed.description or "") + "\n".join(logs_text)
        embed.set_footer(text=f"{len(logs_text)} entries")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="config", description="View configuration")
@app_commands.checks.has_permissions(administrator=True)
async def config(interaction: discord.Interaction):
    """Config"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        cfg = server_configs.get(interaction.guild.id, {})
        
        embed = discord.Embed(
            title="⚙️ Configuration",
            color=discord.Color.blue(),
            timestamp=datetime.now()
        )
        
        log_id = cfg.get('log_channel_id')
        if log_id:
            ch = interaction.guild.get_channel(log_id)
            log_text = f"{ch.mention}" if ch else f"Channel {log_id} (Deleted)"
        else:
            log_text = "Not configured"
        embed.add_field(name="Log Channel", value=log_text, inline=False)
        
        q_id = cfg.get('quarantine_role_id')
        if q_id:
            r = interaction.guild.get_role(q_id)
            q_text = f"{r.mention}" if r else f"Role {q_id} (Deleted)"
        else:
            q_text = "Not configured"
        embed.add_field(name="Quarantine Role", value=q_text, inline=False)
        
        ver = "✅" if cfg.get('verification_enabled') else "❌"
        embed.add_field(name="Verification", value=ver, inline=True)
        
        lock = "🔒" if cfg.get('lockdown_enabled') else "🔓"
        embed.add_field(name="Lockdown", value=lock, inline=True)
        
        try:
            threat = await db.get_current_threat_level(interaction.guild.id)
            level = threat.get('threat_level', 0) if threat else 0
            threat_name = THREAT_LEVELS.get(level, THREAT_LEVELS[0])['name']
            embed.add_field(name="Threat", value=threat_name, inline=True)
        except:
            embed.add_field(name="Threat", value="Unknown", inline=True)
        
        wl_count = len(whitelists.get(interaction.guild.id, set()))
        embed.add_field(name="Whitelisted", value=str(wl_count), inline=True)
        
        embed.set_footer(text=f"Guild: {interaction.guild.id}")
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="reset_config", description="Reset configuration (DANGEROUS)")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=1, window=3600)
async def reset_config(interaction: discord.Interaction):
    """Reset config"""
    await interaction.response.defer(ephemeral=True)
    
    embed = discord.Embed(
        title="⚠️ WARNING: Reset Configuration",
        description="This will reset ALL settings including:\n"
        "• Log channel\n"
        "• Quarantine role\n"
        "• Verification\n"
        "• Whitelists\n"
        "• Threat level\n"
        "• Partnerships\n\n"
        "**THIS CANNOT BE UNDONE!**",
        color=discord.Color.red()
    )
    
    await interaction.followup.send(embed=embed, ephemeral=True)
    await send_alert(interaction.guild, f"Config reset initiated by {interaction.user.mention}", email_admins=True)

# ============= EXTENSION COMMANDS =============

@bot.tree.command(name="shift-lock", description="Lock a user's shift")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def shift_lock(interaction: discord.Interaction, user: discord.Member, reason: str = "No reason"):
    """Lock shift"""
    await interaction.response.defer(ephemeral=True)
    
    reason = sanitize_string(reason, 500)
    
    try:
        gid = interaction.guild.id
        uid = user.id
        
        if uid not in ACTIVE_SHIFTS[gid]:
            await interaction.followup.send(f"❌ {user.mention} has no active shift", ephemeral=True)
            return
        
        SHIFT_LOCKS[gid][uid] = True
        
        embed = discord.Embed(title="🔒 Shift Locked", description=f"{user.mention}'s shift locked", color=discord.Color.orange())
        embed.add_field(name="Reason", value=reason, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'shift', 'Shift Locked', interaction.user, f"{user.mention}: {reason}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="shift-unlock", description="Unlock a user's shift")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def shift_unlock(interaction: discord.Interaction, user: discord.Member):
    """Unlock shift"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        gid = interaction.guild.id
        uid = user.id
        
        if not SHIFT_LOCKS[gid].get(uid, False):
            await interaction.followup.send(f"❌ {user.mention}'s shift is not locked", ephemeral=True)
            return
        
        SHIFT_LOCKS[gid][uid] = False
        
        embed = discord.Embed(title="🔓 Shift Unlocked", description=f"{user.mention}'s shift unlocked", color=discord.Color.green())
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'shift', 'Shift Unlocked', interaction.user, f"{user.mention}")
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="quick_status", description="Quick status check")
@rate_limit(max_calls=10, window=60)
async def quick_status(interaction: discord.Interaction):
    """Quick check"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        active = sum(len(shifts) for shifts in ACTIVE_SHIFTS.values())
        locked = sum(sum(1 for locked in locks.values() if locked) for locks in SHIFT_LOCKS.values())
        
        embed = discord.Embed(title="⚡ Quick Status", color=discord.Color.blue(), timestamp=datetime.now())
        embed.add_field(name="Active Shifts", value=str(active), inline=True)
        embed.add_field(name="Locked Shifts", value=str(locked), inline=True)
        embed.add_field(name="Members", value=str(len(interaction.guild.members)), inline=True)
        embed.add_field(name="Channels", value=str(len(interaction.guild.channels)), inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="perms_check", description="Check user permissions")
@app_commands.checks.has_permissions(administrator=True)
async def perms_check(interaction: discord.Interaction, user: discord.Member):
    """Check perms"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        data = await db.get_member_tier(interaction.guild.id, user.id)
        tier = data.get('tier', 1) if data else 1
        
        tier_name = "USER"
        for name, t in ROLE_HIERARCHY.items():
            if t == tier:
                tier_name = name
                break
        
        embed = discord.Embed(title=f"🔐 Permissions: {user.name}", color=discord.Color.blue())
        embed.add_field(name="Tier", value=f"{tier_name} ({tier})", inline=True)
        
        hier = "**Hierarchy:**\n"
        for name in sorted(ROLE_HIERARCHY.items(), key=lambda x: x[1], reverse=True):
            hier += f"• {name[0]} (Tier {name[1]})\n"
        embed.add_field(name="Tiers", value=hier, inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# PART 4/4 - COMPLETE FINAL - ADD THIS AFTER PART 3

# ============= MISSING: VERIFICATION SYSTEM =============

class VerificationView(discord.ui.View):
    """Verification button view"""
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(label="Verify", style=discord.ButtonStyle.green, custom_id="verify_button")
    async def verify_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Verify button"""
        config = server_configs.get(interaction.guild.id, {})
        verified_role_id = config.get('verified_role_id')
        unverified_role_id = config.get('unverified_role_id')
        
        if not verified_role_id:
            await interaction.response.send_message("❌ Verification not configured", ephemeral=True)
            return
        
        verified_role = interaction.guild.get_role(verified_role_id)
        unverified_role = interaction.guild.get_role(unverified_role_id) if unverified_role_id else None
        
        member = interaction.user
        
        if verified_role and verified_role in member.roles:
            await interaction.response.send_message("✅ Already verified!", ephemeral=True)
            return
        
        try:
            if verified_role and verified_role not in member.roles:
                await member.add_roles(verified_role, reason="Member verified")
            
            if unverified_role and unverified_role in member.roles:
                await member.remove_roles(unverified_role, reason="Member verified")
            
            await interaction.response.send_message("✅ You have been verified!", ephemeral=True)
            
            await log_action(interaction.guild, 'verification', 'User Verified', member, f"{member.mention} verified via button")
            await db.add_log(interaction.guild.id, 'member_verified', member.id, {'verification_method': 'button'})
            
        except discord.Forbidden:
            await interaction.response.send_message("❌ Missing permissions", ephemeral=True)
        except Exception as e:
            logger.error(f"Error: {e}")
            await interaction.response.send_message("❌ Verification failed", ephemeral=True)

class RobloxVerificationView(discord.ui.View):
    """Roblox verification view"""
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(label="Start Verification", style=discord.ButtonStyle.green, custom_id="roblox_verify_start")
    async def start_verification(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Start Roblox verification"""
        try:
            verification = await db.get_verification(interaction.guild.id, interaction.user.id)
            
            if verification and verification.get('verified'):
                await interaction.response.send_message("✅ Already verified!", ephemeral=True)
                return
            
            code = f"VERIFY-{generate_verification_code()}"
            
            await db.create_verification(interaction.guild.id, interaction.user.id, code)
            
            embed = discord.Embed(
                title="🎮 Roblox Verification",
                description=(
                    f"**Your code:** `{code}`\n\n"
                    f"1. Go to [Roblox Settings](https://www.roblox.com/my/account#!/info)\n"
                    f"2. Add code to **About** section\n"
                    f"3. Click 'I've added the code'\n"
                    f"4. Enter your username\n\n"
                    f"⏰ Expires in 5 minutes"
                ),
                color=discord.Color.blue()
            )
            
            view = RobloxVerificationConfirmView()
            await interaction.response.send_message(embed=embed, view=view, ephemeral=True)
            
        except Exception as e:
            logger.error(f"Error: {e}")
            await interaction.response.send_message("❌ Failed", ephemeral=True)

class RobloxVerificationConfirmView(discord.ui.View):
    """Roblox confirm view"""
    def __init__(self):
        super().__init__(timeout=VERIFICATION_TIMEOUT)
    
    @discord.ui.button(label="I've added the code", style=discord.ButtonStyle.green, custom_id="roblox_verify_confirm")
    async def confirm_verification(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Confirm verification"""
        await interaction.response.defer(ephemeral=True)
        
        try:
            verification = await db.get_verification(interaction.guild.id, interaction.user.id)
            
            if not verification:
                await interaction.followup.send("❌ No verification in progress", ephemeral=True)
                return
            
            if verification.get('verified'):
                await interaction.followup.send("✅ Already verified!", ephemeral=True)
                return
            
            await interaction.followup.send("Reply with your **Roblox username**:", ephemeral=True)
            
            def check(m):
                return m.author == interaction.user and m.channel == interaction.channel
            
            try:
                msg = await bot.wait_for('message', timeout=60.0, check=check)
                roblox_username = sanitize_string(msg.content.strip(), 20)
                
                try:
                    await msg.delete()
                except:
                    pass
                
                await interaction.followup.send("🔍 Checking Roblox profile...", ephemeral=True)
                
                roblox_data = await get_roblox_user_info(roblox_username)
                
                if not roblox_data:
                    await interaction.followup.send(f"❌ Roblox user '{roblox_username}' not found", ephemeral=True)
                    return
                
                if verification['verification_code'] not in roblox_data['description']:
                    await interaction.followup.send(f"❌ Code not found in profile description", ephemeral=True)
                    return
                
                await db.complete_verification(
                    interaction.guild.id,
                    interaction.user.id,
                    roblox_data['id'],
                    roblox_data['username']
                )
                
                config = server_configs.get(interaction.guild.id, {})
                verified_role_id = config.get('verified_role_id')
                unverified_role_id = config.get('unverified_role_id')
                
                member = interaction.user
                
                if verified_role_id:
                    verified_role = interaction.guild.get_role(verified_role_id)
                    if verified_role and verified_role not in member.roles:
                        await member.add_roles(verified_role, reason="Roblox verification")
                
                if unverified_role_id:
                    unverified_role = interaction.guild.get_role(unverified_role_id)
                    if unverified_role and unverified_role in member.roles:
                        await member.remove_roles(unverified_role, reason="Roblox verification")
                
                embed = discord.Embed(
                    title="✅ Verified!",
                    description=f"**Account:** {roblox_data['username']}\n**ID:** {roblox_data['id']}",
                    color=discord.Color.green()
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
                await log_action(interaction.guild, 'verification', 'Roblox Verified', member, f"Verified as {roblox_data['username']}")
                
            except asyncio.TimeoutError:
                await interaction.followup.send("❌ Timeout", ephemeral=True)
                
        except Exception as e:
            logger.error(f"Error: {e}")
            await interaction.followup.send("❌ Error", ephemeral=True)

def generate_verification_code() -> str:
    """Generate verification code"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=VERIFICATION_CODE_LENGTH))

async def get_roblox_user_info(username: str) -> Optional[Dict[str, Any]]:
    """Get Roblox user info"""
    username = sanitize_string(username, 20)
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
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
                
                async with session.get(f'https://users.roblox.com/v1/users/{user_id}') as profile_resp:
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
        logger.error(f'Roblox error: {e}')
        return None

# ============= VERIFICATION SETUP COMMANDS =============

@bot.tree.command(name="setup_verification", description="Setup verification system")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=2, window=600)
async def setup_verification(interaction: discord.Interaction, channel: discord.TextChannel):
    """Setup verification"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        unverified_role = discord.utils.get(interaction.guild.roles, name="Unverified")
        if not unverified_role:
            unverified_role = await interaction.guild.create_role(
                name="Unverified",
                color=discord.Color.light_grey(),
                permissions=discord.Permissions.none(),
                reason=f"Verification by {interaction.user}"
            )
        
        verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
        if not verified_role:
            verified_role = await interaction.guild.create_role(
                name="Verified",
                color=discord.Color.green(),
                reason=f"Verification by {interaction.user}"
            )
        
        await db.set_server_config(
            interaction.guild.id,
            unverified_role_id=unverified_role.id,
            verified_role_id=verified_role.id,
            verification_channel_id=channel.id,
            verification_enabled=True
        )
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id].update({
            'unverified_role_id': unverified_role.id,
            'verified_role_id': verified_role.id,
            'verification_channel_id': channel.id,
            'verification_enabled': True
        })
        
        view = VerificationView()
        embed = discord.Embed(
            title="✅ Welcome!",
            description="Click below to verify",
            color=discord.Color.blue()
        )
        await channel.send(embed=embed, view=view)
        
        embed = discord.Embed(
            title="✅ Verification Setup",
            description=f"Unverified: {unverified_role.mention}\nVerified: {verified_role.mention}",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="setup_roblox_verification", description="Setup Roblox verification")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=2, window=600)
async def setup_roblox_verification(interaction: discord.Interaction, channel: discord.TextChannel):
    """Setup Roblox verification"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        unverified_role = discord.utils.get(interaction.guild.roles, name="Unverified")
        if not unverified_role:
            unverified_role = await interaction.guild.create_role(
                name="Unverified",
                color=discord.Color.light_grey(),
                reason=f"Roblox by {interaction.user}"
            )
        
        verified_role = discord.utils.get(interaction.guild.roles, name="Verified")
        if not verified_role:
            verified_role = await interaction.guild.create_role(
                name="Verified",
                color=discord.Color.green(),
                reason=f"Roblox by {interaction.user}"
            )
        
        await db.set_server_config(
            interaction.guild.id,
            unverified_role_id=unverified_role.id,
            verified_role_id=verified_role.id,
            verification_channel_id=channel.id,
            verification_enabled=True
        )
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id].update({
            'unverified_role_id': unverified_role.id,
            'verified_role_id': verified_role.id,
            'verification_channel_id': channel.id,
            'verification_enabled': True
        })
        
        view = RobloxVerificationView()
        embed = discord.Embed(
            title="🎮 Roblox Verification",
            description="Click below to verify your Roblox account",
            color=discord.Color.blue()
        )
        await channel.send(embed=embed, view=view)
        
        embed = discord.Embed(title="✅ Roblox Setup", color=discord.Color.green())
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="verification_enable", description="Enable verification")
@app_commands.checks.has_permissions(administrator=True)
async def verification_enable(interaction: discord.Interaction):
    """Enable verification"""
    config = server_configs.get(interaction.guild.id, {})
    
    if not config.get('verification_channel_id'):
        await interaction.response.send_message("❌ Not setup!", ephemeral=True)
        return
    
    try:
        await db.update_server_field(interaction.guild.id, 'verification_enabled', True)
        server_configs[interaction.guild.id]['verification_enabled'] = True
        
        await interaction.response.send_message("✅ Enabled", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.response.send_message("❌ Failed", ephemeral=True)

@bot.tree.command(name="verification_disable", description="Disable verification")
@app_commands.checks.has_permissions(administrator=True)
async def verification_disable(interaction: discord.Interaction):
    """Disable verification"""
    try:
        await db.update_server_field(interaction.guild.id, 'verification_enabled', False)
        if interaction.guild.id in server_configs:
            server_configs[interaction.guild.id]['verification_enabled'] = False
        
        await interaction.response.send_message("✅ Disabled", ephemeral=True)
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.response.send_message("❌ Failed", ephemeral=True)

@bot.tree.command(name="verify_user", description="Manually verify user")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=10, window=60)
async def verify_user(interaction: discord.Interaction, user: discord.Member):
    """Verify user"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id, {})
    verified_role_id = config.get('verified_role_id')
    unverified_role_id = config.get('unverified_role_id')
    
    if not verified_role_id:
        await interaction.followup.send("❌ Not setup", ephemeral=True)
        return
    
    verified_role = interaction.guild.get_role(verified_role_id)
    unverified_role = interaction.guild.get_role(unverified_role_id) if unverified_role_id else None
    
    try:
        if verified_role and verified_role not in user.roles:
            await user.add_roles(verified_role, reason=f"Verified by {interaction.user.name}")
        
        if unverified_role and unverified_role in user.roles:
            await user.remove_roles(unverified_role, reason=f"Verified by {interaction.user.name}")
        
        await log_action(interaction.guild, 'verification', 'Manual Verify', interaction.user, f"{user.mention}")
        
        await interaction.followup.send(f"✅ {user.mention} verified", ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="whois", description="Show linked Roblox account")
@app_commands.checks.has_permissions(manage_guild=True)
async def whois_command(interaction: discord.Interaction, user: discord.Member):
    """Whois"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        verification = await db.get_verification(interaction.guild.id, user.id)
        
        if not verification or not verification.get('verified'):
            await interaction.followup.send(f"{user.mention} not verified", ephemeral=True)
            return
        
        embed = discord.Embed(title=f"🔍 {user.name}", color=discord.Color.blue())
        embed.add_field(name="Discord", value=user.mention, inline=True)
        embed.add_field(name="Roblox", value=verification.get('roblox_username', 'Unknown'), inline=True)
        
        rid = verification.get('roblox_id')
        if rid:
            embed.add_field(name="Profile", value=f"https://www.roblox.com/users/{rid}/profile", inline=False)
        
        embed.set_thumbnail(url=user.display_avatar.url)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= MORE MISSING COMMANDS =============

@bot.tree.command(name="set_onduty_role", description="Set on-duty role")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def set_onduty_role(interaction: discord.Interaction, role: discord.Role):
    """Set on duty role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'onduty_role_id', role.id)
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id]['onduty_role_id'] = role.id
        
        embed = discord.Embed(title="✅ On Duty Role Set", description=f"{role.mention}", color=discord.Color.green())
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'config', 'On Duty Role Set', interaction.user, f"{role.name}")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="set_allstaff_role", description="Set all-staff role")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def set_allstaff_role(interaction: discord.Interaction, role: discord.Role):
    """Set all staff role"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'allstaff_role_id', role.id)
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id]['allstaff_role_id'] = role.id
        
        embed = discord.Embed(title="✅ All Staff Role Set", description=f"{role.mention}", color=discord.Color.green())
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'config', 'All Staff Role Set', interaction.user, f"{role.name}")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= ADDITIONAL EMAIL HELPERS =============

async def send_shift_email(email: str, user_name: str, action: str, department: str = None, duration: str = None):
    """Send shift event email"""
    if not validate_email(email):
        return
    
    action_text = f"{action} their shift"
    dept_text = f" in {department}" if department else ""
    duration_text = f" ({duration})" if duration else ""
    
    text = f"""
Shift Event Notification

User: {user_name}
Action: {action_text}{dept_text}{duration_text}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

---
Sentinel Security Bot
"""
    
    html = f"""<html><body style="font-family: Arial; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px;">
        <h2 style="color: #3498db;">⏱️ Shift Event</h2>
        <p><b>User:</b> {user_name}</p>
        <p><b>Action:</b> {action_text}{dept_text}{duration_text}</p>
        <p><b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p style="color: #7f8c8d; font-size: 12px;">Sentinel Security Bot</p>
    </div>
    </body></html>"""
    
    asyncio.create_task(send_sentinel_mail(email, f"⏱️ Shift {action_text}", text, html))

async def send_role_email(email: str, user_name: str, role_name: str, action: str, reason: str = None):
    """Send role request email"""
    if not validate_email(email):
        return
    
    reason_text = f"\nReason: {reason}" if reason else ""
    
    text = f"""
Role Request Update

User: {user_name}
Role: {role_name}
Action: {action}{reason_text}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

---
Sentinel Security Bot
"""
    
    html = f"""<html><body style="font-family: Arial; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px;">
        <h2 style="color: #3498db;">👥 Role Request</h2>
        <p><b>User:</b> {user_name}</p>
        <p><b>Role:</b> {role_name}</p>
        <p><b>Action:</b> {action}</p>
        {f'<p><b>Reason:</b> {reason}</p>' if reason else ''}
        <p><b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p style="color: #7f8c8d; font-size: 12px;">Sentinel Security Bot</p>
    </div>
    </body></html>"""
    
    asyncio.create_task(send_sentinel_mail(email, f"👥 Role {action}", text, html))

async def send_department_email(email: str, user_name: str, department: str, action: str, reason: str = None):
    """Send department event email"""
    if not validate_email(email):
        return
    
    reason_text = f"\nReason: {reason}" if reason else ""
    
    text = f"""
Department Update

User: {user_name}
Department: {department}
Action: {action}{reason_text}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

---
Sentinel Security Bot
"""
    
    html = f"""<html><body style="font-family: Arial; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px;">
        <h2 style="color: #3498db;">👥 Department Update</h2>
        <p><b>User:</b> {user_name}</p>
        <p><b>Department:</b> {department}</p>
        <p><b>Action:</b> {action}</p>
        {f'<p><b>Reason:</b> {reason}</p>' if reason else ''}
        <p style="color: #7f8c8d; font-size: 12px;">Sentinel Security Bot</p>
    </div>
    </body></html>"""
    
    asyncio.create_task(send_sentinel_mail(email, f"👥 Department {action}", text, html))

# ============= ADDITIONAL EVENT HANDLERS =============

@bot.event
async def on_member_join(member: discord.Member):
    """Track new members"""
    try:
        await db.add_log(
            member.guild.id,
            'member_join',
            member.id,
            {'username': member.name, 'account_age': (datetime.now() - member.created_at).days}
        )
        logger.info(f"Member joined: {member.name} ({member.id}) in {member.guild.name}")
    except Exception as e:
        logger.error(f"Error in on_member_join: {e}")

@bot.event
async def on_member_remove(member: discord.Member):
    """Track member removals"""
    try:
        await db.add_log(
            member.guild.id,
            'member_remove',
            member.id,
            {'username': member.name}
        )
        logger.info(f"Member left: {member.name} ({member.id}) from {member.guild.name}")
    except Exception as e:
        logger.error(f"Error in on_member_remove: {e}")

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
                
                count = track_action(guild.id, user.id, 'role_delete')
                threshold = DEFAULT_THRESHOLDS['role_delete']
                
                if count >= threshold['count']:
                    await send_alert(
                        guild,
                        f"⚠️ **ROLE DELETE THRESHOLD BREACHED**\n"
                        f"{user.mention} deleted {count} roles in {threshold['seconds']} seconds!",
                        user,
                        email_admins=True
                    )
                    await quarantine_user(guild, user, f"Mass role deletion ({count} roles)")
                break
    except Exception as e:
        logger.error(f"Error in on_guild_role_delete: {e}")

@bot.event
async def on_guild_role_create(role: discord.Role):
    """Monitor suspicious role creation"""
    try:
        await asyncio.sleep(1)
        guild = role.guild
        
        async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.role_create):
            if entry.target.id == role.id:
                user = entry.user
                
                if user.bot or await is_whitelisted(guild.id, user.id):
                    return
                
                # Log role creation
                await db.add_log(
                    guild.id,
                    'role_create',
                    user.id,
                    {'role_name': role.name, 'role_id': role.id}
                )
                break
    except Exception as e:
        logger.error(f"Error in on_guild_role_create: {e}")

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    """Monitor member role changes"""
    try:
        if before.roles != after.roles:
            added_roles = [r for r in after.roles if r not in before.roles]
            removed_roles = [r for r in before.roles if r not in after.roles]
            
            guild = after.guild
            
            if added_roles or removed_roles:
                await db.add_log(
                    guild.id,
                    'member_roles_changed',
                    after.id,
                    {
                        'added': [r.name for r in added_roles],
                        'removed': [r.name for r in removed_roles]
                    }
                )
    except Exception as e:
        logger.error(f"Error in on_member_update: {e}")

# ============= BACKGROUND TASKS =============

@tasks.loop(minutes=5)
async def shift_heartbeat():
    """Monitor active shifts every 5 minutes"""
    try:
        for guild_id, shifts in ACTIVE_SHIFTS.items():
            for user_id, shift in list(shifts.items()):
                elapsed = (datetime.now() - shift['start_time']).total_seconds()
                
                # Log shift status
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
    """Clean up logs older than 30 days"""
    try:
        cutoff = datetime.now() - timedelta(days=30)
        await db.delete_old_logs(cutoff)
        logger.info("Cleaned up old logs")
    except Exception as e:
        logger.error(f"Log cleanup error: {e}")

@tasks.loop(hours=6)
async def reset_daily_threat():
    """Reset threat level daily if no incidents"""
    try:
        for guild_id in server_configs.keys():
            threat = await db.get_current_threat_level(guild_id)
            level = threat.get('threat_level', 0) if threat else 0
            
            if level > 0:
                # Check if there were incidents in last 6 hours
                recent_alerts = await db.get_recent_alerts(guild_id, hours=6)
                
                if not recent_alerts:
                    # Reset to Clear
                    await db.set_threat_level(guild_id, 0)
                    logger.info(f"Reset threat level to Clear for guild {guild_id}")
    except Exception as e:
        logger.error(f"Threat reset error: {e}")

@shift_heartbeat.before_loop
@cleanup_old_logs.before_loop
@reset_daily_threat.before_loop
async def before_loops():
    """Wait until bot is ready"""
    await bot.wait_until_ready()

# ============= ENHANCED EMAIL COMMANDS =============

# Update /shift-start to include email
@bot.tree.command(name="shift-start-email", description="Start shift (with email)")
@rate_limit(max_calls=5, window=60)
async def shift_start_email(interaction: discord.Interaction, department: str = None, callsign: str = None):
    """Start shift with email"""
    await interaction.response.defer(ephemeral=True)
    
    if department:
        department = sanitize_string(department, 50)
    if callsign:
        callsign = sanitize_string(callsign, 50)
    
    try:
        uid = interaction.user.id
        gid = interaction.guild.id
        
        if uid in ACTIVE_SHIFTS[gid]:
            await interaction.followup.send("❌ Already on shift", ephemeral=True)
            return
        
        start_time = datetime.now()
        ACTIVE_SHIFTS[gid][uid] = {
            'start_time': start_time,
            'department': department,
            'callsign': callsign,
            'status': 'active'
        }
        
        await db.create_shift(gid, uid, department, start_time, callsign=callsign)
        
        # Send email to user
        try:
            user_email = await db.get_user_email(gid, uid)
            if user_email:
                await send_shift_email(user_email, interaction.user.name, "started", department)
        except:
            pass
        
        # Add on-duty role
        config = server_configs.get(gid, {})
        onduty_id = config.get('onduty_role_id')
        if onduty_id:
            member = interaction.guild.get_member(uid)
            role = interaction.guild.get_role(onduty_id)
            if member and role:
                try:
                    await member.add_roles(role, reason="Shift started")
                except:
                    pass
        
        embed = discord.Embed(title="✅ Shift Started", color=discord.Color.green())
        if department:
            embed.add_field(name="Department", value=department, inline=True)
        if callsign:
            embed.add_field(name="Callsign", value=callsign, inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        await log_action(interaction.guild, 'shift', 'Shift Started', interaction.user, f"Dept: {department or 'None'}")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= MISSING MONITORING COMMANDS =============

@bot.tree.command(name="shift-check-overlap", description="Check for overlapping shifts")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def shift_check_overlap(interaction: discord.Interaction):
    """Check overlapping shifts"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        overlaps = await db.detect_shift_overlaps(interaction.guild.id)
        
        if not overlaps:
            await interaction.followup.send("✅ No overlaps", ephemeral=True)
            return
        
        embed = discord.Embed(title="⚠️ Overlapping Shifts", color=discord.Color.orange())
        text = []
        for o in overlaps[:10]:
            users = o.get('users', [])
            dept = o.get('department', 'Unknown')
            names = ", ".join([bot.get_user(u).name if bot.get_user(u) else f"User {u}" for u in users])
            text.append(f"**{dept}**: {names}")
        
        embed.description = "\n".join(text)
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="shift-violations", description="Check shift violations")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def shift_violations(interaction: discord.Interaction, hours: int = 24):
    """Shift violations"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        violations = await db.detect_shift_violations(interaction.guild.id, hours)
        
        if not violations:
            await interaction.followup.send(f"✅ No violations in {hours}h", ephemeral=True)
            return
        
        embed = discord.Embed(title="⚠️ Violations", color=discord.Color.orange())
        text = []
        for v in violations[:10]:
            uid = v.get('user_id')
            vtype = v.get('type', 'unknown')
            u = bot.get_user(uid)
            uname = u.name if u else f"User {uid}"
            text.append(f"• {uname}: {vtype}")
        
        embed.description = "\n".join(text)
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="shift-report", description="Generate shift report")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def shift_report(interaction: discord.Interaction, days: int = 7):
    """Shift report"""
    await interaction.response.defer(ephemeral=True)
    
    if days > 90:
        days = 90
    
    try:
        report = await db.generate_shift_report(interaction.guild.id, days)
        
        embed = discord.Embed(title=f"📊 Shift Report ({days}d)", color=discord.Color.blue())
        embed.add_field(name="Total Shifts", value=report.get('total_shifts', 0), inline=True)
        embed.add_field(name="Total Hours", value=f"{report.get('total_hours', 0):.1f}h", inline=True)
        embed.add_field(name="Avg Duration", value=f"{report.get('avg_duration', 0):.1f}h", inline=True)
        embed.add_field(name="Top User", value=report.get('top_user', 'N/A'), inline=True)
        embed.add_field(name="Top Dept", value=report.get('top_dept', 'N/A'), inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="role-heal", description="Auto-restore roles in department")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=300)
async def role_heal(interaction: discord.Interaction, department: str):
    """Role heal"""
    await interaction.response.defer(ephemeral=True)
    
    department = sanitize_string(department, 50)
    
    try:
        members = await db.get_department_members(interaction.guild.id, department)
        
        if not members:
            await interaction.followup.send(f"ℹ️ No members in {department}", ephemeral=True)
            return
        
        healed = 0
        failed = 0
        
        dept_info = await db.get_department(interaction.guild.id, department)
        dept_role_id = dept_info.get('role_id') if dept_info else None
        
        for m in members:
            uid = m.get('user_id')
            member = interaction.guild.get_member(uid)
            
            if not member:
                continue
            
            try:
                if dept_role_id:
                    role = interaction.guild.get_role(dept_role_id)
                    if role and role not in member.roles:
                        await member.add_roles(role, reason="Auto-role healing")
                        healed += 1
            except:
                failed += 1
        
        embed = discord.Embed(title="✅ Role Healing", color=discord.Color.green())
        embed.add_field(name="Healed", value=str(healed), inline=True)
        embed.add_field(name="Failed", value=str(failed), inline=True)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

@bot.tree.command(name="dept-analytics", description="Department analytics")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=5, window=60)
async def dept_analytics(interaction: discord.Interaction, department: str = None):
    """Analytics"""
    await interaction.response.defer(ephemeral=True)
    
    if department:
        department = sanitize_string(department, 50)
    
    try:
        if department:
            members = await db.get_department_members(interaction.guild.id, department)
            shifts = await db.get_department_shifts(interaction.guild.id, department)
            
            embed = discord.Embed(title=f"📊 {department}", color=discord.Color.blue())
            
            total_h = sum(s.get('duration_seconds', 0) for s in shifts) / 3600 if shifts else 0
            avg_shift = total_h / len(shifts) if shifts else 0
            
            embed.add_field(name="Members", value=str(len(members)), inline=True)
            embed.add_field(name="Shifts", value=str(len(shifts)), inline=True)
            embed.add_field(name="Total Hours", value=f"{total_h:.1f}h", inline=True)
            embed.add_field(name="Avg Shift", value=f"{avg_shift:.1f}h", inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            depts = await db.get_all_departments(interaction.guild.id)
            
            embed = discord.Embed(title="📊 Analytics", color=discord.Color.blue())
            
            total_m = 0
            total_s = 0
            
            for d in depts:
                m = await db.get_department_members(interaction.guild.id, d['name'])
                s = await db.get_department_shifts(interaction.guild.id, d['name'])
                total_m += len(m)
                total_s += len(s)
            
            embed.add_field(name="Departments", value=str(len(depts)), inline=True)
            embed.add_field(name="Members", value=str(total_m), inline=True)
            embed.add_field(name="Shifts", value=str(total_s), inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        await interaction.followup.send("❌ Failed", ephemeral=True)

# ============= DAILY VIOLATION REPORTS - CORRECTED =============
# Place this AFTER all your command definitions, before EVENT HANDLERS

from discord.ext import tasks
from datetime import datetime, timezone, time

# Track last report send time to prevent duplicates
last_report_time = {}

@tasks.loop(minutes=5)
async def daily_violation_report():
    """Send daily violation reports to admins via email - runs every 5 minutes, sends at 6 AM UTC"""
    try:
        # Get current UTC time
        now = datetime.now(timezone.utc)
        current_time = now.time()
        
        # Define report time as 6:00 AM UTC (with 5-minute window: 6:00-6:05)
        report_time_start = time(6, 0, 0)  # 6:00 AM UTC
        report_time_end = time(6, 5, 0)    # 6:05 AM UTC
        
        # Check if current time is within report window
        if not (report_time_start <= current_time < report_time_end):
            return
        
        logger.info("🚀 Starting daily violation report task...")
        
        # Process each guild
        for guild in bot.guilds:
            try:
                guild_id = guild.id
                
                # Skip if we already sent report for this guild today
                last_sent = last_report_time.get(guild_id)
                if last_sent and (now - last_sent).total_seconds() < 3600:  # Already sent within last hour
                    logger.debug(f"Already sent report for {guild.name} today, skipping")
                    continue
                
                # Check if daily reports enabled
                config = server_configs.get(guild_id, {})
                if not config.get('daily_reports_enabled', False):
                    logger.debug(f"Daily reports disabled for {guild.name}")
                    continue
                
                # Get violations from last 24 hours
                violations = await db.detect_shift_violations(guild_id, hours=24)
                quarantine_incidents = await db.get_logs(guild_id, category='quarantine', limit=50)
                threat_changes = await db.get_logs(guild_id, category='threat', limit=50)
                
                if not violations and not quarantine_incidents and not threat_changes:
                    logger.debug(f"No violations for {guild.name}")
                    continue
                
                # Collect admin emails
                admin_emails = []
                for member in guild.members:
                    if member.guild_permissions.administrator:
                        try:
                            email = await db.get_user_email(guild_id, member.id)
                            if email and validate_email(email):
                                admin_emails.append(email)
                        except Exception as e:
                            logger.error(f"Error getting email for {member.name}: {e}")
                
                if not admin_emails:
                    logger.debug(f"No admin emails for {guild.name}")
                    continue
                
                # Generate report
                report = await generate_violation_report(guild, violations, quarantine_incidents, threat_changes)
                
                # Send to each admin
                sent_count = 0
                for email in admin_emails[:MAX_EMAIL_RECIPIENTS]:
                    try:
                        result = await send_violation_report_email(email, guild.name, report)
                        if result:
                            sent_count += 1
                            logger.info(f"✅ Sent daily violation report to {email} for {guild.name}")
                    except Exception as e:
                        logger.error(f"Error sending report to {email}: {e}")
                
                # Mark as sent
                if sent_count > 0:
                    last_report_time[guild_id] = now
                    await log_action(
                        guild,
                        'daily_report',
                        'Daily Violation Report Sent',
                        None,
                        f"Daily report sent to {sent_count} admin(s)"
                    )
                
            except Exception as e:
                logger.error(f"Error processing violations for {guild.name}: {e}")
        
        logger.info("✅ Daily violation report task completed")
        
    except Exception as e:
        logger.error(f"Error in daily violation report task: {e}")

@daily_violation_report.before_loop
async def before_daily_report():
    """Wait until bot is ready"""
    await bot.wait_until_ready()
    logger.info("📊 Daily violation report task ready (runs daily at 6 AM UTC)")

async def generate_violation_report(
    guild: discord.Guild,
    violations: List[Dict],
    quarantine_incidents: List[Dict],
    threat_changes: List[Dict]
) -> Dict[str, Any]:
    """Generate comprehensive violation report"""
    try:
        report = {
            'guild_name': guild.name,
            'guild_id': guild.id,
            'timestamp': datetime.now(timezone.utc),
            'violations': [],
            'quarantines': [],
            'threats': [],
            'summary': {}
        }
        
        # Process violations
        if violations:
            for v in violations[:10]:
                user_id = v.get('user_id')
                violation_type = v.get('type', 'unknown')
                user = bot.get_user(user_id)
                user_name = user.name if user else f"User {user_id}"
                
                report['violations'].append({
                    'user': user_name,
                    'type': violation_type,
                    'timestamp': v.get('timestamp', 'Unknown')
                })
        
        # Process quarantines
        if quarantine_incidents:
            for q in quarantine_incidents[:10]:
                user_id = q.get('user_id')
                details = q.get('details', {})
                user = bot.get_user(user_id)
                user_name = user.name if user else f"User {user_id}"
                
                report['quarantines'].append({
                    'user': user_name,
                    'reason': details.get('message', 'No reason'),
                    'timestamp': q.get('timestamp', 'Unknown')
                })
        
        # Process threat changes
        if threat_changes:
            for t in threat_changes[:10]:
                details = t.get('details', {})
                report['threats'].append({
                    'level': details.get('threat_name', 'Unknown'),
                    'timestamp': t.get('timestamp', 'Unknown')
                })
        
        # Summary
        report['summary'] = {
            'total_violations': len(violations),
            'total_quarantines': len(quarantine_incidents),
            'total_threats': len(threat_changes),
            'period': '24 hours'
        }
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating violation report: {e}")
        return {
            'guild_name': guild.name,
            'guild_id': guild.id,
            'timestamp': datetime.now(timezone.utc),
            'error': str(e)
        }

async def send_violation_report_email(email: str, guild_name: str, report: Dict[str, Any]) -> bool:
    """Send daily violation report email"""
    if not validate_email(email):
        return False
    
    try:
        # Build text content
        text_content = f"""
SENTINEL SECURITY BOT - DAILY VIOLATION REPORT
=============================================

Server: {guild_name}
Report Date: {report['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}
Period: Last 24 Hours

SUMMARY
-------
Total Violations: {report['summary'].get('total_violations', 0)}
Total Quarantines: {report['summary'].get('total_quarantines', 0)}
Threat Level Changes: {report['summary'].get('total_threats', 0)}
"""
        
        if report.get('violations'):
            text_content += "\nVIOLATIONS\n"
            text_content += "-" * 40 + "\n"
            for i, v in enumerate(report['violations'], 1):
                text_content += f"\n{i}. {v['user']}\n"
                text_content += f"   Type: {v['type']}\n"
                text_content += f"   Time: {v['timestamp']}\n"
        else:
            text_content += "\n✅ No violations detected\n"
        
        if report.get('quarantines'):
            text_content += "\nQUARANTINES\n"
            text_content += "-" * 40 + "\n"
            for i, q in enumerate(report['quarantines'], 1):
                text_content += f"\n{i}. {q['user']}\n"
                text_content += f"   Reason: {q['reason']}\n"
                text_content += f"   Time: {q['timestamp']}\n"
        
        if report.get('threats'):
            text_content += "\nTHREAT LEVEL CHANGES\n"
            text_content += "-" * 40 + "\n"
            for i, t in enumerate(report['threats'], 1):
                text_content += f"\n{i}. {t['level']}\n"
                text_content += f"   Time: {t['timestamp']}\n"
        
        text_content += f"""

---
This is an automated report from Sentinel Security Bot.
Report Period: 24 Hours
Next Report: Tomorrow at 6 AM UTC

For more details, check your Discord server logs.
"""
        
        # Build HTML content
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px; }}
                .container {{ max-width: 700px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 6px; margin-bottom: 25px; }}
                .header h1 {{ margin: 0; font-size: 24px; }}
                .header p {{ margin: 5px 0 0 0; opacity: 0.9; }}
                .summary {{ background-color: #f9f9f9; padding: 15px; border-left: 4px solid #667eea; margin: 20px 0; border-radius: 4px; }}
                .summary-item {{ display: inline-block; margin-right: 30px; }}
                .summary-item .number {{ font-size: 24px; font-weight: bold; color: #667eea; }}
                .summary-item .label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
                .section {{ margin: 25px 0; }}
                .section-title {{ font-size: 16px; font-weight: bold; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 8px; margin-bottom: 15px; }}
                .violation-item {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 12px 15px; margin: 10px 0; border-radius: 4px; }}
                .quarantine-item {{ background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 12px 15px; margin: 10px 0; border-radius: 4px; }}
                .threat-item {{ background-color: #d1ecf1; border-left: 4px solid #17a2b8; padding: 12px 15px; margin: 10px 0; border-radius: 4px; }}
                .clear {{ background-color: #d4edda; border-left: 4px solid #28a745; padding: 12px 15px; margin: 10px 0; border-radius: 4px; }}
                .item-user {{ font-weight: bold; color: #333; }}
                .item-detail {{ font-size: 12px; color: #666; margin: 4px 0; }}
                .footer {{ background-color: #f9f9f9; padding: 15px; border-top: 1px solid #eee; margin-top: 25px; text-align: center; font-size: 11px; color: #999; }}
                .footer p {{ margin: 5px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ Sentinel Security Bot</h1>
                    <p>Daily Violation Report</p>
                </div>
                
                <div style="background-color: #f0f0f0; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                    <strong>Server:</strong> {guild_name}<br>
                    <strong>Report Date:</strong> {report['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
                    <strong>Period:</strong> Last 24 Hours
                </div>
                
                <div class="summary">
                    <div class="summary-item">
                        <div class="number">{report['summary'].get('total_violations', 0)}</div>
                        <div class="label">Violations</div>
                    </div>
                    <div class="summary-item">
                        <div class="number">{report['summary'].get('total_quarantines', 0)}</div>
                        <div class="label">Quarantines</div>
                    </div>
                    <div class="summary-item">
                        <div class="number">{report['summary'].get('total_threats', 0)}</div>
                        <div class="label">Threat Changes</div>
                    </div>
                </div>
                
                <div class="section">
                    <div class="section-title">{'⚠️ Violations' if report.get('violations') else '✅ No Violations'}</div>
                    {''.join([f"<div class='violation-item'><div class='item-user'>{v['user']}</div><div class='item-detail'>Type: {v['type']}</div><div class='item-detail'>Time: {v['timestamp']}</div></div>" for v in report.get('violations', [])]) if report.get('violations') else "<div class='clear'>No violations detected in the last 24 hours.</div>"}
                </div>
                
                {'<div class="section"><div class="section-title">🔒 Quarantines</div>' + ''.join([f"<div class='quarantine-item'><div class='item-user'>{q['user']}</div><div class='item-detail'>Reason: {q['reason']}</div><div class='item-detail'>Time: {q['timestamp']}</div></div>" for q in report.get('quarantines', [])]) + "</div>" if report.get('quarantines') else ""}
                
                {'<div class="section"><div class="section-title">🚨 Threat Level Changes</div>' + ''.join([f"<div class='threat-item'><div class='item-user'>{t['level']}</div><div class='item-detail'>Time: {t['timestamp']}</div></div>" for t in report.get('threats', [])]) + "</div>" if report.get('threats') else ""}
                
                <div class="footer">
                    <p><strong>Sentinel Security Bot v2.0</strong></p>
                    <p>This is an automated daily security report sent at 6 AM UTC</p>
                    <p>Next report will be sent in 24 hours</p>
                    <p style="margin-top: 10px; border-top: 1px solid #ddd; padding-top: 10px;">For urgent security issues, check your Discord server immediately</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        subject = f"🛡️ Sentinel Daily Report - {guild_name}"
        
        await send_sentinel_mail(email, subject, text_content, html_content)
        return True
        
    except Exception as e:
        logger.error(f"Error sending violation report: {e}")
        return False

# ============= COMMANDS =============

@bot.tree.command(name="daily_reports_enable", description="Enable daily violation reports via email")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def daily_reports_enable(interaction: discord.Interaction):
    """Enable daily reports"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'daily_reports_enabled', True)
        
        if interaction.guild.id not in server_configs:
            server_configs[interaction.guild.id] = {}
        server_configs[interaction.guild.id]['daily_reports_enabled'] = True
        
        embed = discord.Embed(
            title="✅ Daily Reports Enabled",
            description="Admins will receive daily violation reports at 6 AM UTC",
            color=discord.Color.green()
        )
        embed.add_field(name="Email Alerts", value="Enabled for all administrators", inline=False)
        embed.add_field(name="Schedule", value="Daily at 6 AM UTC", inline=True)
        embed.add_field(name="Includes", value="Violations, Quarantines, Threat Changes", inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'config',
            'Daily Reports Enabled',
            interaction.user,
            "Admins will receive daily violation reports"
        )
        
    except Exception as e:
        logger.error(f"Error enabling daily reports: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="daily_reports_disable", description="Disable daily violation reports")
@app_commands.checks.has_permissions(administrator=True)
@rate_limit(max_calls=3, window=300)
async def daily_reports_disable(interaction: discord.Interaction):
    """Disable daily reports"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        await db.update_server_field(interaction.guild.id, 'daily_reports_enabled', False)
        
        if interaction.guild.id in server_configs:
            server_configs[interaction.guild.id]['daily_reports_enabled'] = False
        
        embed = discord.Embed(
            title="✅ Daily Reports Disabled",
            description="Daily violation reports are now disabled",
            color=discord.Color.green()
        )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
        await log_action(
            interaction.guild,
            'config',
            'Daily Reports Disabled',
            interaction.user,
            "Daily violation reports disabled"
        )
        
    except Exception as e:
        logger.error(f"Error disabling daily reports: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

@bot.tree.command(name="daily_reports_status", description="Check daily reports status")
@rate_limit(max_calls=5, window=60)
async def daily_reports_status(interaction: discord.Interaction):
    """Check daily reports status"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        config = server_configs.get(interaction.guild.id, {})
        enabled = config.get('daily_reports_enabled', False)
        
        embed = discord.Embed(
            title="📊 Daily Reports Status",
            color=discord.Color.blue()
        )
        
        embed.add_field(
            name="Status",
            value="✅ Enabled" if enabled else "❌ Disabled",
            inline=True
        )
        
        if enabled:
            embed.add_field(name="Schedule", value="Daily at 6 AM UTC", inline=True)
            embed.add_field(name="Recipients", value="All administrators with email configured", inline=False)
            embed.add_field(
                name="Includes",
                value="• Shift violations\n• Quarantine incidents\n• Threat level changes",
                inline=False
            )
        else:
            embed.add_field(
                name="Next Steps",
                value="Use `/daily_reports_enable` to start receiving daily reports",
                inline=False
            )
        
        await interaction.followup.send(embed=embed, ephemeral=True)
        
    except Exception as e:
        logger.error(f"Error checking daily reports: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= BOT START =============

if __name__ == "__main__":
    try:
        logger.info("🚀 STARTING SENTINEL SECURITY BOT v2.0 - COMPLETE")
        bot.run(TOKEN)
    except KeyboardInterrupt:
        logger.info("⛔ Bot stopped by user")
    except Exception as e:
        logger.critical(f"❌ Critical error: {e}")
