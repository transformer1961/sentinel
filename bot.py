import discord
from discord.ext import commands
from discord import app_commands
import os
from dotenv import load_dotenv
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
import json
import logging
import aiohttp
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import custom database module
import database as db

# ============= LOGGING SETUP =============
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecurityBot')

# ============= CONFIGURATION =============
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
SENTINEL_EMAIL = os.getenv('SENTINEL_EMAIL')
SENTINEL_EMAIL_PASS = os.getenv('SENTINEL_EMAIL_PASS')

# Bot setup with required intents
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

# ============= CONSTANTS =============
MAX_PARTNERSHIPS_DISPLAY = 10
VERIFICATION_CODE_LENGTH = 8
VERIFICATION_TIMEOUT = 300  # 5 minutes

# Default security thresholds (configurable per server)
DEFAULT_THRESHOLDS = {
    'channel_delete': {'count': 3, 'seconds': 10},
    'channel_create': {'count': 5, 'seconds': 10},
    'role_delete': {'count': 3, 'seconds': 10},
    'role_update': {'count': 10, 'seconds': 30},
    'member_ban': {'count': 5, 'seconds': 30},
    'member_kick': {'count': 5, 'seconds': 30},
    'mass_join': {'count': 10, 'seconds': 60},
    'message_delete': {'count': 10, 'seconds': 5}
}

# Threat level definitions
THREAT_LEVELS = {
    0: {"name": "🟢 Clear", "color": discord.Color.green(), "description": "Normal operations"},
    1: {"name": "🟡 Elevated", "color": discord.Color.gold(), "description": "Minor threat detected"},
    2: {"name": "🟠 High", "color": discord.Color.orange(), "description": "Serious threat - Lockdown engaged"},
    3: {"name": "🔴 Alpha", "color": discord.Color.red(), "description": "FULL SECURITY BREACH"}
}

# ============= IN-MEMORY STORAGE =============
server_configs = {}
whitelists = defaultdict(set)
action_tracker = defaultdict(lambda: defaultdict(list))
join_tracker = defaultdict(list)

# ============= EMAIL FUNCTIONS =============

async def send_sentinel_mail(to: str, subject: str, text: str, html: str = None):
    """Send email notification from Sentinel Security Bot"""
    if not SENTINEL_EMAIL or not SENTINEL_EMAIL_PASS:
        logger.warning("Email credentials not configured. Skipping email notification.")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f"Sentinel Security Bot <{SENTINEL_EMAIL}>"
        msg['To'] = to
        msg['Subject'] = subject
        
        text_part = MIMEText(text, 'plain')
        msg.attach(text_part)
        
        if html:
            html_part = MIMEText(html, 'html')
            msg.attach(html_part)
        
        await asyncio.to_thread(_send_email_sync, msg, to)
        logger.info(f"Email sent successfully to {to}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email to {to}: {e}")
        return False

def _send_email_sync(msg, to):
    """Synchronous email sending (run in thread)"""
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(SENTINEL_EMAIL, SENTINEL_EMAIL_PASS)
        server.send_message(msg)

# ============= HELPER FUNCTIONS =============

async def is_whitelisted(guild_id: int, user_id: int) -> bool:
    """Check if user is whitelisted"""
    if user_id in whitelists.get(guild_id, set()):
        return True
    return await db.is_whitelisted(guild_id, user_id)

def track_action(guild_id: int, user_id: int, action_type: str) -> int:
    """Track user actions and return count within threshold window"""
    now = datetime.now()
    action_tracker[guild_id][(user_id, action_type)].append(now)
    
    threshold = DEFAULT_THRESHOLDS.get(action_type, {'seconds': 60})
    cutoff = now - timedelta(seconds=threshold['seconds'])
    action_tracker[guild_id][(user_id, action_type)] = [
        t for t in action_tracker[guild_id][(user_id, action_type)] if t > cutoff
    ]
    
    return len(action_tracker[guild_id][(user_id, action_type)])

async def send_alert(guild: discord.Guild, message: str, user: discord.User = None, 
                     color: discord.Color = discord.Color.red(), email_admins: bool = False):
    """Send security alert to log channel, whitelisted admins, and optionally email"""
    config = server_configs.get(guild.id, {})
    log_channel_id = config.get('log_channel_id')
    
    embed = discord.Embed(
        title="🚨 Security Alert",
        description=message,
        color=color,
        timestamp=datetime.now()
    )
    
    if user:
        embed.add_field(name="User", value=f"{user.mention} ({user.id})", inline=False)
    
    embed.add_field(name="Server", value=guild.name, inline=True)
    embed.add_field(name="Time", value=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), inline=True)
    
    await db.add_log(
        guild.id,
        'security_alert',
        user.id if user else None,
        details={'message': message}
    )
    
    if log_channel_id:
        channel = guild.get_channel(log_channel_id)
        if channel:
            try:
                await channel.send(embed=embed)
            except Exception as e:
                logger.error(f"Failed to send alert to log channel: {e}")
    
    admin_emails = []
    for member in guild.members:
        if member.guild_permissions.administrator and await is_whitelisted(guild.id, member.id):
            try:
                await member.send(embed=embed)
            except Exception as e:
                logger.debug(f"Could not DM {member.name}: {e}")
            
            if email_admins:
                admin_email = await db.get_user_email(guild.id, member.id)
                if admin_email:
                    admin_emails.append(admin_email)
    
    if email_admins and admin_emails:
        email_subject = f"🚨 Security Alert: {guild.name}"
        email_text = f"""
Sentinel Security Bot Alert

Server: {guild.name}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{message}

{'User: ' + user.name + ' (' + str(user.id) + ')' if user else 'System Alert'}

Please check your Discord server immediately.

---
This is an automated message from Sentinel Security Bot.
        """
        
        email_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #e74c3c;">🚨 Security Alert</h2>
            <p><strong>Server:</strong> {guild.name}</p>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <hr>
            <p>{message.replace(chr(10), '<br>')}</p>
            <p><strong>User:</strong> {user.name if user else 'System Alert'} {f'({user.id})' if user else ''}</p>
            <hr>
            <p style="color: #7f8c8d; font-size: 12px;">
                This is an automated message from Sentinel Security Bot.<br>
                Please check your Discord server immediately.
            </p>
        </body>
        </html>
        """
        
        for email in admin_emails:
            await send_sentinel_mail(email, email_subject, email_text, email_html)

async def log_action(guild: discord.Guild, category: str, title: str, user: discord.User, 
                     description: str, extra_info: dict = None):
    """Log an action to the log channel and database"""
    config = server_configs.get(guild.id, {})
    log_channel_id = config.get('log_channel_id')
    
    embed = discord.Embed(
        title=f"📋 {title}",
        description=description,
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Category", value=category.title(), inline=True)
    embed.add_field(name="User", value=user.mention if user else "System", inline=True)
    
    if extra_info:
        for key, value in extra_info.items():
            embed.add_field(name=key, value=str(value), inline=True)
    
    await db.add_log(
        guild.id,
        category,
        user.id if user else None,
        details={'title': title, 'description': description, **(extra_info or {})}
    )
    
    if log_channel_id:
        channel = guild.get_channel(log_channel_id)
        if channel:
            try:
                await channel.send(embed=embed)
            except Exception as e:
                logger.error(f"Failed to send log: {e}")

async def quarantine_user(guild: discord.Guild, user: discord.User, reason: str) -> bool:
    """Quarantine a user by removing all roles and adding quarantine role"""
    config = server_configs.get(guild.id, {})
    quarantine_role_id = config.get('quarantine_role_id')
    
    if not quarantine_role_id:
        await send_alert(guild, f"⚠️ Cannot quarantine {user.mention}: Quarantine role not set up!", user)
        return False
    
    quarantine_role = guild.get_role(quarantine_role_id)
    if not quarantine_role:
        await send_alert(guild, f"⚠️ Cannot quarantine {user.mention}: Quarantine role not found!", user)
        return False
    
    member = guild.get_member(user.id)
    if not member:
        return False
    
    try:
        removed_roles = [role.id for role in member.roles if role != guild.default_role]
        await db.store_quarantine_roles(guild.id, user.id, removed_roles)
        
        roles_to_remove = [role for role in member.roles if role != guild.default_role]
        if roles_to_remove:
            await member.remove_roles(*roles_to_remove, reason=f"Quarantined: {reason}")
        
        await member.add_roles(quarantine_role, reason=f"Quarantined: {reason}")
        
        await send_alert(guild, f"✅ Quarantined {user.mention}\nReason: {reason}", user, email_admins=True)
        
        try:
            await member.send(
                f"⚠️ You have been quarantined in **{guild.name}**\n"
                f"**Reason:** {reason}\n"
                f"Please contact a server administrator for assistance."
            )
        except:
            pass
        
        return True
    except Exception as e:
        logger.error(f"Failed to quarantine user {user.id}: {e}")
        await send_alert(guild, f"❌ Failed to quarantine {user.mention}: {str(e)}", user)
        return False

def generate_verification_code():
    """Generate a random verification code"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=VERIFICATION_CODE_LENGTH))

async def get_roblox_user_info(username: str):
    """Get Roblox user info from username"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'https://users.roblox.com/v1/usernames/users',
                json={'usernames': [username], 'excludeBannedUsers': True}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('data') and len(data['data']) > 0:
                        user_data = data['data'][0]
                        user_id = user_data['id']
                        
                        async with session.get(f'https://users.roblox.com/v1/users/{user_id}') as profile_resp:
                            if profile_resp.status == 200:
                                profile_data = await profile_resp.json()
                                return {
                                    'id': user_id,
                                    'username': user_data['name'],
                                    'displayName': user_data['displayName'],
                                    'description': profile_data.get('description', '')
                                }
        return None
    except Exception as e:
        logger.error(f'Error fetching Roblox user: {e}')
        return None

# ============= BOT EVENTS =============

@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    logger.info(f'Bot is in {len(bot.guilds)} servers')
    logger.info(f'Bot ID: {bot.user.id}')
    
    await db.init_database()
    
    global server_configs, whitelists
    server_configs = await db.load_all_configs()
    whitelists = await db.load_all_whitelists()
    logger.info(f'✅ Loaded {len(server_configs)} server configs and {len(whitelists)} whitelists')
    
    bot.add_view(VerificationView())
    bot.add_view(RobloxVerificationView())
    
    try:
        synced = await bot.tree.sync()
        logger.info(f'Synced {len(synced)} command(s)')
    except Exception as e:
        logger.error(f'Error syncing commands: {e}')
    
    logger.info('🔍 Bot is now monitoring events...')

@bot.event
async def on_guild_channel_delete(channel):
    """Monitor channel deletions"""
    await asyncio.sleep(1)
    
    guild = channel.guild
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
            if entry.target.id == channel.id:
                user = entry.user
                
                if user.bot or await is_whitelisted(guild.id, user.id):
                    return
                
                count = track_action(guild.id, user.id, 'channel_delete')
                threshold = DEFAULT_THRESHOLDS['channel_delete']
                
                logger.info(f"Channel deleted by {user.name}: {count}/{threshold['count']}")
                
                if count >= threshold['count']:
                    await send_alert(guild,
                        f"⚠️ **CHANNEL DELETE THRESHOLD BREACHED**\n"
                        f"{user.mention} deleted {count} channels in {threshold['seconds']} seconds!",
                        user,
                        email_admins=True)
                    await quarantine_user(guild, user, f"Mass channel deletion ({count} channels)")
    except Exception as e:
        logger.error(f"Error in on_guild_channel_delete: {e}")

@bot.event
async def on_guild_channel_create(channel):
    """Monitor channel creations"""
    await asyncio.sleep(1)
    
    guild = channel.guild
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_create):
            if entry.target.id == channel.id:
                user = entry.user
                
                if user.bot or await is_whitelisted(guild.id, user.id):
                    return
                
                count = track_action(guild.id, user.id, 'channel_create')
                threshold = DEFAULT_THRESHOLDS['channel_create']
                
                logger.info(f"Channel created by {user.name}: {count}/{threshold['count']}")
                
                if count >= threshold['count']:
                    await send_alert(guild,
                        f"⚠️ **CHANNEL CREATE THRESHOLD BREACHED**\n"
                        f"{user.mention} created {count} channels in {threshold['seconds']} seconds!",
                        user,
                        email_admins=True)
                    await quarantine_user(guild, user, f"Mass channel creation ({count} channels)")
    except Exception as e:
        logger.error(f"Error in on_guild_channel_create: {e}")

@bot.event
async def on_guild_role_delete(role):
    """Monitor role deletions"""
    await asyncio.sleep(1)
    
    guild = role.guild
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
            if entry.target.id == role.id:
                user = entry.user
                
                if user.bot or await is_whitelisted(guild.id, user.id):
                    return
                
                count = track_action(guild.id, user.id, 'role_delete')
                threshold = DEFAULT_THRESHOLDS['role_delete']
                
                if count >= threshold['count']:
                    await send_alert(guild,
                        f"⚠️ **ROLE DELETE THRESHOLD BREACHED**\n"
                        f"{user.mention} deleted {count} roles in {threshold['seconds']} seconds!",
                        user,
                        email_admins=True)
                    await quarantine_user(guild, user, f"Mass role deletion ({count} roles)")
    except Exception as e:
        logger.error(f"Error in on_guild_role_delete: {e}")

@bot.event
async def on_guild_role_update(role_before, role_after):
    """Monitor role updates (especially permission changes)"""
    await asyncio.sleep(1)
    
    guild = role_after.guild
    
    try:
        dangerous_perms = [
            'administrator', 'manage_guild', 'manage_roles', 
            'manage_channels', 'ban_members', 'kick_members'
        ]
        
        perms_added = []
        for perm in dangerous_perms:
            if not getattr(role_before.permissions, perm) and getattr(role_after.permissions, perm):
                perms_added.append(perm)
        
        if perms_added:
            async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.role_update):
                if entry.target.id == role_after.id:
                    user = entry.user
                    
                    if user.bot or await is_whitelisted(guild.id, user.id):
                        return
                    
                    count = track_action(guild.id, user.id, 'role_update')
                    threshold = DEFAULT_THRESHOLDS['role_update']
                    
                    logger.warning(f"Dangerous permissions added to role {role_after.name} by {user.name}")
                    
                    if count >= threshold['count']:
                        await send_alert(guild,
                            f"⚠️ **SUSPICIOUS ROLE MODIFICATIONS**\n"
                            f"{user.mention} modified {count} roles in {threshold['seconds']} seconds!\n"
                            f"Dangerous permissions added: {', '.join(perms_added)}",
                            user,
                            color=discord.Color.orange(),
                            email_admins=True)
    except Exception as e:
        logger.error(f"Error in on_guild_role_update: {e}")

@bot.event
async def on_member_ban(guild, user):
    """Monitor member bans"""
    await asyncio.sleep(1)
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
            if entry.target.id == user.id:
                banner = entry.user
                
                if banner.bot or await is_whitelisted(guild.id, banner.id):
                    return
                
                count = track_action(guild.id, banner.id, 'member_ban')
                threshold = DEFAULT_THRESHOLDS['member_ban']
                
                if count >= threshold['count']:
                    await send_alert(guild,
                        f"⚠️ **MASS BAN THRESHOLD BREACHED**\n"
                        f"{banner.mention} banned {count} members in {threshold['seconds']} seconds!",
                        banner,
                        email_admins=True)
                    await quarantine_user(guild, banner, f"Mass member banning ({count} bans)")
    except Exception as e:
        logger.error(f"Error in on_member_ban: {e}")

@bot.event
async def on_member_remove(member):
    """Monitor member kicks/leaves"""
    await asyncio.sleep(1)
    
    guild = member.guild
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.kick):
            if entry.target.id == member.id:
                kicker = entry.user
                
                if kicker.bot or await is_whitelisted(guild.id, kicker.id):
                    return
                
                count = track_action(guild.id, kicker.id, 'member_kick')
                threshold = DEFAULT_THRESHOLDS['member_kick']
                
                if count >= threshold['count']:
                    await send_alert(guild,
                        f"⚠️ **MASS KICK THRESHOLD BREACHED**\n"
                        f"{kicker.mention} kicked {count} members in {threshold['seconds']} seconds!",
                        kicker,
                        email_admins=True)
                    await quarantine_user(guild, kicker, f"Mass member kicking ({count} kicks)")
                return
    except Exception as e:
        logger.error(f"Error checking for kick: {e}")
    
    await db.add_log(
        guild.id,
        'member_leave',
        member.id,
        details={'member_name': member.name, 'member_id': member.id}
    )

@bot.event
async def on_member_join(member):
    """Handle new member joins - verification and raid detection"""
    guild = member.guild
    config = server_configs.get(guild.id, {})
    
    if config.get('verification_enabled'):
        unverified_role_id = config.get('unverified_role_id')
        if unverified_role_id:
            unverified_role = guild.get_role(unverified_role_id)
            if unverified_role:
                try:
                    await member.add_roles(unverified_role, reason="New member - needs verification")
                    
                    verification_channel_id = config.get('verification_channel_id')
                    if verification_channel_id:
                        channel = guild.get_channel(verification_channel_id)
                        try:
                            await member.send(
                                f"Welcome to **{guild.name}**! 🎉\n\n"
                                f"Please verify yourself in {channel.mention} to gain access to the server."
                            )
                        except:
                            pass
                except Exception as e:
                    logger.error(f"Failed to apply unverified role to {member.id}: {e}")
    
    now = datetime.now()
    join_tracker[guild.id].append(now)
    
    cutoff = now - timedelta(seconds=DEFAULT_THRESHOLDS['mass_join']['seconds'])
    join_tracker[guild.id] = [t for t in join_tracker[guild.id] if t > cutoff]
    
    count = len(join_tracker[guild.id])
    threshold = DEFAULT_THRESHOLDS['mass_join']
    
    if count >= threshold['count']:
        await send_alert(guild,
            f"⚠️ **POSSIBLE RAID DETECTED**\n"
            f"{count} accounts joined in {threshold['seconds']} seconds!\n"
            f"Consider enabling verification or lockdown.",
            color=discord.Color.orange(),
            email_admins=True)
        
        await db.add_log(
            guild.id,
            'mass_join_detected',
            None,
            details={'count': count, 'time_window': threshold['seconds']}
        )

@bot.event
async def on_message_delete(message):
    """Monitor mass message deletions"""
    if message.author.bot:
        return
    
    guild = message.guild
    if not guild:
        return
    
    await asyncio.sleep(1)
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.message_delete):
            if entry.target.id == message.author.id:
                deleter = entry.user
                
                if deleter.bot or await is_whitelisted(guild.id, deleter.id):
                    return
                
                count = track_action(guild.id, deleter.id, 'message_delete')
                threshold = DEFAULT_THRESHOLDS['message_delete']
                
                if count >= threshold['count']:
                    await send_alert(guild,
                        f"⚠️ **MASS MESSAGE DELETE DETECTED**\n"
                        f"{deleter.mention} deleted {count} messages in {threshold['seconds']} seconds!",
                        deleter,
                        color=discord.Color.orange())
    except Exception as e:
        logger.error(f"Error in on_message_delete: {e}")

@bot.event
async def on_bulk_message_delete(messages):
    """Monitor bulk message deletions (purges)"""
    if not messages:
        return
    
    guild = messages[0].guild
    if not guild:
        return
    
    await asyncio.sleep(1)
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.message_bulk_delete):
            user = entry.user
            
            if user.bot or await is_whitelisted(guild.id, user.id):
                return
            
            await send_alert(guild,
                f"⚠️ **BULK MESSAGE DELETE DETECTED**\n"
                f"{user.mention} deleted {len(messages)} messages in bulk!\n"
                f"Channel: {messages[0].channel.mention}",
                user,
                color=discord.Color.orange())
    except Exception as e:
        logger.error(f"Error in on_bulk_message_delete: {e}")

@bot.event
async def on_guild_update(before, after):
    """Monitor server settings changes"""
    await asyncio.sleep(1)
    
    try:
        critical_changes = []
        
        if before.name != after.name:
            critical_changes.append(f"Server name changed: {before.name} → {after.name}")
        
        if before.icon != after.icon:
            critical_changes.append("Server icon changed")
        
        if before.verification_level != after.verification_level:
            critical_changes.append(f"Verification level: {before.verification_level} → {after.verification_level}")
        
        if critical_changes:
            async for entry in after.audit_logs(limit=1, action=discord.AuditLogAction.guild_update):
                user = entry.user
                
                if user.bot or await is_whitelisted(after.id, user.id):
                    return
                
                await send_alert(after,
                    f"⚠️ **SERVER SETTINGS MODIFIED**\n"
                    f"{user.mention} made the following changes:\n" + "\n".join(f"• {change}" for change in critical_changes),
                    user,
                    color=discord.Color.blue())
    except Exception as e:
        logger.error(f"Error in on_guild_update: {e}")

@bot.event
async def on_webhooks_update(channel):
    """Monitor webhook creations/modifications"""
    await asyncio.sleep(1)
    
    guild = channel.guild
    
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.webhook_create):
            user = entry.user
            
            if user.bot or await is_whitelisted(guild.id, user.id):
                return
            
            await send_alert(guild,
                f"⚠️ **WEBHOOK CREATED**\n"
                f"{user.mention} created a webhook in {channel.mention}\n"
                f"Webhook: {entry.target.name if entry.target else 'Unknown'}",
                user,
                color=discord.Color.gold())
    except Exception as e:
        logger.error(f"Error in on_webhooks_update: {e}")

# ============= SETUP COMMANDS =============

# FIXES FOR bot.py - Add these to replace existing commands

# ============= FIX 1: SETUP COMMAND =============

@bot.tree.command(name="setup", description="Initial bot setup wizard")
@app_commands.checks.has_permissions(administrator=True)
async def setup(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)  # ADD THIS LINE
    
    embed = discord.Embed(
        title="🛡️ Security Bot Setup",
        description="Let's set up your server protection!",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="Step 1: Set Log Channel",
        value="`/set_log_channel #channel` - Where alerts are sent",
        inline=False
    )
    
    embed.add_field(
        name="Step 2: Create Quarantine Role",
        value="`/create_quarantine_role` - Role for restricted users",
        inline=False
    )
    
    embed.add_field(
        name="Step 3: Whitelist Trusted Users",
        value="`/whitelist_add @user` - Exempt from monitoring",
        inline=False
    )
    
    embed.add_field(
        name="Optional: Email Notifications",
        value="`/set_admin_email your@email.com` - Receive alerts via email",
        inline=False
    )
    
    embed.add_field(
        name="Optional: Verification",
        value="`/setup_verification #channel` - New member verification\n`/setup_roblox_verification #channel` - Roblox account verification",
        inline=False
    )
    
    embed.add_field(
        name="Optional: Threat Roles",
        value="`/set_onduty_role @role` - For elevated threats\n`/set_allstaff_role @role` - For Alpha threats",
        inline=False
    )
    
    embed.add_field(
        name="Optional: Partnership System",
        value="`/set_partnership_channel #channel` - Server partnerships",
        inline=False
    )
    
    await interaction.followup.send(embed=embed, ephemeral=True)  # CHANGE THIS LINE


@bot.tree.command(name="create_quarantine_role", description="Create a quarantine role")
@app_commands.checks.has_permissions(administrator=True)
async def create_quarantine_role(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    role = await guild.create_role(
        name="Quarantined",
        color=discord.Color.dark_grey(),
        permissions=discord.Permissions.none(),
        reason="Security bot quarantine role"
    )
    
    for channel in guild.channels:
        try:
            await channel.set_permissions(role, 
                read_messages=True if isinstance(channel, discord.TextChannel) else False,
                send_messages=False,
                add_reactions=False,
                connect=False if isinstance(channel, discord.VoiceChannel) else None,
                speak=False if isinstance(channel, discord.VoiceChannel) else None
            )
        except:
            pass
    
    await db.update_server_field(guild.id, 'quarantine_role_id', role.id)
    
    if guild.id not in server_configs:
        server_configs[guild.id] = {}
    server_configs[guild.id]['quarantine_role_id'] = role.id
    
    await interaction.followup.send(
        f"✅ Quarantine role created: {role.mention}\n"
        f"⚠️ Make sure this role is below the bot's role in the role hierarchy!",
        ephemeral=True
    )

@bot.tree.command(name="set_admin_email", description="Set your email for security alerts")
@app_commands.checks.has_permissions(administrator=True)
async def set_admin_email(interaction: discord.Interaction, email: str):
    """Set admin email for notifications"""
    if '@' not in email or '.' not in email:
        await interaction.response.send_message(
            "❌ Invalid email format. Please provide a valid email address.",
            ephemeral=True
        )
        return
    
    await db.set_user_email(interaction.guild.id, interaction.user.id, email)
    
    await interaction.response.send_message(
        f"✅ Your email has been set to: `{email}`\n"
        f"You will now receive critical security alerts via email.",
        ephemeral=True
    )
    
    try:
        await send_sentinel_mail(
            email,
            f"✅ Sentinel Bot Email Configured: {interaction.guild.name}",
            f"""
Hello {interaction.user.name},

Your email has been successfully configured to receive security alerts from Sentinel Security Bot.

Server: {interaction.guild.name}
Your Discord ID: {interaction.user.id}

You will receive notifications for:
- Critical security breaches
- Mass actions (channel/role deletion, mass bans)
- Threat level changes
- Quarantine actions

To disable email notifications, use /remove_admin_email

---
Sentinel Security Bot
            """,
            f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #27ae60;">✅ Email Configured Successfully</h2>
                <p>Hello <strong>{interaction.user.name}</strong>,</p>
                <p>Your email has been successfully configured to receive security alerts from <strong>Sentinel Security Bot</strong>.</p>
                
                <hr>
                <p><strong>Server:</strong> {interaction.guild.name}</p>
                <p><strong>Your Discord ID:</strong> {interaction.user.id}</p>
                
                <h3>You will receive notifications for:</h3>
                <ul>
                    <li>Critical security breaches</li>
                    <li>Mass actions (channel/role deletion, mass bans)</li>
                    <li>Threat level changes</li>
                    <li>Quarantine actions</li>
                </ul>
                
                <p style="color: #7f8c8d; font-size: 12px;">
                    To disable email notifications, use <code>/remove_admin_email</code>
                </p>
                
                <hr>
                <p style="color: #7f8c8d; font-size: 12px;">Sentinel Security Bot</p>
            </body>
            </html>
            """
        )
    except Exception as e:
        logger.error(f"Failed to send test email: {e}")

@bot.tree.command(name="remove_admin_email", description="Remove your email from notifications")
@app_commands.checks.has_permissions(administrator=True)
async def remove_admin_email(interaction: discord.Interaction):
    """Remove admin email"""
    removed = await db.remove_user_email(interaction.guild.id, interaction.user.id)
    
    if removed:
        await interaction.response.send_message(
            "✅ Your email has been removed from notifications.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            "❌ No email found for your account.",
            ephemeral=True
        )

# ============= WHITELIST COMMANDS =============

@bot.tree.command(name="whitelist_add", description="Add user to whitelist")
@app_commands.checks.has_permissions(administrator=True)
async def whitelist_add(interaction: discord.Interaction, user: discord.User):
    await interaction.response.defer(ephemeral=True)  # ADD THIS LINE
    
    await db.add_to_whitelist(interaction.guild.id, user.id, 'user', interaction.user.id)
    
    if interaction.guild.id not in whitelists:
        whitelists[interaction.guild.id] = set()
    whitelists[interaction.guild.id].add(user.id)
    
    await log_action(interaction.guild, 'whitelist', 'User Whitelisted',
                    interaction.user, f"{user.mention} added to whitelist",
                    extra_info={'Target User': user.name})
    
    await interaction.followup.send(  # CHANGE TO followup
        f"✅ Added {user.mention} to whitelist - they are now exempt from security monitoring",
        ephemeral=True
    )

@bot.tree.command(name="whitelist_remove", description="Remove user from whitelist")
@app_commands.checks.has_permissions(administrator=True)
async def whitelist_remove(interaction: discord.Interaction, user: discord.User):
    removed = await db.remove_from_whitelist(interaction.guild.id, user.id)
    
    if user.id in whitelists.get(interaction.guild.id, set()):
        whitelists[interaction.guild.id].remove(user.id)
    
    if removed:
        await log_action(interaction.guild, 'whitelist', 'User Removed from Whitelist',
                        interaction.user, f"{user.mention} removed from whitelist",
                        extra_info={'Target User': user.name})
        
        await interaction.response.send_message(
            f"✅ Removed {user.mention} from whitelist",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"❌ {user.mention} is not whitelisted",
            ephemeral=True
        )

@bot.tree.command(name="whitelist_list", description="Show all whitelisted users")
@app_commands.checks.has_permissions(administrator=True)
async def whitelist_list(interaction: discord.Interaction):
    guild_whitelist = whitelists.get(interaction.guild.id, set())
    
    if not guild_whitelist:
        await interaction.response.send_message("No users whitelisted", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="✅ Whitelisted Users",
        description="These users are exempt from security monitoring:",
        color=discord.Color.green()
    )
    
    users = []
    for user_id in guild_whitelist:
        user = bot.get_user(user_id)
        users.append(f"• {user.mention if user else f'User ID: {user_id}'}")
    
    embed.description += "\n\n" + "\n".join(users)
    embed.set_footer(text=f"Total: {len(guild_whitelist)} user(s)")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ============= QUARANTINE COMMANDS =============

@bot.tree.command(name="quarantine", description="Manually quarantine a user")
@app_commands.checks.has_permissions(administrator=True)
async def quarantine_cmd(interaction: discord.Interaction, user: discord.Member, reason: str = "Manual quarantine"):
    await interaction.response.defer(ephemeral=True)
    
    success = await quarantine_user(interaction.guild, user, reason)
    
    if success:
        await interaction.followup.send(f"✅ Quarantined {user.mention}", ephemeral=True)
    else:
        await interaction.followup.send(f"❌ Failed to quarantine {user.mention}", ephemeral=True)

@bot.tree.command(name="unquarantine", description="Remove quarantine from a user")
@app_commands.checks.has_permissions(administrator=True)
async def unquarantine_cmd(interaction: discord.Interaction, user: discord.Member):
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id, {})
    quarantine_role_id = config.get('quarantine_role_id')
    
    if not quarantine_role_id:
        await interaction.followup.send("❌ Quarantine role not set up!", ephemeral=True)
        return
    
    quarantine_role = interaction.guild.get_role(quarantine_role_id)
    if not quarantine_role or quarantine_role not in user.roles:
        await interaction.followup.send(f"❌ {user.mention} is not quarantined!", ephemeral=True)
        return
    
    try:
        await user.remove_roles(quarantine_role, reason=f"Unquarantined by {interaction.user.name}")
        
        stored_roles = await db.get_quarantine_roles(interaction.guild.id, user.id)
        if stored_roles:
            roles_to_restore = [interaction.guild.get_role(rid) for rid in stored_roles]
            roles_to_restore = [r for r in roles_to_restore if r]
            if roles_to_restore:
                await user.add_roles(*roles_to_restore, reason="Roles restored after unquarantine")
        
        await send_alert(
            interaction.guild,
            f"✅ {user.mention} was unquarantined by {interaction.user.mention}",
            user,
            color=discord.Color.green()
        )
        
        await interaction.followup.send(f"✅ Removed quarantine from {user.mention}", ephemeral=True)
    except Exception as e:
        logger.error(f"Failed to unquarantine user: {e}")
        await interaction.followup.send(f"❌ Failed to unquarantine: {str(e)}", ephemeral=True)

@bot.tree.command(name="quarantine_list", description="List all quarantined users")
@app_commands.checks.has_permissions(administrator=True)
async def quarantine_list(interaction: discord.Interaction):
    """Show all quarantined users"""
    config = server_configs.get(interaction.guild.id, {})
    quarantine_role_id = config.get('quarantine_role_id')
    
    if not quarantine_role_id:
        await interaction.response.send_message("❌ Quarantine role not set up!", ephemeral=True)
        return
    
    quarantine_role = interaction.guild.get_role(quarantine_role_id)
    if not quarantine_role:
        await interaction.response.send_message("❌ Quarantine role not found!", ephemeral=True)
        return
    
    quarantined_members = [member for member in interaction.guild.members if quarantine_role in member.roles]
    
    if not quarantined_members:
        await interaction.response.send_message("✅ No users are currently quarantined.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="🔒 Quarantined Users",
        color=discord.Color.dark_grey()
    )
    
    users_list = "\n".join([f"• {member.mention} ({member.name})" for member in quarantined_members])
    embed.description = users_list
    embed.set_footer(text=f"Total: {len(quarantined_members)} user(s)")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ============= LOCKDOWN COMMANDS =============

@bot.tree.command(name="lockdown_enable", description="Lock down the server (emergency mode)")
@app_commands.checks.has_permissions(administrator=True)
async def lockdown_enable(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    try:
        for channel in guild.text_channels:
            await channel.set_permissions(
                guild.default_role,
                send_messages=False,
                add_reactions=False,
                create_instant_invite=False
            )
        
        await db.update_server_field(guild.id, 'lockdown_enabled', True)
        if guild.id not in server_configs:
            server_configs[guild.id] = {}
        server_configs[guild.id]['lockdown_enabled'] = True
        
        await send_alert(
            guild,
            f"🔒 **SERVER LOCKDOWN ACTIVATED**\n"
            f"Initiated by {interaction.user.mention}\n"
            f"All members restricted from sending messages and reacting.",
            color=discord.Color.orange(),
            email_admins=True
        )
        
        await interaction.followup.send(
            "🔒 Server is now in lockdown mode!\n"
            "• Members cannot send messages\n"
            "• Members cannot add reactions\n"
            "• Members cannot create invites\n\n"
            "Use `/lockdown_disable` to lift the lockdown.",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Failed to enable lockdown: {e}")
        await interaction.followup.send(f"❌ Failed to enable lockdown: {str(e)}", ephemeral=True)

@bot.tree.command(name="lockdown_disable", description="Disable server lockdown")
@app_commands.checks.has_permissions(administrator=True)
async def lockdown_disable(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    try:
        for channel in guild.text_channels:
            await channel.set_permissions(
                guild.default_role,
                send_messages=None,
                add_reactions=None,
                create_instant_invite=None
            )
        
        await db.update_server_field(guild.id, 'lockdown_enabled', False)
        if guild.id in server_configs:
            server_configs[guild.id]['lockdown_enabled'] = False
        
        await log_action(guild, 'security', 'Lockdown Disabled', interaction.user,
                        "Server lockdown lifted - Normal permissions restored")
        
        await interaction.followup.send(
            "🔓 Server lockdown has been lifted!\nNormal permissions restored.",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Failed to disable lockdown: {e}")
        await interaction.followup.send(f"❌ Failed to disable lockdown: {str(e)}", ephemeral=True)

# ============= STATUS COMMAND =============

@bot.tree.command(name="status", description="Show bot protection status")
async def status(interaction: discord.Interaction):
    config = server_configs.get(interaction.guild.id, {})
    
    embed = discord.Embed(
        title="🛡️ Security Bot Status",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    log_channel = "✅ Configured" if config.get('log_channel_id') else "❌ Not Set"
    quarantine_role = "✅ Configured" if config.get('quarantine_role_id') else "❌ Not Set"
    verification = "✅ Enabled" if config.get('verification_enabled') else "❌ Disabled"
    lockdown = "🔒 Active" if config.get('lockdown_enabled') else "🔓 Inactive"
    whitelist_count = len(whitelists.get(interaction.guild.id, set()))
    
    embed.add_field(name="Log Channel", value=log_channel, inline=True)
    embed.add_field(name="Quarantine Role", value=quarantine_role, inline=True)
    embed.add_field(name="Verification", value=verification, inline=True)
    embed.add_field(name="Lockdown Status", value=lockdown, inline=True)
    embed.add_field(name="Whitelisted Users", value=str(whitelist_count), inline=True)
    
    try:
        current_threat = await db.get_current_threat_level(interaction.guild.id)
        threat_level = current_threat.get('threat_level', 0)
        threat_info = THREAT_LEVELS.get(threat_level, THREAT_LEVELS[0])
        embed.add_field(name="Threat Level", value=threat_info['name'], inline=True)
    except:
        embed.add_field(name="Threat Level", value="🟢 Clear", inline=True)
    
    user_email = await db.get_user_email(interaction.guild.id, interaction.user.id)
    email_status = "✅ Enabled" if user_email else "❌ Not Set"
    embed.add_field(name="Your Email Alerts", value=email_status, inline=True)
    
    embed.set_footer(text=f"Monitoring {len(interaction.guild.members)} members")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ============= VERIFICATION VIEW CLASSES =============

class VerificationView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(label="Verify", style=discord.ButtonStyle.green, custom_id="verify_button")
    async def verify_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        config = server_configs.get(interaction.guild.id, {})
        verified_role_id = config.get('verified_role_id')
        unverified_role_id = config.get('unverified_role_id')
        
        if not verified_role_id:
            await interaction.response.send_message(
                "❌ Verification system error. Contact an administrator.",
                ephemeral=True
            )
            return
        
        verified_role = interaction.guild.get_role(verified_role_id)
        unverified_role = interaction.guild.get_role(unverified_role_id)
        
        member = interaction.user
        
        if verified_role and verified_role in member.roles:
            await interaction.response.send_message(
                "✅ You are already verified!",
                ephemeral=True
            )
            return
        
        try:
            if verified_role and verified_role not in member.roles:
                await member.add_roles(verified_role, reason="Member verified")
            
            if unverified_role and unverified_role in member.roles:
                await member.remove_roles(unverified_role, reason="Member verified")
            
            await interaction.response.send_message(
                "✅ You have been verified! Welcome to the server!",
                ephemeral=True
            )
            
            await log_action(interaction.guild, 'verification', 'User Verified',
                            member, f"{member.mention} verified via button")
            
            await db.add_log(
                interaction.guild.id,
                'member_verified',
                member.id,
                details={'verification_method': 'button'}
            )
        except Exception as e:
            logger.error(f"Verification error: {e}")
            await interaction.response.send_message(
                "❌ Verification failed. Please contact an administrator.",
                ephemeral=True
            )

class RobloxVerificationView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(label="Start Verification", style=discord.ButtonStyle.green, custom_id="roblox_verify_start")
    async def start_verification(self, interaction: discord.Interaction, button: discord.ui.Button):
        verification = await db.get_verification(interaction.guild.id, interaction.user.id)
        if verification and verification.get('verified'):
            await interaction.response.send_message(
                "✅ You are already verified!",
                ephemeral=True
            )
            return
        
        code = f"VERIFY-{generate_verification_code()}"
        
        await db.create_verification(interaction.guild.id, interaction.user.id, code)
        
        embed = discord.Embed(
            title="🎮 Roblox Verification - Step 1",
            description=(
                f"**Your verification code:** `{code}`\n\n"
                f"**Instructions:**\n"
                f"1. Go to [Roblox Profile Settings](https://www.roblox.com/my/account#!/info)\n"
                f"2. Add this code to your **'About' / 'Description'** section\n"
                f"3. Save your changes\n"
                f"4. Come back here and click 'I've added the code'\n\n"
                f"⏰ This code expires in 5 minutes or if you leave and rejoin."
            ),
            color=discord.Color.blue()
        )
        embed.set_footer(text="Make sure to save your Roblox profile after adding the code!")
        
        view = RobloxVerificationConfirmView()
        await interaction.response.send_message(embed=embed, view=view, ephemeral=True)

class RobloxVerificationConfirmView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=VERIFICATION_TIMEOUT)
    
    @discord.ui.button(label="I've added the code", style=discord.ButtonStyle.green, custom_id="roblox_verify_confirm")
    async def confirm_verification(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer(ephemeral=True)
        
        verification = await db.get_verification(interaction.guild.id, interaction.user.id)
        
        if not verification:
            await interaction.followup.send("❌ No verification in progress. Please start verification first.", ephemeral=True)
            return
        
        if verification.get('verified'):
            await interaction.followup.send("✅ You're already verified!", ephemeral=True)
            return
        
        await interaction.followup.send(
            "Please reply with your **Roblox username** (type it in chat):",
            ephemeral=True
        )
        
        def check(m):
            return m.author == interaction.user and m.channel == interaction.channel
        
        try:
            msg = await bot.wait_for('message', timeout=60.0, check=check)
            roblox_username = msg.content.strip()
            
            try:
                await msg.delete()
            except:
                pass
            
            await interaction.followup.send("🔍 Checking your Roblox profile...", ephemeral=True)
            
            roblox_data = await get_roblox_user_info(roblox_username)
            
            if not roblox_data:
                await interaction.followup.send(
                    f"❌ Could not find Roblox user '{roblox_username}'. Please check the username and try again.",
                    ephemeral=True
                )
                return
            
            if verification['verification_code'] not in roblox_data['description']:
                await interaction.followup.send(
                    f"❌ Verification code not found in your Roblox profile description.\n\n"
                    f"Make sure you added `{verification['verification_code']}` to your profile and saved it.",
                    ephemeral=True
                )
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
                    await member.add_roles(verified_role, reason="Roblox verification successful")
            
            if unverified_role_id:
                unverified_role = interaction.guild.get_role(unverified_role_id)
                if unverified_role and unverified_role in member.roles:
                    await member.remove_roles(unverified_role, reason="Roblox verification successful")
            
            embed = discord.Embed(
                title="✅ Verification Successful!",
                description=(
                    f"**Roblox Account:** {roblox_data['username']}\n"
                    f"**Display Name:** {roblox_data['displayName']}\n"
                    f"**Roblox ID:** {roblox_data['id']}\n\n"
                    f"You now have access to the server!\n\n"
                    f"⚠️ Remember to remove the verification code from your Roblox profile."
                ),
                color=discord.Color.green()
            )
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
            await log_action(interaction.guild, 'verification', 'Roblox Verification Completed',
                           member, f"Verified as {roblox_data['username']}",
                           extra_info={'Roblox Username': roblox_data['username'], 'Roblox ID': roblox_data['id']})
            
            await db.add_log(
                interaction.guild.id,
                'roblox_verified',
                member.id,
                details={
                    'roblox_username': roblox_data['username'],
                    'roblox_id': roblox_data['id']
                }
            )
            
        except asyncio.TimeoutError:
            await interaction.followup.send("❌ Verification timed out. Please try again.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error in Roblox verification: {e}")
            await interaction.followup.send(f"❌ Verification error: {str(e)}", ephemeral=True)

# ============= VERIFICATION COMMANDS =============

@bot.tree.command(name="setup_verification", description="Set up verification system for new members")
@app_commands.checks.has_permissions(administrator=True)
async def setup_verification(interaction: discord.Interaction, channel: discord.TextChannel):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    unverified_role = await guild.create_role(
        name="Unverified",
        color=discord.Color.light_grey(),
        permissions=discord.Permissions.none(),
        reason="Verification system - unverified members"
    )
    
    verified_role = await guild.create_role(
        name="Verified",
        color=discord.Color.green(),
        reason="Verification system - verified members"
    )
    
    await db.set_server_config(
        guild.id,
        unverified_role_id=unverified_role.id,
        verified_role_id=verified_role.id,
        verification_channel_id=channel.id,
        verification_enabled=True
    )
    
    if guild.id not in server_configs:
        server_configs[guild.id] = {}
    server_configs[guild.id].update({
        'unverified_role_id': unverified_role.id,
        'verified_role_id': verified_role.id,
        'verification_channel_id': channel.id,
        'verification_enabled': True
    })
    
    view = VerificationView()
    embed = discord.Embed(
        title="✅ Welcome to the Server!",
        description="Please click the button below to verify and gain access to the server.",
        color=discord.Color.blue()
    )
    embed.set_footer(text="Click the Verify button to get started!")
    await channel.send(embed=embed, view=view)
    
    await interaction.followup.send(
        f"✅ Verification system set up!\n\n"
        f"• Unverified role: {unverified_role.mention}\n"
        f"• Verified role: {verified_role.mention}\n"
        f"• Verification channel: {channel.mention}\n\n"
        f"New members will be assigned the Unverified role and must verify in {channel.mention}.",
        ephemeral=True
    )

@bot.tree.command(name="verification_enable", description="Enable verification for new members")
@app_commands.checks.has_permissions(administrator=True)
async def verification_enable(interaction: discord.Interaction):
    config = server_configs.get(interaction.guild.id, {})
    
    if not config.get('verification_channel_id'):
        await interaction.response.send_message(
            "❌ Verification system not set up! Use `/setup_verification` first.",
            ephemeral=True
        )
        return
    
    await db.update_server_field(interaction.guild.id, 'verification_enabled', True)
    server_configs[interaction.guild.id]['verification_enabled'] = True
    
    await interaction.response.send_message(
        "✅ Verification enabled! New members will need to verify.",
        ephemeral=True
    )

@bot.tree.command(name="verification_disable", description="Disable verification for new members")
@app_commands.checks.has_permissions(administrator=True)
async def verification_disable(interaction: discord.Interaction):
    await db.update_server_field(interaction.guild.id, 'verification_enabled', False)
    if interaction.guild.id in server_configs:
        server_configs[interaction.guild.id]['verification_enabled'] = False
    
    await interaction.response.send_message(
        "✅ Verification disabled. New members will join normally.",
        ephemeral=True
    )

# ============= ROBLOX VERIFICATION COMMANDS =============

@bot.tree.command(name="setup_roblox_verification", description="Set up Roblox verification system")
@app_commands.checks.has_permissions(administrator=True)
async def setup_roblox_verification(interaction: discord.Interaction, channel: discord.TextChannel):
    try:
        await interaction.response.defer(ephemeral=True)
        
        guild = interaction.guild
        
        unverified_role = discord.utils.get(guild.roles, name="Unverified")
        if not unverified_role:
            unverified_role = await guild.create_role(
                name="Unverified",
                color=discord.Color.light_grey(),
                permissions=discord.Permissions.none(),
                reason="Roblox verification - unverified members"
            )
        
        verified_role = discord.utils.get(guild.roles, name="Verified")
        if not verified_role:
            verified_role = await guild.create_role(
                name="Verified",
                color=discord.Color.green(),
                reason="Roblox verification - verified members"
            )
        
        await db.set_server_config(
            guild.id,
            unverified_role_id=unverified_role.id,
            verified_role_id=verified_role.id,
            verification_channel_id=channel.id,
            verification_enabled=True
        )
        
        if guild.id not in server_configs:
            server_configs[guild.id] = {}
        server_configs[guild.id].update({
            'unverified_role_id': unverified_role.id,
            'verified_role_id': verified_role.id,
            'verification_channel_id': channel.id,
            'verification_enabled': True
        })
        
        view = RobloxVerificationView()
        embed = discord.Embed(
            title="🎮 Roblox Verification",
            description=(
                "Welcome! To access this server, you need to verify your Roblox account.\n\n"
                "**How to verify:**\n"
                "1. Click the button below\n"
                "2. You'll receive a unique code\n"
                "3. Add the code to your Roblox profile description\n"
                "4. Submit your Roblox username\n"
                "5. Remove the code after verification!\n\n"
                "✅ You'll be verified and gain access to the server!"
            ),
            color=discord.Color.blue()
        )
        embed.set_footer(text="Click 'Start Verification' to begin!")
        await channel.send(embed=embed, view=view)
        
        await interaction.followup.send(
            f"✅ Roblox verification system set up!\n\n"
            f"• Unverified role: {unverified_role.mention}\n"
            f"• Verified role: {verified_role.mention}\n"
            f"• Verification channel: {channel.mention}\n\n"
            f"New members will need to verify their Roblox account.",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Error in setup_roblox_verification: {e}")
        await interaction.followup.send(f"❌ Error setting up verification: {str(e)}", ephemeral=True)

@bot.tree.command(name="whois", description="Show linked Roblox account for a user")
@app_commands.checks.has_permissions(manage_guild=True)
async def whois_command(interaction: discord.Interaction, user: discord.Member):
    """Show user's linked Roblox account"""
    await interaction.response.defer(ephemeral=True)
    
    verification = await db.get_verification(interaction.guild.id, user.id)
    
    if not verification or not verification.get('verified'):
        await interaction.followup.send(
            f"{user.mention} has not verified their Roblox account.",
            ephemeral=True
        )
        return
    
    embed = discord.Embed(
        title=f"🔍 User Info: {user.name}",
        color=discord.Color.blue()
    )
    
    embed.add_field(name="Discord User", value=user.mention, inline=True)
    embed.add_field(name="Discord ID", value=str(user.id), inline=True)
    embed.add_field(name="Roblox Username", value=verification.get('roblox_username', 'Unknown'), inline=True)
    embed.add_field(name="Roblox ID", value=str(verification.get('roblox_id', 'Unknown')), inline=True)
    
    roblox_profile_url = f"https://www.roblox.com/users/{verification.get('roblox_id')}/profile"
    embed.add_field(name="Roblox Profile", value=f"[View Profile]({roblox_profile_url})", inline=True)
    
    verified_at = verification.get('verified_at', 'Unknown')
    if verified_at and verified_at != 'Unknown':
        if isinstance(verified_at, str):
            embed.add_field(name="Verified At", value=verified_at, inline=True)
        else:
            embed.add_field(name="Verified At", value=verified_at.strftime('%Y-%m-%d %H:%M:%S'), inline=True)
    
    embed.set_thumbnail(url=user.display_avatar.url)
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="verify_user", description="Manually verify a user (bypass verification)")
@app_commands.checks.has_permissions(administrator=True)
async def verify_user(interaction: discord.Interaction, user: discord.Member):
    """Manually verify a user"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id, {})
    verified_role_id = config.get('verified_role_id')
    unverified_role_id = config.get('unverified_role_id')
    
    if not verified_role_id:
        await interaction.followup.send("❌ Verification system not set up!", ephemeral=True)
        return
    
    verified_role = interaction.guild.get_role(verified_role_id)
    unverified_role = interaction.guild.get_role(unverified_role_id)
    
    try:
        if verified_role and verified_role not in user.roles:
            await user.add_roles(verified_role, reason=f"Manually verified by {interaction.user.name}")
        
        if unverified_role and unverified_role in user.roles:
            await user.remove_roles(unverified_role, reason=f"Manually verified by {interaction.user.name}")
        
        await log_action(interaction.guild, 'verification', 'Manual Verification',
                        interaction.user, f"{user.mention} manually verified",
                        extra_info={'Target User': user.name})
        
        await interaction.followup.send(f"✅ {user.mention} has been manually verified.", ephemeral=True)
    except Exception as e:
        logger.error(f"Error manually verifying user: {e}")
        await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)

# ============= THREAT LEVEL SYSTEM =============

async def apply_threat_level(guild: discord.Guild, level: int, set_by_user: discord.User):
    """Apply threat level actions to server"""
    config = server_configs.get(guild.id, {})
    
    if level == 0:
        for channel in guild.channels:
            try:
                if isinstance(channel, discord.TextChannel):
                    await channel.set_permissions(guild.default_role, send_messages=None, add_reactions=None, view_channel=None)
                elif isinstance(channel, discord.VoiceChannel):
                    await channel.set_permissions(guild.default_role, connect=None, view_channel=None)
            except:
                pass
        
        await send_alert(guild, f"🟢 **Threat Level: CLEAR**\nServer restored to normal operations by {set_by_user.mention}", 
                        color=discord.Color.green())
    
    elif level == 1:
        await db.update_server_field(guild.id, 'verification_enabled', True)
        if guild.id in server_configs:
            server_configs[guild.id]['verification_enabled'] = True
        
        onduty_role_id = config.get('onduty_role_id')
        if onduty_role_id:
            onduty_role = guild.get_role(onduty_role_id)
            if onduty_role:
                await send_alert(guild, 
                    f"🟡 **Threat Level: ELEVATED**\n"
                    f"{onduty_role.mention} - Increased security measures active.\n"
                    f"Verification has been enabled for new members.\n"
                    f"Set by: {set_by_user.mention}",
                    color=discord.Color.gold(),
                    email_admins=True)
        else:
            await send_alert(guild, 
                f"🟡 **Threat Level: ELEVATED**\n"
                f"Verification has been enabled for new members.\n"
                f"Set by: {set_by_user.mention}",
                color=discord.Color.gold(),
                email_admins=True)
    
    elif level == 2:
        for channel in guild.text_channels:
            try:
                await channel.set_permissions(guild.default_role, send_messages=False, add_reactions=False)
            except:
                pass
        
        for channel in guild.voice_channels:
            try:
                await channel.set_permissions(guild.default_role, connect=False)
            except:
                pass
        
        onduty_role_id = config.get('onduty_role_id')
        if onduty_role_id:
            onduty_role = guild.get_role(onduty_role_id)
            if onduty_role:
                for member in guild.members:
                    if onduty_role in member.roles:
                        try:
                            await member.send(
                                f"🟠 **HIGH THREAT ALERT** 🟠\n"
                                f"Server: **{guild.name}**\n"
                                f"All channels have been locked.\n"
                                f"Set by: {set_by_user.mention}\n\n"
                                f"Please check the server immediately."
                            )
                        except:
                            pass
        
        await send_alert(guild, 
            f"🟠 **Threat Level: HIGH**\n"
            f"⚠️ Server lockdown engaged!\n"
            f"All text and voice channels locked.\n"
            f"Set by: {set_by_user.mention}",
            color=discord.Color.orange(),
            email_admins=True)
    
    elif level == 3:
        for channel in guild.text_channels:
            try:
                await channel.set_permissions(guild.default_role, 
                    send_messages=False, add_reactions=False, view_channel=False)
            except:
                pass
        
        for channel in guild.voice_channels:
            try:
                await channel.set_permissions(guild.default_role, connect=False, view_channel=False)
                for member in channel.members:
                    if not member.guild_permissions.administrator:
                        try:
                            await member.move_to(None)
                        except:
                            pass
            except:
                pass
        
        allstaff_role_id = config.get('allstaff_role_id')
        if allstaff_role_id:
            allstaff_role = guild.get_role(allstaff_role_id)
            if allstaff_role:
                for member in guild.members:
                    if allstaff_role in member.roles:
                        try:
                            await member.send(
                                f"🚨 **ALPHA ALERT - SECURITY BREACH** 🚨\n"
                                f"Server: **{guild.name}**\n"
                                f"FULL LOCKDOWN IN EFFECT\n\n"
                                f"All channels locked and hidden.\n"
                                f"All users kicked from voice channels.\n\n"
                                f"⚠️ RESPOND IMMEDIATELY ⚠️\n"
                                f"Set by: {set_by_user.mention}"
                            )
                        except:
                            pass
        
        await send_alert(guild, 
            f"🔴 **THREAT LEVEL: ALPHA** 🔴\n"
            f"🚨 FULL SECURITY BREACH 🚨\n\n"
            f"Complete server lockdown engaged.\n"
            f"• All channels hidden and locked\n"
            f"• All users kicked from voice\n"
            f"• Only administrators can access\n\n"
            f"Set by: {set_by_user.mention}",
            color=discord.Color.red(),
            email_admins=True)

@bot.tree.command(name="threat_set", description="Set server threat level")
@app_commands.checks.has_permissions(administrator=True)
@app_commands.choices(level=[
    app_commands.Choice(name="🟢 Clear - Normal operations", value=0),
    app_commands.Choice(name="🟡 Elevated - Minor threat detected", value=1),
    app_commands.Choice(name="🟠 High - Serious threat, lockdown engaged", value=2),
    app_commands.Choice(name="🔴 Alpha - FULL SECURITY BREACH", value=3)
])
async def threat_set(interaction: discord.Interaction, level: int, reason: str):
    """Set threat level (0=Clear, 1=Elevated, 2=High, 3=Alpha)"""
    await interaction.response.defer(ephemeral=True)  # ADD THIS LINE
    
    await db.set_threat_level(interaction.guild.id, level, reason, interaction.user.id)
    
    await apply_threat_level(interaction.guild, level, interaction.user)
    
    level_info = THREAT_LEVELS[level]
    await interaction.followup.send(  # CHANGE TO followup
        f"{level_info['name']} **Threat Level Set**\n"
        f"Reason: {reason}\n"
        f"Actions have been applied to the server.",
        ephemeral=True
    )
    
    await db.add_log(
        interaction.guild.id,
        'threat_level_changed',
        interaction.user.id,
        details={'level': level, 'reason': reason}
    )

@bot.tree.command(name="threat_status", description="View current threat level")
async def threat_status(interaction: discord.Interaction):
    """Show current threat level"""
    await interaction.response.defer(ephemeral=True)
    
    current = await db.get_current_threat_level(interaction.guild.id)
    level = current.get('threat_level', 0)
    level_info = THREAT_LEVELS[level]
    
    embed = discord.Embed(
        title=f"{level_info['name']} - Threat Level Status",
        description=level_info['description'],
        color=level_info['color'],
        timestamp=datetime.now()
    )
    
    embed.add_field(name="Current Level", value=str(level), inline=True)
    embed.add_field(name="Reason", value=current.get('reason', 'N/A'), inline=True)
    
    if current.get('set_by'):
        set_by_user = bot.get_user(current['set_by'])
        embed.add_field(name="Set By", value=set_by_user.mention if set_by_user else f"User ID: {current['set_by']}", inline=True)
    
    if current.get('set_at'):
        set_at = current['set_at']
        if hasattr(set_at, 'strftime'):
            embed.add_field(name="Set At", value=set_at.strftime('%Y-%m-%d %H:%M:%S'), inline=False)
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="set_onduty_role", description="Set on-duty staff role for threat alerts")
@app_commands.checks.has_permissions(administrator=True)
async def set_onduty_role(interaction: discord.Interaction, role: discord.Role):
    """Set on-duty staff role"""
    await db.update_server_field(interaction.guild.id, 'onduty_role_id', role.id)
    
    if interaction.guild.id not in server_configs:
        server_configs[interaction.guild.id] = {}
    server_configs[interaction.guild.id]['onduty_role_id'] = role.id
    
    await interaction.response.send_message(
        f"✅ On-duty staff role set to {role.mention}\n"
        f"This role will be alerted for Elevated and High threat levels.",
        ephemeral=True
    )

@bot.tree.command(name="set_allstaff_role", description="Set all staff role for Alpha alerts")
@app_commands.checks.has_permissions(administrator=True)
async def set_allstaff_role(interaction: discord.Interaction, role: discord.Role):
    """Set all staff role"""
    await db.update_server_field(interaction.guild.id, 'allstaff_role_id', role.id)
    
    if interaction.guild.id not in server_configs:
        server_configs[interaction.guild.id] = {}
    server_configs[interaction.guild.id]['allstaff_role_id'] = role.id
    
    await interaction.response.send_message(
        f"✅ All staff role set to {role.mention}\n"
        f"This role will be DM'd during Alpha (Level 3) threats.",
        ephemeral=True
    )

# ============= ROLE MANAGEMENT SYSTEM =============

@bot.tree.command(name="promotion", description="Promote a user by giving them a role")
@app_commands.checks.has_permissions(manage_roles=True)
async def promotion(interaction: discord.Interaction, user: discord.Member, role: discord.Role, reason: str = "No reason provided"):
    """Promote a user by giving them a role"""
    await interaction.response.defer(ephemeral=True)
    
    if role >= interaction.guild.me.top_role:
        await interaction.followup.send(
            f"❌ I cannot manage {role.mention} - it's higher than or equal to my highest role.",
            ephemeral=True
        )
        return
    
    if role in user.roles:
        await interaction.followup.send(
            f"❌ {user.mention} already has the {role.mention} role.",
            ephemeral=True
        )
        return
    
    try:
        await user.add_roles(role, reason=f"Promoted by {interaction.user.name}: {reason}")
        
        await log_action(interaction.guild, 'promotion', 'User Promoted',
                        interaction.user, f"{user.mention} given {role.mention}",
                        extra_info={'User': user.name, 'Role': role.name, 'Reason': reason})
        
        try:
            await user.send(
                f"🎉 Congratulations! You've been promoted in **{interaction.guild.name}**!\n"
                f"**Role Granted:** {role.name}\n"
                f"**Promoted By:** {interaction.user.name}\n"
                f"**Reason:** {reason}"
            )
        except:
            pass
        
        await interaction.followup.send(
            f"✅ Promoted {user.mention} to {role.mention}",
            ephemeral=True
        )
        
    except discord.Forbidden:
        await interaction.followup.send(
            f"❌ I don't have permission to manage roles.",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Error promoting user: {e}")
        await interaction.followup.send(
            f"❌ Error promoting user: {str(e)}",
            ephemeral=True
        )

@bot.tree.command(name="demotion", description="Demote a user by removing a role")
@app_commands.checks.has_permissions(manage_roles=True)
async def demotion(interaction: discord.Interaction, user: discord.Member, role: discord.Role, reason: str = "No reason provided"):
    """Demote a user by removing a role"""
    await interaction.response.defer(ephemeral=True)
    
    if role >= interaction.guild.me.top_role:
        await interaction.followup.send(
            f"❌ I cannot manage {role.mention} - it's higher than or equal to my highest role.",
            ephemeral=True
        )
        return
    
    if role not in user.roles:
        await interaction.followup.send(
            f"❌ {user.mention} doesn't have the {role.mention} role.",
            ephemeral=True
        )
        return
    
    try:
        await user.remove_roles(role, reason=f"Demoted by {interaction.user.name}: {reason}")
        
        await log_action(interaction.guild, 'demotion', 'User Demoted',
                        interaction.user, f"{user.mention} removed from {role.mention}",
                        extra_info={'User': user.name, 'Role': role.name, 'Reason': reason})
        
        try:
            await user.send(
                f"📉 You've been demoted in **{interaction.guild.name}**.\n"
                f"**Role Removed:** {role.name}\n"
                f"**Demoted By:** {interaction.user.name}\n"
                f"**Reason:** {reason}"
            )
        except:
            pass
        
        await interaction.followup.send(
            f"✅ Demoted {user.mention} - removed {role.mention}",
            ephemeral=True
        )
        
    except discord.Forbidden:
        await interaction.followup.send(
            f"❌ I don't have permission to manage roles.",
            ephemeral=True
        )
    except Exception as e:
        logger.error(f"Error demoting user: {e}")
        await interaction.followup.send(
            f"❌ Error demoting user: {str(e)}",
            ephemeral=True
        )

@bot.tree.command(name="requestrole", description="Request a role from staff")
async def requestrole(interaction: discord.Interaction, role: discord.Role, reason: str = "No reason provided"):
    """Request a role"""
    await interaction.response.defer(ephemeral=True)
    
    if role >= interaction.guild.me.top_role:
        await interaction.followup.send(
            f"❌ You cannot request {role.mention} - it's an administrative role.",
            ephemeral=True
        )
        return
    
    if role in interaction.user.roles:
        await interaction.followup.send(
            f"❌ You already have the {role.mention} role.",
            ephemeral=True
        )
        return
    
    request_id = await db.create_role_request(
        interaction.guild.id,
        interaction.user.id,
        interaction.user.name,
        role.id,
        reason
    )
    
    config = server_configs.get(interaction.guild.id, {})
    log_channel_id = config.get('log_channel_id')
    
    if log_channel_id:
        log_channel = interaction.guild.get_channel(log_channel_id)
        if log_channel:
            embed = discord.Embed(
                title="📝 Role Request",
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            embed.add_field(name="User", value=interaction.user.mention, inline=True)
            embed.add_field(name="Role Requested", value=role.mention, inline=True)
            embed.add_field(name="Reason", value=reason, inline=False)
            embed.set_footer(text=f"Request ID: {request_id}")
            
            view = RoleRequestView(request_id)
            await log_channel.send(embed=embed, view=view)
    
    await interaction.followup.send(
        f"✅ Role request submitted!\n"
        f"**Role:** {role.mention}\n"
        f"**Request ID:** {request_id}\n\n"
        f"Staff will review your request shortly.",
        ephemeral=True
    )
    
    await db.add_log(
        interaction.guild.id,
        'role_request_submitted',
        interaction.user.id,
        details={'role_id': role.id, 'role_name': role.name, 'request_id': request_id, 'reason': reason}
    )

class RoleRequestView(discord.ui.View):
    def __init__(self, request_id):
        super().__init__(timeout=None)
        self.request_id = request_id
    
    @discord.ui.button(label="✅ Approve", style=discord.ButtonStyle.green, custom_id="role_approve")
    async def approve_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.manage_roles:
            await interaction.response.send_message(
                "❌ You need 'Manage Roles' permission to approve role requests.",
                ephemeral=True
            )
            return
        
        await interaction.response.defer()
        
        request = await db.get_role_request(self.request_id)
        if not request:
            await interaction.followup.send("❌ Request not found.", ephemeral=True)
            return
        
        user = interaction.guild.get_member(request['user_id'])
        role = interaction.guild.get_role(request['role_id'])
        
        if not user:
            await interaction.followup.send("❌ User not found in server.", ephemeral=True)
            return
        
        if not role:
            await interaction.followup.send("❌ Role not found.", ephemeral=True)
            return
        
        try:
            await user.add_roles(role, reason=f"Role request approved by {interaction.user.name}")
            
            await db.update_role_request_status(self.request_id, 'approved', interaction.user.id)
            
            try:
                await user.send(
                    f"✅ Your role request has been **APPROVED**!\n"
                    f"**Server:** {interaction.guild.name}\n"
                    f"**Role:** {role.name}\n"
                    f"**Approved By:** {interaction.user.name}"
                )
            except:
                pass
            
            embed = interaction.message.embeds[0]
            embed.color = discord.Color.green()
            embed.title = "✅ Role Request Approved"
            embed.add_field(name="Approved By", value=interaction.user.mention, inline=True)
            
            await interaction.message.edit(embed=embed, view=None)
            
            await db.add_log(
                interaction.guild.id,
                'role_request_approved',
                interaction.user.id,
                details={'role_id': role.id, 'request_id': self.request_id, 'target_user_id': user.id}
            )
            
            await interaction.followup.send(f"✅ Role request approved! {user.mention} has been given {role.mention}", ephemeral=True)
            
        except discord.Forbidden:
            await interaction.followup.send("❌ I don't have permission to manage roles.", ephemeral=True)
        except Exception as e:
            logger.error(f"Error approving role request: {e}")
            await interaction.followup.send(f"❌ Error: {str(e)}", ephemeral=True)
    
    @discord.ui.button(label="❌ Deny", style=discord.ButtonStyle.red, custom_id="role_deny")
    async def deny_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not interaction.user.guild_permissions.manage_roles:
            await interaction.response.send_message(
                "❌ You need 'Manage Roles' permission to deny role requests.",
                ephemeral=True
            )
            return
        
        await interaction.response.defer()
        
        request = await db.get_role_request(self.request_id)
        if not request:
            await interaction.followup.send("❌ Request not found.", ephemeral=True)
            return
        
        user = interaction.guild.get_member(request['user_id'])
        role = interaction.guild.get_role(request['role_id'])
        
        await db.update_role_request_status(self.request_id, 'denied', interaction.user.id)
        
        if user:
            try:
                await user.send(
                    f"❌ Your role request has been **DENIED**.\n"
                    f"**Server:** {interaction.guild.name}\n"
                    f"**Role:** {role.name if role else 'Unknown'}\n"
                    f"**Denied By:** {interaction.user.name}"
                )
            except:
                pass
        
        embed = interaction.message.embeds[0]
        embed.color = discord.Color.red()
        embed.title = "❌ Role Request Denied"
        embed.add_field(name="Denied By", value=interaction.user.mention, inline=True)
        
        await interaction.message.edit(embed=embed, view=None)
        
        await db.add_log(
            interaction.guild.id,
            'role_request_denied',
            interaction.user.id,
            details={'role_id': request['role_id'], 'request_id': self.request_id, 'target_user_id': request['user_id']}
        )
        
        await interaction.followup.send("❌ Role request denied.", ephemeral=True)

# ============= ROLE REQUESTS CONTINUATION =============

@bot.tree.command(name="role_requests", description="View all pending role requests")
@app_commands.checks.has_permissions(manage_roles=True)
async def role_requests(interaction: discord.Interaction):
    """View all pending role requests"""
    await interaction.response.defer(ephemeral=True)
    
    pending_requests = await db.get_pending_role_requests(interaction.guild.id)
    
    if not pending_requests:
        await interaction.followup.send("✅ No pending role requests.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="📝 Pending Role Requests",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    for request in pending_requests[:10]:
        user = bot.get_user(request['user_id'])
        role = interaction.guild.get_role(request['role_id'])
        
        # FIX: Use variables instead of nested f-strings with brackets
        user_id = request['user_id']
        role_id = request['role_id']
        user_str = user.mention if user else f"ID: {user_id}"
        role_str = role.mention if role else f"ID: {role_id}"
        reason = request.get('reason', 'No reason provided')
        
        embed.add_field(
            name=f"Request ID: {request['id']}",
            value=(
                f"**User:** {user_str}\n"
                f"**Role:** {role_str}\n"
                f"**Reason:** {reason}"
            ),
            inline=False
        )
    
    embed.set_footer(text=f"Showing {min(10, len(pending_requests))} of {len(pending_requests)} requests")
    await interaction.followup.send(embed=embed, ephemeral=True)
    
# ============= LOG CHANNEL SETUP =============

@bot.tree.command(name="set_log_channel", description="Set the security log channel")
@app_commands.checks.has_permissions(administrator=True)
async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    """Set where security alerts are logged"""
    await interaction.response.defer(ephemeral=True)
    
    await db.update_server_field(interaction.guild.id, 'log_channel_id', channel.id)
    
    if interaction.guild.id not in server_configs:
        server_configs[interaction.guild.id] = {}
    server_configs[interaction.guild.id]['log_channel_id'] = channel.id
    
    embed = discord.Embed(
        title="✅ Log Channel Set",
        description=f"Security alerts will be sent to {channel.mention}",
        color=discord.Color.green()
    )
    
    await interaction.followup.send(embed=embed, ephemeral=True)
    
    try:
        test_embed = discord.Embed(
            title="🧪 Test Message",
            description="Log channel configured successfully!",
            color=discord.Color.green(),
            timestamp=datetime.now()
        )
        await channel.send(embed=test_embed)
    except Exception as e:
        logger.warning(f"Could not send test message to log channel: {e}")

@bot.tree.command(name="set_partnership_channel", description="Set the partnership/whitelist channel")
@app_commands.checks.has_permissions(administrator=True)
async def set_partnership_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    """Set partnership channel for server collaboration"""
    await interaction.response.defer(ephemeral=True)
    
    await db.update_server_field(interaction.guild.id, 'partnership_channel_id', channel.id)
    
    if interaction.guild.id not in server_configs:
        server_configs[interaction.guild.id] = {}
    server_configs[interaction.guild.id]['partnership_channel_id'] = channel.id
    
    await interaction.followup.send(
        f"✅ Partnership channel set to {channel.mention}\n"
        f"Use `/partnership_add` to add partner servers.",
        ephemeral=True
    )

# ============= PARTNERSHIP SYSTEM =============

@bot.tree.command(name="partnership_add", description="Add a partner server to whitelist")
@app_commands.checks.has_permissions(administrator=True)
async def partnership_add(interaction: discord.Interaction, server_id: str, server_name: str, contact: str = "Not provided"):
    """Add a partner server"""
    await interaction.response.defer(ephemeral=True)
    
    try:
        server_id_int = int(server_id)
    except ValueError:
        await interaction.followup.send("❌ Invalid server ID. Must be a number.", ephemeral=True)
        return
    
    partnership_id = await db.create_partnership(
        interaction.guild.id,
        server_id_int,
        server_name,
        contact,
        interaction.user.id
    )
    
    config = server_configs.get(interaction.guild.id, {})
    partnership_channel_id = config.get('partnership_channel_id')
    
    if partnership_channel_id:
        channel = interaction.guild.get_channel(partnership_channel_id)
        if channel:
            embed = discord.Embed(
                title="🤝 New Partnership",
                color=discord.Color.blue(),
                timestamp=datetime.now()
            )
            embed.add_field(name="Server Name", value=server_name, inline=True)
            embed.add_field(name="Server ID", value=server_id, inline=True)
            embed.add_field(name="Contact", value=contact, inline=True)
            embed.add_field(name="Added By", value=interaction.user.mention, inline=True)
            
            try:
                await channel.send(embed=embed)
            except Exception as e:
                logger.warning(f"Could not send partnership announcement: {e}")
    
    await interaction.followup.send(
        f"✅ Partnership added!\n"
        f"**Server:** {server_name}\n"
        f"**Server ID:** {server_id}\n"
        f"**Partnership ID:** {partnership_id}",
        ephemeral=True
    )
    
    await db.add_log(
        interaction.guild.id,
        'partnership_added',
        interaction.user.id,
        details={'partnership_id': partnership_id, 'server_name': server_name, 'server_id': server_id_int}
    )

@bot.tree.command(name="partnership_remove", description="Remove a partner server")
@app_commands.checks.has_permissions(administrator=True)
async def partnership_remove(interaction: discord.Interaction, partnership_id: int):
    """Remove a partnership"""
    await interaction.response.defer(ephemeral=True)
    
    partnership = await db.get_partnership(partnership_id)
    
    if not partnership:
        await interaction.followup.send("❌ Partnership not found.", ephemeral=True)
        return
    
    if partnership['guild_id'] != interaction.guild.id:
        await interaction.followup.send("❌ This partnership doesn't belong to your server.", ephemeral=True)
        return
    
    await db.delete_partnership(partnership_id)
    
    await interaction.followup.send(
        f"✅ Partnership removed: {partnership['partner_server_name']}",
        ephemeral=True
    )
    
    await db.add_log(
        interaction.guild.id,
        'partnership_removed',
        interaction.user.id,
        details={'partnership_id': partnership_id, 'server_name': partnership['partner_server_name']}
    )

@bot.tree.command(name="partnerships", description="View all partner servers")
@app_commands.checks.has_permissions(manage_guild=True)
async def partnerships(interaction: discord.Interaction):
    """View all partnerships"""
    await interaction.response.defer(ephemeral=True)
    
    partnerships_list = await db.get_partnerships(interaction.guild.id)
    
    if not partnerships_list:
        await interaction.followup.send("❌ No partnerships yet. Use `/partnership_add` to add one.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="🤝 Partner Servers",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    display_count = min(MAX_PARTNERSHIPS_DISPLAY, len(partnerships_list))
    
    for partnership in partnerships_list[:MAX_PARTNERSHIPS_DISPLAY]:
        embed.add_field(
            name=f"{partnership['partner_server_name']} (ID: {partnership['id']})",
            value=(
                f"**Server ID:** {partnership['partner_server_id']}\n"
                f"**Contact:** {partnership['contact']}\n"
                f"**Added By:** <@{partnership['added_by']}>"
            ),
            inline=False
        )
    
    if len(partnerships_list) > MAX_PARTNERSHIPS_DISPLAY:
        embed.set_footer(text=f"Showing {display_count} of {len(partnerships_list)} partnerships")
    else:
        embed.set_footer(text=f"Total: {len(partnerships_list)} partnership(s)")
    
    await interaction.followup.send(embed=embed, ephemeral=True)

# ============= ADMIN COMMANDS =============

@bot.tree.command(name="logs", description="View recent server logs")
@app_commands.checks.has_permissions(administrator=True)
async def logs(interaction: discord.Interaction, limit: int = 10):
    """View recent server logs"""
    await interaction.response.defer(ephemeral=True)
    
    if limit < 1 or limit > 50:
        await interaction.followup.send("❌ Limit must be between 1 and 50.", ephemeral=True)
        return
    
    guild_logs = await db.get_logs(interaction.guild.id, limit)
    
    if not guild_logs:
        await interaction.followup.send("❌ No logs found.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="📋 Recent Server Logs",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    for log in guild_logs:
        user_mention = f"<@{log['user_id']}>" if log['user_id'] else "System"
        timestamp = log.get('timestamp', 'Unknown')
        
        if isinstance(timestamp, str):
            timestamp_str = timestamp
        else:
            timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(timestamp, 'strftime') else str(timestamp)
        
        log_text = f"**Type:** {log['log_type']}\n**User:** {user_mention}\n**Time:** {timestamp_str}"
        
        if log.get('details'):
            details = log['details']
            if isinstance(details, dict):
                for key, value in list(details.items())[:3]:
                    log_text += f"\n**{key}:** {str(value)[:100]}"
        
        embed.add_field(name=f"Log #{log['id']}", value=log_text, inline=False)
    
    embed.set_footer(text=f"Showing {len(guild_logs)} log(s)")
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="config", description="View server configuration")
@app_commands.checks.has_permissions(administrator=True)
async def config(interaction: discord.Interaction):
    """View server configuration"""
    await interaction.response.defer(ephemeral=True)
    
    config = server_configs.get(interaction.guild.id, {})
    
    embed = discord.Embed(
        title="⚙️ Server Configuration",
        color=discord.Color.blue(),
        timestamp=datetime.now()
    )
    
    security_config = {
        'Log Channel': f"<#{config.get('log_channel_id')}>" if config.get('log_channel_id') else "Not set",
        'Quarantine Role': f"<@&{config.get('quarantine_role_id')}>" if config.get('quarantine_role_id') else "Not set",
        'Verified Role': f"<@&{config.get('verified_role_id')}>" if config.get('verified_role_id') else "Not set",
        'Unverified Role': f"<@&{config.get('unverified_role_id')}>" if config.get('unverified_role_id') else "Not set",
    }
    
    for key, value in security_config.items():
        embed.add_field(name=key, value=value, inline=True)
    
    features = {
        'Verification Enabled': "✅ Yes" if config.get('verification_enabled') else "❌ No",
        'Lockdown Active': "🔒 Yes" if config.get('lockdown_enabled') else "🔓 No",
    }
    
    for key, value in features.items():
        embed.add_field(name=key, value=value, inline=True)
    
    staff_roles = {
        'On-Duty Role': f"<@&{config.get('onduty_role_id')}>" if config.get('onduty_role_id') else "Not set",
        'All Staff Role': f"<@&{config.get('allstaff_role_id')}>" if config.get('allstaff_role_id') else "Not set",
    }
    
    for key, value in staff_roles.items():
        embed.add_field(name=key, value=value, inline=True)
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="reset_config", description="Reset server configuration")
@app_commands.checks.has_permissions(administrator=True)
async def reset_config(interaction: discord.Interaction):
    """Reset server configuration"""
    await interaction.response.send_message(
        "⚠️ Are you sure you want to reset all configuration?\n"
        "This will clear all settings. React with ✅ to confirm or ❌ to cancel.",
        ephemeral=True
    )
    
    def check(reaction, user):
        return user == interaction.user
    
    try:
        reaction, _ = await bot.wait_for('reaction_add', timeout=30.0, check=check)
        
        if str(reaction.emoji) == '✅':
            await db.reset_server_config(interaction.guild.id)
            if interaction.guild.id in server_configs:
                server_configs[interaction.guild.id] = {}
            
            await interaction.followup.send("✅ Configuration reset!", ephemeral=True)
        else:
            await interaction.followup.send("❌ Reset cancelled.", ephemeral=True)
    except asyncio.TimeoutError:
        await interaction.followup.send("❌ Reset cancelled (timeout).", ephemeral=True)

# ============= BOT RUN =============

if __name__ == "__main__":
    try:
        bot.run(TOKEN)
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")