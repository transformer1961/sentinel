import discord
from discord.ext import commands
from discord import app_commands
import os
from dotenv import load_dotenv
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict
import json
import database as db

# Load environment variables
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')

# Bot setup with all required intents
intents = discord.Intents.all()
bot = commands.Bot(command_prefix='!', intents=intents)

# In-memory tracking for actions
action_tracker = defaultdict(lambda: defaultdict(list))

# Default thresholds
DEFAULT_THRESHOLDS = {
    'channel_delete': {'count': 3, 'seconds': 10},
    'channel_create': {'count': 3, 'seconds': 10},
    'role_delete': {'count': 3, 'seconds': 10},
    'role_update': {'count': 5, 'seconds': 10},
    'member_ban': {'count': 5, 'seconds': 30},
    'member_kick': {'count': 5, 'seconds': 30},
    'mass_join': {'count': 10, 'seconds': 60}
}

# Server configurations (loaded from database)
server_configs = {}
whitelists = defaultdict(set)

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    print(f'Bot is in {len(bot.guilds)} servers')
    print(f'Bot ID: {bot.user.id}')
    print(f'Intents: {bot.intents}')
    print(f'Intents Value: {bot.intents.value}')
    
    # Initialize database
    await db.init_database()
    
    # Load configs and whitelists from database
    global server_configs, whitelists
    server_configs = await db.load_all_configs()
    whitelists = await db.load_all_whitelists()
    print(f'✅ Loaded {len(server_configs)} server configs and {len(whitelists)} whitelists')
    
    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        print(f'Synced {len(synced)} command(s)')
    except Exception as e:
        print(f'Error syncing commands: {e}')
    
    print('\n🔍 DEBUG MODE: Bot is now monitoring events...')

# Test event to see if bot receives ANY events
@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    print(f'💬 DEBUG: Message received from {message.author.name}: {message.content[:50]}')

# Helper function to check if user is whitelisted
async def is_whitelisted_check(guild_id, user_id):
    # Check in-memory first
    if user_id in whitelists.get(guild_id, set()):
        return True
    # Fallback to database
    return await db.is_whitelisted(guild_id, user_id)

# Helper function to track actions
def track_action(guild_id, user_id, action_type):
    now = datetime.now()
    action_tracker[guild_id][(user_id, action_type)].append(now)
    
    # Clean old entries
    threshold = DEFAULT_THRESHOLDS.get(action_type, {'seconds': 60})
    cutoff = now - timedelta(seconds=threshold['seconds'])
    action_tracker[guild_id][(user_id, action_type)] = [
        t for t in action_tracker[guild_id][(user_id, action_type)] if t > cutoff
    ]
    
    return len(action_tracker[guild_id][(user_id, action_type)])

# Helper function to send alerts
async def send_alert(guild, message, user=None):
    config = server_configs.get(guild.id, {})
    log_channel_id = config.get('log_channel_id')
    
    embed = discord.Embed(
        title="🚨 Security Alert",
        description=message,
        color=discord.Color.red(),
        timestamp=datetime.now()
    )
    
    if user:
        embed.add_field(name="User", value=f"{user.mention} ({user.id})", inline=False)
    
    # Log to database
    await db.add_log(
        guild.id, 
        'security_alert', 
        user.id if user else None,
        details={'message': message}
    )
    
    # Send to log channel
    if log_channel_id:
        channel = guild.get_channel(log_channel_id)
        if channel:
            await channel.send(embed=embed)
    
    # DM whitelisted admins
    for member in guild.members:
        if member.guild_permissions.administrator and await is_whitelisted_check(guild.id, member.id):
            try:
                await member.send(embed=embed)
            except:
                pass

# Helper function to quarantine user
async def quarantine_user(guild, user, reason):
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
    
    # Remove all roles and add quarantine role
    try:
        roles_removed = [role for role in member.roles if role != guild.default_role]
        await member.remove_roles(*roles_removed, reason=f"Quarantined: {reason}")
        await member.add_roles(quarantine_role, reason=f"Quarantined: {reason}")
        
        await send_alert(guild, f"✅ Quarantined {user.mention}\nReason: {reason}", user)
        return True
    except Exception as e:
        await send_alert(guild, f"❌ Failed to quarantine {user.mention}: {str(e)}", user)
        return False

# Event: Channel Deletion
@bot.event
async def on_guild_channel_delete(channel):
    print(f'\n🗑️ DEBUG: Channel deleted: {channel.name} in {channel.guild.name}')
    await asyncio.sleep(1)  # Wait for audit log
    
    guild = channel.guild
    print(f'🔍 DEBUG: Checking audit logs...')
    
    async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
        print(f'📋 DEBUG: Audit log entry found - User: {entry.user.name}, Target: {entry.target.id}')
        if entry.target.id == channel.id:
            user = entry.user
            
            print(f'👤 DEBUG: Deleter: {user.name} (ID: {user.id})')
            print(f'🤖 DEBUG: Is bot? {user.bot}')
            print(f'✅ DEBUG: Is whitelisted? {is_whitelisted(guild.id, user.id)}')
            
            # Skip if whitelisted or bot
            if user.bot or await is_whitelisted_check(guild.id, user.id):
                print(f'⏭️ DEBUG: Skipping (bot or whitelisted)')
                return
            
            # Track action
            count = track_action(guild.id, user.id, 'channel_delete')
            threshold = DEFAULT_THRESHOLDS['channel_delete']
            
            print(f'📊 DEBUG: Delete count: {count}/{threshold["count"]} in {threshold["seconds"]}s')
            
            if count >= threshold['count']:
                print(f'🚨 DEBUG: THRESHOLD BREACHED! Sending alert and quarantining...')
                await send_alert(guild, 
                    f"⚠️ **CHANNEL DELETE THRESHOLD BREACHED**\n"
                    f"{user.mention} deleted {count} channels in {threshold['seconds']} seconds!",
                    user)
                await quarantine_user(guild, user, f"Mass channel deletion ({count} channels)")
            else:
                print(f'✓ DEBUG: Below threshold, continuing to monitor')
        else:
            print(f'⚠️ DEBUG: Audit log target mismatch')

# Event: Channel Creation
@bot.event
async def on_guild_channel_create(channel):
    print(f'\n➕ DEBUG: Channel created: {channel.name} in {channel.guild.name}')
    await asyncio.sleep(1)
    
    guild = channel.guild
    print(f'🔍 DEBUG: Checking audit logs...')
    
    async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_create):
        print(f'📋 DEBUG: Audit log entry found - User: {entry.user.name}, Target: {entry.target.id}')
        if entry.target.id == channel.id:
            user = entry.user
            
            print(f'👤 DEBUG: Creator: {user.name} (ID: {user.id})')
            print(f'🤖 DEBUG: Is bot? {user.bot}')
            print(f'✅ DEBUG: Is whitelisted? {await is_whitelisted_check(guild.id, user.id)}')
            
            if user.bot or await is_whitelisted_check(guild.id, user.id):
                print(f'⏭️ DEBUG: Skipping (bot or whitelisted)')
                return
            
            count = track_action(guild.id, user.id, 'channel_create')
            threshold = DEFAULT_THRESHOLDS['channel_create']
            
            print(f'📊 DEBUG: Create count: {count}/{threshold["count"]} in {threshold["seconds"]}s')
            
            if count >= threshold['count']:
                print(f'🚨 DEBUG: THRESHOLD BREACHED! Sending alert and quarantining...')
                await send_alert(guild,
                    f"⚠️ **CHANNEL CREATE THRESHOLD BREACHED**\n"
                    f"{user.mention} created {count} channels in {threshold['seconds']} seconds!",
                    user)
                await quarantine_user(guild, user, f"Mass channel creation ({count} channels)")
            else:
                print(f'✓ DEBUG: Below threshold, continuing to monitor')
        else:
            print(f'⚠️ DEBUG: Audit log target mismatch')

# Event: Role Deletion
@bot.event
async def on_guild_role_delete(role):
    await asyncio.sleep(1)
    
    guild = role.guild
    async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
        if entry.target.id == role.id:
            user = entry.user
            
            if user.bot or is_whitelisted(guild.id, user.id):
                return
            
            count = track_action(guild.id, user.id, 'role_delete')
            threshold = DEFAULT_THRESHOLDS['role_delete']
            
            if count >= threshold['count']:
                await send_alert(guild,
                    f"⚠️ **ROLE DELETE THRESHOLD BREACHED**\n"
                    f"{user.mention} deleted {count} roles in {threshold['seconds']} seconds!",
                    user)
                await quarantine_user(guild, user, f"Mass role deletion ({count} roles)")

# Event: Member Ban
@bot.event
async def on_member_ban(guild, user):
    await asyncio.sleep(1)
    
    async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
        if entry.target.id == user.id:
            banner = entry.user
            
            if banner.bot or is_whitelisted(guild.id, banner.id):
                return
            
            count = track_action(guild.id, banner.id, 'member_ban')
            threshold = DEFAULT_THRESHOLDS['member_ban']
            
            if count >= threshold['count']:
                await send_alert(guild,
                    f"⚠️ **MASS BAN THRESHOLD BREACHED**\n"
                    f"{banner.mention} banned {count} members in {threshold['seconds']} seconds!",
                    banner)
                await quarantine_user(guild, banner, f"Mass member banning ({count} bans)")

# Event: Mass Join Detection
join_tracker = defaultdict(list)

@bot.event
async def on_member_join(member):
    guild = member.guild
    now = datetime.now()
    
    join_tracker[guild.id].append(now)
    
    # Clean old entries
    cutoff = now - timedelta(seconds=DEFAULT_THRESHOLDS['mass_join']['seconds'])
    join_tracker[guild.id] = [t for t in join_tracker[guild.id] if t > cutoff]
    
    count = len(join_tracker[guild.id])
    threshold = DEFAULT_THRESHOLDS['mass_join']
    
    if count >= threshold['count']:
        await send_alert(guild,
            f"⚠️ **POSSIBLE RAID DETECTED**\n"
            f"{count} accounts joined in {threshold['seconds']} seconds!\n"
            f"Consider enabling verification or lockdown.")

# Setup Command
@bot.tree.command(name="setup", description="Initial bot setup wizard")
@app_commands.checks.has_permissions(administrator=True)
async def setup(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    embed = discord.Embed(
        title="🛡️ Security Bot Setup",
        description="Let's set up your server protection!",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="Step 1: Set Log Channel",
        value="Use `/set_log_channel #channel` to set where alerts go",
        inline=False
    )
    
    embed.add_field(
        name="Step 2: Create Quarantine Role",
        value="Use `/create_quarantine_role` to create a quarantine role",
        inline=False
    )
    
    embed.add_field(
        name="Step 3: Whitelist Trusted Users",
        value="Use `/whitelist add @user` to whitelist admins/bots",
        inline=False
    )
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="set_log_channel", description="Set the security log channel")
@app_commands.checks.has_permissions(administrator=True)
async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    await db.update_server_field(interaction.guild.id, 'log_channel_id', channel.id)
    
    # Update in-memory cache
    if interaction.guild.id not in server_configs:
        server_configs[interaction.guild.id] = {}
    server_configs[interaction.guild.id]['log_channel_id'] = channel.id
    
    await interaction.response.send_message(
        f"✅ Security log channel set to {channel.mention}",
        ephemeral=True
    )

# Create Quarantine Role
@bot.tree.command(name="create_quarantine_role", description="Create a quarantine role")
@app_commands.checks.has_permissions(administrator=True)
async def create_quarantine_role(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    # Create role with no permissions
    role = await guild.create_role(
        name="Quarantined",
        color=discord.Color.dark_grey(),
        permissions=discord.Permissions.none(),
        reason="Security bot quarantine role"
    )
    
    await db.update_server_field(guild.id, 'quarantine_role_id', role.id)
    
    # Update in-memory cache
    if guild.id not in server_configs:
        server_configs[guild.id] = {}
    server_configs[guild.id]['quarantine_role_id'] = role.id
    
    await interaction.followup.send(
        f"✅ Quarantine role created: {role.mention}\n"
        f"⚠️ Make sure this role is below the bot's role in the role hierarchy!",
        ephemeral=True
    )

# Whitelist Commands
@bot.tree.command(name="whitelist_add", description="Add user to whitelist")
@app_commands.checks.has_permissions(administrator=True)
async def whitelist_add(interaction: discord.Interaction, user: discord.User):
    await db.add_to_whitelist(interaction.guild.id, user.id, 'user', interaction.user.id)
    
    # Update in-memory cache
    if interaction.guild.id not in whitelists:
        whitelists[interaction.guild.id] = set()
    whitelists[interaction.guild.id].add(user.id)
    
    await interaction.response.send_message(
        f"✅ Added {user.mention} to whitelist",
        ephemeral=True
    )

@bot.tree.command(name="whitelist_remove", description="Remove user from whitelist")
@app_commands.checks.has_permissions(administrator=True)
async def whitelist_remove(interaction: discord.Interaction, user: discord.User):
    removed = await db.remove_from_whitelist(interaction.guild.id, user.id)
    
    # Update in-memory cache
    if user.id in whitelists.get(interaction.guild.id, set()):
        whitelists[interaction.guild.id].remove(user.id)
    
    if removed:
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
        title="Whitelisted Users",
        color=discord.Color.green()
    )
    
    users = []
    for user_id in guild_whitelist:
        user = bot.get_user(user_id)
        users.append(f"• {user.mention if user else f'User ID: {user_id}'}")
    
    embed.description = "\n".join(users)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# Status Command
@bot.tree.command(name="status", description="Show bot protection status")
async def status(interaction: discord.Interaction):
    config = server_configs.get(interaction.guild.id, {})
    
    embed = discord.Embed(
        title="🛡️ Security Bot Status",
        color=discord.Color.blue()
    )
    
    log_channel = "✅ Configured" if config.get('log_channel_id') else "❌ Not Set"
    quarantine_role = "✅ Configured" if config.get('quarantine_role_id') else "❌ Not Set"
    whitelist_count = len(whitelists.get(interaction.guild.id, set()))
    
    embed.add_field(name="Log Channel", value=log_channel, inline=True)
    embed.add_field(name="Quarantine Role", value=quarantine_role, inline=True)
    embed.add_field(name="Whitelisted Users", value=str(whitelist_count), inline=True)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# Test command - triggers alert manually
@bot.tree.command(name="test_alert", description="Test the alert system")
@app_commands.checks.has_permissions(administrator=True)
async def test_alert(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await send_alert(interaction.guild, "🧪 This is a test alert!", interaction.user)
    await interaction.followup.send("Test alert sent!", ephemeral=True)

# Manual Quarantine Command
@bot.tree.command(name="quarantine", description="Manually quarantine a user")
@app_commands.checks.has_permissions(administrator=True)
async def quarantine_cmd(interaction: discord.Interaction, user: discord.Member, reason: str = "Manual quarantine"):
    await interaction.response.defer(ephemeral=True)
    
    success = await quarantine_user(interaction.guild, user, reason)
    
    if success:
        await interaction.followup.send(f"✅ Quarantined {user.mention}", ephemeral=True)
    else:
        await interaction.followup.send(f"❌ Failed to quarantine {user.mention}", ephemeral=True)

# Unquarantine Command
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
    if not quarantine_role:
        await interaction.followup.send("❌ Quarantine role not found!", ephemeral=True)
        return
    
    if quarantine_role not in user.roles:
        await interaction.followup.send(f"❌ {user.mention} is not quarantined!", ephemeral=True)
        return
    
    try:
        await user.remove_roles(quarantine_role, reason=f"Unquarantined by {interaction.user.name}")
        
        await send_alert(
            interaction.guild,
            f"✅ {user.mention} was unquarantined by {interaction.user.mention}",
            user
        )
        
        await interaction.followup.send(f"✅ Removed quarantine from {user.mention}", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ Failed to unquarantine: {str(e)}", ephemeral=True)

# Lockdown Commands
@bot.tree.command(name="lockdown_enable", description="Lock down the server (emergency mode)")
@app_commands.checks.has_permissions(administrator=True)
async def lockdown_enable(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    try:
        # Remove @everyone permissions to send messages and add reactions
        everyone_role = guild.default_role
        permissions = everyone_role.permissions
        permissions.update(
            send_messages=False,
            add_reactions=False,
            create_instant_invite=False
        )
        
        await everyone_role.edit(permissions=permissions, reason="Server lockdown activated")
        
        # Update database
        await db.update_server_field(guild.id, 'lockdown_enabled', 1)
        if guild.id not in server_configs:
            server_configs[guild.id] = {}
        server_configs[guild.id]['lockdown_enabled'] = True
        
        # Send alert
        await send_alert(
            guild,
            f"🔒 **SERVER LOCKDOWN ACTIVATED**\n"
            f"Initiated by {interaction.user.mention}\n"
            f"All members restricted from sending messages and reacting."
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
        await interaction.followup.send(f"❌ Failed to enable lockdown: {str(e)}", ephemeral=True)

@bot.tree.command(name="lockdown_disable", description="Disable server lockdown")
@app_commands.checks.has_permissions(administrator=True)
async def lockdown_disable(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    try:
        # Restore @everyone permissions
        everyone_role = guild.default_role
        permissions = everyone_role.permissions
        permissions.update(
            send_messages=True,
            add_reactions=True,
            create_instant_invite=True
        )
        
        await everyone_role.edit(permissions=permissions, reason="Server lockdown lifted")
        
        # Update database
        await db.update_server_field(guild.id, 'lockdown_enabled', 0)
        if guild.id in server_configs:
            server_configs[guild.id]['lockdown_enabled'] = False
        
        # Send alert
        await send_alert(
            guild,
            f"🔓 **SERVER LOCKDOWN LIFTED**\n"
            f"Lifted by {interaction.user.mention}\n"
            f"Normal permissions restored."
        )
        
        await interaction.followup.send(
            "🔓 Server lockdown has been lifted!\n"
            "Normal permissions restored.",
            ephemeral=True
        )
    except Exception as e:
        await interaction.followup.send(f"❌ Failed to disable lockdown: {str(e)}", ephemeral=True)

# Verification System
@bot.tree.command(name="setup_verification", description="Set up verification system for new members")
@app_commands.checks.has_permissions(administrator=True)
async def setup_verification(interaction: discord.Interaction, channel: discord.TextChannel):
    await interaction.response.defer(ephemeral=True)
    
    guild = interaction.guild
    
    # Create Unverified role
    unverified_role = await guild.create_role(
        name="Unverified",
        color=discord.Color.light_grey(),
        permissions=discord.Permissions.none(),
        reason="Verification system - unverified members"
    )
    
    # Create Verified/Member role (or they can use existing one)
    verified_role = await guild.create_role(
        name="Verified",
        color=discord.Color.green(),
        reason="Verification system - verified members"
    )
    
    # Update database
    await db.set_server_config(
        guild.id,
        unverified_role_id=unverified_role.id,
        verified_role_id=verified_role.id,
        verification_channel_id=channel.id,
        verification_enabled=1
    )
    
    # Update in-memory cache
    if guild.id not in server_configs:
        server_configs[guild.id] = {}
    server_configs[guild.id].update({
        'unverified_role_id': unverified_role.id,
        'verified_role_id': verified_role.id,
        'verification_channel_id': channel.id,
        'verification_enabled': True
    })
    
    # Send verification message with button
    view = VerificationView()
    embed = discord.Embed(
        title="✅ Welcome to the Server!",
        description="Please click the button below to verify and gain access to the server.",
        color=discord.Color.blue()
    )
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
    
    await db.update_server_field(interaction.guild.id, 'verification_enabled', 1)
    server_configs[interaction.guild.id]['verification_enabled'] = True
    
    await interaction.response.send_message(
        "✅ Verification enabled! New members will need to verify.",
        ephemeral=True
    )

@bot.tree.command(name="verification_disable", description="Disable verification for new members")
@app_commands.checks.has_permissions(administrator=True)
async def verification_disable(interaction: discord.Interaction):
    await db.update_server_field(interaction.guild.id, 'verification_enabled', 0)
    if interaction.guild.id in server_configs:
        server_configs[interaction.guild.id]['verification_enabled'] = False
    
    await interaction.response.send_message(
        "✅ Verification disabled. New members will join normally.",
        ephemeral=True
    )

# Verification Button View
class VerificationView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)  # Never timeout
    
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
        
        # Add verified role
        if verified_role and verified_role not in member.roles:
            await member.add_roles(verified_role, reason="Member verified")
        
        # Remove unverified role
        if unverified_role and unverified_role in member.roles:
            await member.remove_roles(unverified_role, reason="Member verified")
        
        await interaction.response.send_message(
            "✅ You have been verified! Welcome to the server!",
            ephemeral=True
        )
        
        # Log verification
        await db.add_log(
            interaction.guild.id,
            'member_verified',
            member.id,
            details={'verification_method': 'button'}
        )

# Handle new member joins for verification
@bot.event
async def on_member_join(member):
    guild = member.guild
    config = server_configs.get(guild.id, {})
    
    # Check if verification is enabled
    if config.get('verification_enabled'):
        unverified_role_id = config.get('unverified_role_id')
        if unverified_role_id:
            unverified_role = guild.get_role(unverified_role_id)
            if unverified_role:
                await member.add_roles(unverified_role, reason="New member - needs verification")
                
                # Send DM with verification instructions
                verification_channel_id = config.get('verification_channel_id')
                if verification_channel_id:
                    channel = guild.get_channel(verification_channel_id)
                    try:
                        await member.send(
                            f"Welcome to **{guild.name}**! 🎉\n\n"
                            f"Please verify yourself in {channel.mention} to gain access to the server."
                        )
                    except:
                        pass  # User has DMs disabled
    
    # Mass join detection (existing code)
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
            f"Consider enabling verification or lockdown.")

# Run the bot
bot.run(TOKEN)