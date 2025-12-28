import os
import json
from datetime import datetime

# Check if we're using PostgreSQL or SQLite
DATABASE_URL = os.getenv('DATABASE_URL')
USE_POSTGRES = DATABASE_URL is not None

if USE_POSTGRES:
    import asyncpg
    # Fix Railway's postgres:// to postgresql://
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
else:
    import aiosqlite
    DATABASE_PATH = 'sentinel.db'

# Database connection pool for PostgreSQL
db_pool = None

async def get_pool():
    """Get or create PostgreSQL connection pool"""
    global db_pool
    if USE_POSTGRES and db_pool is None:
        db_pool = await asyncpg.create_pool(DATABASE_URL)
    return db_pool

async def init_database():
    """Initialize the database with all required tables"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            # Server configurations table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS servers (
                    server_id BIGINT PRIMARY KEY,
                    log_channel_id BIGINT,
                    quarantine_role_id BIGINT,
                    unverified_role_id BIGINT,
                    verified_role_id BIGINT,
                    verification_channel_id BIGINT,
                    lockdown_enabled BOOLEAN DEFAULT FALSE,
                    verification_enabled BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Thresholds table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS thresholds (
                    id SERIAL PRIMARY KEY,
                    server_id BIGINT,
                    action_type TEXT,
                    count_limit INTEGER,
                    time_window_seconds INTEGER,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id),
                    UNIQUE(server_id, action_type)
                )
            ''')
            
            # Whitelist table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS whitelist (
                    id SERIAL PRIMARY KEY,
                    server_id BIGINT,
                    entity_id BIGINT,
                    entity_type TEXT,
                    added_by BIGINT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Logs table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    log_id SERIAL PRIMARY KEY,
                    server_id BIGINT,
                    action_type TEXT,
                    user_id BIGINT,
                    target_id BIGINT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Roblox verification table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS roblox_verifications (
                    id SERIAL PRIMARY KEY,
                    server_id BIGINT,
                    user_id BIGINT,
                    roblox_id BIGINT,
                    roblox_username TEXT,
                    verification_code TEXT,
                    verified BOOLEAN DEFAULT FALSE,
                    verified_at TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id),
                    UNIQUE(server_id, user_id)
                )
            ''')
            
            # Partnerships table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS partnerships (
                    id SERIAL PRIMARY KEY,
                    server_id BIGINT,
                    partner_server_name TEXT,
                    partner_invite_link TEXT,
                    partner_description TEXT,
                    representative TEXT,
                    partnership_date DATE,
                    partnership_type TEXT,
                    benefits TEXT,
                    member_count INTEGER,
                    submitted_by BIGINT,
                    approved_by BIGINT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    approved_at TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Backups table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS backups (
                    backup_id SERIAL PRIMARY KEY,
                    server_id BIGINT,
                    backup_data TEXT,
                    backup_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Threat levels table
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_levels (
                    id SERIAL PRIMARY KEY,
                    server_id BIGINT,
                    threat_level INTEGER DEFAULT 0,
                    reason TEXT,
                    set_by BIGINT,
                    set_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            print("✅ PostgreSQL database initialized successfully")
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            # Server configurations table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS servers (
                    server_id INTEGER PRIMARY KEY,
                    log_channel_id INTEGER,
                    quarantine_role_id INTEGER,
                    unverified_role_id INTEGER,
                    verified_role_id INTEGER,
                    verification_channel_id INTEGER,
                    lockdown_enabled BOOLEAN DEFAULT 0,
                    verification_enabled BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Thresholds table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS thresholds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    action_type TEXT,
                    count_limit INTEGER,
                    time_window_seconds INTEGER,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id),
                    UNIQUE(server_id, action_type)
                )
            ''')
            
            # Whitelist table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    entity_id INTEGER,
                    entity_type TEXT,
                    added_by INTEGER,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Logs table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    action_type TEXT,
                    user_id INTEGER,
                    target_id INTEGER,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Roblox verification table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS roblox_verifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    user_id INTEGER,
                    roblox_id INTEGER,
                    roblox_username TEXT,
                    verification_code TEXT,
                    verified BOOLEAN DEFAULT 0,
                    verified_at TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id),
                    UNIQUE(server_id, user_id)
                )
            ''')
            
            # Partnerships table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS partnerships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    partner_server_name TEXT,
                    partner_invite_link TEXT,
                    partner_description TEXT,
                    representative TEXT,
                    partnership_date DATE,
                    partnership_type TEXT,
                    benefits TEXT,
                    member_count INTEGER,
                    submitted_by INTEGER,
                    approved_by INTEGER,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    approved_at TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Backups table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS backups (
                    backup_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    backup_data TEXT,
                    backup_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            # Threat levels table
            await db.execute('''
                CREATE TABLE IF NOT EXISTS threat_levels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER,
                    threat_level INTEGER DEFAULT 0,
                    reason TEXT,
                    set_by INTEGER,
                    set_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (server_id) REFERENCES servers(server_id)
                )
            ''')
            
            await db.commit()
            print("✅ SQLite database initialized successfully")

# Server Configuration Functions
async def get_server_config(server_id):
    """Get server configuration"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow('SELECT * FROM servers WHERE server_id = $1', server_id)
            if row:
                return dict(row)
            return None
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM servers WHERE server_id = ?', (server_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None

async def set_server_config(server_id, **kwargs):
    """Set or update server configuration"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            config = await get_server_config(server_id)
            
            if config is None:
                await conn.execute('INSERT INTO servers (server_id) VALUES ($1)', server_id)
            
            for key, value in kwargs.items():
                await conn.execute(
                    f'UPDATE servers SET {key} = $1 WHERE server_id = $2',
                    value, server_id
                )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            config = await get_server_config(server_id)
            
            if config is None:
                await db.execute('INSERT INTO servers (server_id) VALUES (?)', (server_id,))
            
            for key, value in kwargs.items():
                await db.execute(
                    f'UPDATE servers SET {key} = ? WHERE server_id = ?',
                    (value, server_id)
                )
            
            await db.commit()

async def update_server_field(server_id, field, value):
    """Update a specific server configuration field"""
    await set_server_config(server_id, **{field: value})

# Whitelist Functions
async def add_to_whitelist(server_id, entity_id, entity_type, added_by):
    """Add entity to whitelist"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            try:
                await conn.execute(
                    '''INSERT INTO whitelist (server_id, entity_id, entity_type, added_by)
                       VALUES ($1, $2, $3, $4)''',
                    server_id, entity_id, entity_type, added_by
                )
                return True
            except asyncpg.UniqueViolationError:
                return False
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            try:
                await db.execute(
                    '''INSERT INTO whitelist (server_id, entity_id, entity_type, added_by)
                       VALUES (?, ?, ?, ?)''',
                    (server_id, entity_id, entity_type, added_by)
                )
                await db.commit()
                return True
            except aiosqlite.IntegrityError:
                return False

async def remove_from_whitelist(server_id, entity_id):
    """Remove entity from whitelist"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute(
                'DELETE FROM whitelist WHERE server_id = $1 AND entity_id = $2',
                server_id, entity_id
            )
            return result != 'DELETE 0'
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cursor = await db.execute(
                'DELETE FROM whitelist WHERE server_id = ? AND entity_id = ?',
                (server_id, entity_id)
            )
            await db.commit()
            return cursor.rowcount > 0

async def is_whitelisted(server_id, entity_id):
    """Check if entity is whitelisted"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            result = await conn.fetchval(
                'SELECT 1 FROM whitelist WHERE server_id = $1 AND entity_id = $2',
                server_id, entity_id
            )
            return result is not None
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            async with db.execute(
                'SELECT 1 FROM whitelist WHERE server_id = ? AND entity_id = ?',
                (server_id, entity_id)
            ) as cursor:
                result = await cursor.fetchone()
                return result is not None

async def get_whitelist(server_id):
    """Get all whitelisted entities for a server"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch('SELECT * FROM whitelist WHERE server_id = $1', server_id)
            return [dict(row) for row in rows]
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM whitelist WHERE server_id = ?', (server_id,)) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

# Threshold Functions
async def set_threshold(server_id, action_type, count_limit, time_window_seconds):
    """Set or update threshold for an action type"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                '''INSERT INTO thresholds (server_id, action_type, count_limit, time_window_seconds)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT(server_id, action_type) 
                   DO UPDATE SET count_limit = $3, time_window_seconds = $4''',
                server_id, action_type, count_limit, time_window_seconds
            )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                '''INSERT INTO thresholds (server_id, action_type, count_limit, time_window_seconds)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(server_id, action_type) 
                   DO UPDATE SET count_limit = ?, time_window_seconds = ?''',
                (server_id, action_type, count_limit, time_window_seconds, 
                 count_limit, time_window_seconds)
            )
            await db.commit()

async def get_threshold(server_id, action_type):
    """Get threshold for specific action type"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM thresholds WHERE server_id = $1 AND action_type = $2',
                server_id, action_type
            )
            if row:
                return dict(row)
            return None
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                'SELECT * FROM thresholds WHERE server_id = ? AND action_type = ?',
                (server_id, action_type)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None

async def get_all_thresholds(server_id):
    """Get all thresholds for a server"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch('SELECT * FROM thresholds WHERE server_id = $1', server_id)
            return [dict(row) for row in rows]
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM thresholds WHERE server_id = ?', (server_id,)) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

# Logging Functions
async def add_log(server_id, action_type, user_id, target_id=None, details=None):
    """Add a log entry"""
    details_json = json.dumps(details) if details else None
    
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                '''INSERT INTO logs (server_id, action_type, user_id, target_id, details)
                   VALUES ($1, $2, $3, $4, $5)''',
                server_id, action_type, user_id, target_id, details_json
            )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                '''INSERT INTO logs (server_id, action_type, user_id, target_id, details)
                   VALUES (?, ?, ?, ?, ?)''',
                (server_id, action_type, user_id, target_id, details_json)
            )
            await db.commit()

async def get_recent_logs(server_id, limit=10):
    """Get recent logs for a server"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                '''SELECT * FROM logs 
                   WHERE server_id = $1 
                   ORDER BY timestamp DESC 
                   LIMIT $2''',
                server_id, limit
            )
            return [dict(row) for row in rows]
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                '''SELECT * FROM logs 
                   WHERE server_id = ? 
                   ORDER BY timestamp DESC 
                   LIMIT ?''',
                (server_id, limit)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]

# Load all server configs into memory on startup
async def load_all_configs():
    """Load all server configurations into memory"""
    configs = {}
    
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch('SELECT * FROM servers')
            for row in rows:
                configs[row['server_id']] = dict(row)
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM servers') as cursor:
                rows = await cursor.fetchall()
                for row in rows:
                    configs[row['server_id']] = dict(row)
    
    return configs

async def load_all_whitelists():
    """Load all whitelists into memory"""
    whitelists = {}
    
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch('SELECT server_id, entity_id FROM whitelist')
            for row in rows:
                server_id = row['server_id']
                if server_id not in whitelists:
                    whitelists[server_id] = set()
                whitelists[server_id].add(row['entity_id'])
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT server_id, entity_id FROM whitelist') as cursor:
                rows = await cursor.fetchall()
                for row in rows:
                    server_id = row['server_id']
                    if server_id not in whitelists:
                        whitelists[server_id] = set()
                    whitelists[server_id].add(row['entity_id'])
    
    return whitelists

# Roblox Verification Functions
async def create_verification(server_id, user_id, verification_code):
    """Create a new verification entry"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                '''INSERT INTO roblox_verifications (server_id, user_id, verification_code)
                   VALUES ($1, $2, $3)
                   ON CONFLICT(server_id, user_id) 
                   DO UPDATE SET verification_code = $3, verified = FALSE''',
                server_id, user_id, verification_code
            )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                '''INSERT OR REPLACE INTO roblox_verifications (server_id, user_id, verification_code, verified)
                   VALUES (?, ?, ?, 0)''',
                (server_id, user_id, verification_code)
            )
            await db.commit()

async def get_verification(server_id, user_id):
    """Get verification entry for a user"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM roblox_verifications WHERE server_id = $1 AND user_id = $2',
                server_id, user_id
            )
            if row:
                return dict(row)
            return None
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                'SELECT * FROM roblox_verifications WHERE server_id = ? AND user_id = ?',
                (server_id, user_id)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None

async def complete_verification(server_id, user_id, roblox_id, roblox_username):
    """Mark verification as complete"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                '''UPDATE roblox_verifications 
                   SET verified = TRUE, roblox_id = $1, roblox_username = $2, verified_at = CURRENT_TIMESTAMP
                   WHERE server_id = $3 AND user_id = $4''',
                roblox_id, roblox_username, server_id, user_id
            )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                '''UPDATE roblox_verifications 
                   SET verified = 1, roblox_id = ?, roblox_username = ?, verified_at = CURRENT_TIMESTAMP
                   WHERE server_id = ? AND user_id = ?''',
                (roblox_id, roblox_username, server_id, user_id)
            )
            await db.commit()

async def is_verified(server_id, user_id):
    """Check if user is verified"""
    verification = await get_verification(server_id, user_id)
    return verification and verification.get('verified')

# Partnership Functions
async def create_partnership(server_id, data, submitted_by):
    """Create a new partnership submission"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            partnership_id = await conn.fetchval(
                '''INSERT INTO partnerships 
                   (server_id, partner_server_name, partner_invite_link, partner_description, 
                    representative, partnership_date, partnership_type, benefits, member_count, submitted_by)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                   RETURNING id''',
                server_id, data['server_name'], data['invite_link'], data['description'],
                data['representative'], data['partnership_date'], data['partnership_type'],
                data['benefits'], data.get('member_count', 0), submitted_by
            )
            return partnership_id
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            cursor = await db.execute(
                '''INSERT INTO partnerships 
                   (server_id, partner_server_name, partner_invite_link, partner_description, 
                    representative, partnership_date, partnership_type, benefits, member_count, submitted_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (server_id, data['server_name'], data['invite_link'], data['description'],
                 data['representative'], data['partnership_date'], data['partnership_type'],
                 data['benefits'], data.get('member_count', 0), submitted_by)
            )
            await db.commit()
            return cursor.lastrowid

async def get_partnership(partnership_id):
    """Get partnership by ID"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow('SELECT * FROM partnerships WHERE id = $1', partnership_id)
            if row:
                return dict(row)
            return None
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute('SELECT * FROM partnerships WHERE id = ?', (partnership_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None

async def approve_partnership(partnership_id, approved_by):
    """Approve a partnership"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                '''UPDATE partnerships 
                   SET status = 'approved', approved_by = $1, approved_at = CURRENT_TIMESTAMP
                   WHERE id = $2''',
                approved_by, partnership_id
            )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                '''UPDATE partnerships 
                   SET status = 'approved', approved_by = ?, approved_at = CURRENT_TIMESTAMP
                   WHERE id = ?''',
                (approved_by, partnership_id)
            )
            await db.commit()

async def deny_partnership(partnership_id, denied_by):
    """Deny a partnership"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                '''UPDATE partnerships 
                   SET status = 'denied', approved_by = $1, approved_at = CURRENT_TIMESTAMP
                   WHERE id = $2''',
                denied_by, partnership_id
            )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                '''UPDATE partnerships 
                   SET status = 'denied', approved_by = ?, approved_at = CURRENT_TIMESTAMP
                   WHERE id = ?''',
                (denied_by, partnership_id)
            )
            await db.commit()

async def get_partnerships_by_status(server_id, status):
    """Get all partnerships with a specific status"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                'SELECT * FROM partnerships WHERE server_id = $1 AND status = $2 ORDER BY created_at DESC',
                server_id, status
            )
            return [dict(row) for row in rows]
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                'SELECT * FROM partnerships WHERE server_id = ? AND status = ? ORDER BY created_at DESC',
                (server_id, status)
            ) as cursor:
                rows = await cursor.fetchall()
                result = [dict(row) for row in rows]
                print(f"DEBUG DB: Query returned {len(result)} rows for server {server_id}, status {status}")
                return result

async def delete_partnership(partnership_id):
    """Delete a partnership"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute('DELETE FROM partnerships WHERE id = $1', partnership_id)
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute('DELETE FROM partnerships WHERE id = ?', (partnership_id,))
            await db.commit()

# Threat Level Functions
async def set_threat_level(server_id, level, reason, set_by):
    """Set threat level for a server"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                '''INSERT INTO threat_levels (server_id, threat_level, reason, set_by)
                   VALUES ($1, $2, $3, $4)''',
                server_id, level, reason, set_by
            )
            # Update current threat level in servers table
            await conn.execute(
                '''INSERT INTO servers (server_id) VALUES ($1)
                   ON CONFLICT(server_id) DO NOTHING''',
                server_id
            )
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            await db.execute(
                '''INSERT INTO threat_levels (server_id, threat_level, reason, set_by)
                   VALUES (?, ?, ?, ?)''',
                (server_id, level, reason, set_by)
            )
            await db.commit()

async def get_current_threat_level(server_id):
    """Get current threat level"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                '''SELECT * FROM threat_levels 
                   WHERE server_id = $1 
                   ORDER BY set_at DESC 
                   LIMIT 1''',
                server_id
            )
            if row:
                return dict(row)
            return {'threat_level': 0, 'reason': 'Default', 'set_by': None}
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                '''SELECT * FROM threat_levels 
                   WHERE server_id = ? 
                   ORDER BY set_at DESC 
                   LIMIT 1''',
                (server_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return {'threat_level': 0, 'reason': 'Default', 'set_by': None}

async def get_threat_history(server_id, limit=10):
    """Get threat level history"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                '''SELECT * FROM threat_levels 
                   WHERE server_id = $1 
                   ORDER BY set_at DESC 
                   LIMIT $2''',
                server_id, limit
            )
            return [dict(row) for row in rows]
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                '''SELECT * FROM threat_levels 
                   WHERE server_id = ? 
                   ORDER BY set_at DESC 
                   LIMIT ?''',
                (server_id, limit)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
            
async def add_threat_columns():
    """Add missing columns for threat system"""
    if USE_POSTGRES:
        pool = await get_pool()
        async with pool.acquire() as conn:
            try:
                await conn.execute("ALTER TABLE servers ADD COLUMN onduty_role_id BIGINT")
                print("✅ Added onduty_role_id column")
            except Exception as e:
                print(f"⚠️ onduty_role_id: {e}")
            
            try:
                await conn.execute("ALTER TABLE servers ADD COLUMN allstaff_role_id BIGINT")
                print("✅ Added allstaff_role_id column")
            except Exception as e:
                print(f"⚠️ allstaff_role_id: {e}")
            
            try:
                await conn.execute("ALTER TABLE servers ADD COLUMN partnership_channel_id BIGINT")
                print("✅ Added partnership_channel_id column")
            except Exception as e:
                print(f"⚠️ partnership_channel_id: {e}")
    else:
        async with aiosqlite.connect(DATABASE_PATH) as db:
            try:
                await db.execute("ALTER TABLE servers ADD COLUMN onduty_role_id INTEGER")
                print("✅ Added onduty_role_id column")
            except Exception as e:
                print(f"⚠️ onduty_role_id: {e}")
            
            try:
                await db.execute("ALTER TABLE servers ADD COLUMN allstaff_role_id INTEGER")
                print("✅ Added allstaff_role_id column")
            except Exception as e:
                print(f"⚠️ allstaff_role_id: {e}")
            
            try:
                await db.execute("ALTER TABLE servers ADD COLUMN partnership_channel_id INTEGER")
                print("✅ Added partnership_channel_id column")
            except Exception as e:
                print(f"⚠️ partnership_channel_id: {e}")
            
            await db.commit()