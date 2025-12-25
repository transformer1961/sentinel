import aiosqlite
import json
from datetime import datetime

DATABASE_PATH = 'sentinel.db'

async def init_database():
    """Initialize the database with all required tables"""
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
        
        await db.commit()
        print("✅ Database initialized successfully")

# Server Configuration Functions
async def get_server_config(server_id):
    """Get server configuration"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            'SELECT * FROM servers WHERE server_id = ?', 
            (server_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None

async def set_server_config(server_id, **kwargs):
    """Set or update server configuration"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Check if server exists
        config = await get_server_config(server_id)
        
        if config is None:
            # Insert new server
            await db.execute(
                'INSERT INTO servers (server_id) VALUES (?)',
                (server_id,)
            )
        
        # Update fields
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
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            'DELETE FROM whitelist WHERE server_id = ? AND entity_id = ?',
            (server_id, entity_id)
        )
        await db.commit()
        return cursor.rowcount > 0

async def is_whitelisted(server_id, entity_id):
    """Check if entity is whitelisted"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute(
            'SELECT 1 FROM whitelist WHERE server_id = ? AND entity_id = ?',
            (server_id, entity_id)
        ) as cursor:
            result = await cursor.fetchone()
            return result is not None

async def get_whitelist(server_id):
    """Get all whitelisted entities for a server"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            'SELECT * FROM whitelist WHERE server_id = ?',
            (server_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

# Threshold Functions
async def set_threshold(server_id, action_type, count_limit, time_window_seconds):
    """Set or update threshold for an action type"""
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
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            'SELECT * FROM thresholds WHERE server_id = ?',
            (server_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

# Logging Functions
async def add_log(server_id, action_type, user_id, target_id=None, details=None):
    """Add a log entry"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        details_json = json.dumps(details) if details else None
        await db.execute(
            '''INSERT INTO logs (server_id, action_type, user_id, target_id, details)
               VALUES (?, ?, ?, ?, ?)''',
            (server_id, action_type, user_id, target_id, details_json)
        )
        await db.commit()

async def get_recent_logs(server_id, limit=10):
    """Get recent logs for a server"""
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