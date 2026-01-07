import sqlite3
import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger('SecurityBot.Database')

# Database file path
DATABASE_FILE = 'security_bot.db'

# ============= DATABASE INITIALIZATION =============

async def init_database():
    """Initialize the database with all required tables"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        
        # Enable foreign keys
        cursor.execute('PRAGMA foreign_keys = ON')
        
        # Server Configurations Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_configs (
                guild_id INTEGER PRIMARY KEY,
                log_channel_id INTEGER,
                quarantine_role_id INTEGER,
                verified_role_id INTEGER,
                unverified_role_id INTEGER,
                verification_channel_id INTEGER,
                verification_enabled BOOLEAN DEFAULT 0,
                lockdown_enabled BOOLEAN DEFAULT 0,
                partnership_channel_id INTEGER,
                onduty_role_id INTEGER,
                allstaff_role_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Whitelist Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                whitelist_type TEXT DEFAULT 'user',
                added_by INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id),
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # Logs Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                log_type TEXT NOT NULL,
                user_id INTEGER,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # User Emails Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id),
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # Quarantine Roles Storage Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role_ids TEXT NOT NULL,
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id),
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # Verification Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                verification_code TEXT,
                roblox_id INTEGER,
                roblox_username TEXT,
                verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMP,
                UNIQUE(guild_id, user_id),
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # Role Requests Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS role_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                role_id INTEGER NOT NULL,
                reason TEXT,
                status TEXT DEFAULT 'pending',
                reviewed_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # Partnerships Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS partnerships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                partner_guild_id INTEGER NOT NULL,
                partner_server_name TEXT NOT NULL,
                contact TEXT,
                added_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # Threat Levels Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_levels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                threat_level INTEGER DEFAULT 0,
                reason TEXT,
                set_by INTEGER,
                set_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id),
                FOREIGN KEY (guild_id) REFERENCES server_configs(guild_id)
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_guild ON logs(guild_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_logs_type ON logs(log_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_whitelist_guild ON whitelist(guild_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_verifications_guild ON verifications(guild_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_role_requests_guild ON role_requests(guild_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_partnerships_guild ON partnerships(guild_id)')
        
        conn.commit()
        conn.close()
        logger.info('✅ Database initialized successfully')
        return True
    except Exception as e:
        logger.error(f'Database initialization error: {e}')
        return False

# ============= HELPER FUNCTION =============

def _execute_query(query: str, params: tuple = (), fetch_one: bool = False, fetch_all: bool = False):
    """Execute a database query synchronously"""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        
        if fetch_one:
            result = cursor.fetchone()
            conn.close()
            return dict(result) if result else None
        elif fetch_all:
            results = cursor.fetchall()
            conn.close()
            return [dict(row) for row in results]
        else:
            conn.commit()
            conn.close()
            return cursor.lastrowid
    except Exception as e:
        logger.error(f'Database error: {e}')
        return None

async def execute_query(query: str, params: tuple = (), fetch_one: bool = False, fetch_all: bool = False):
    """Execute a database query asynchronously"""
    return await asyncio.to_thread(_execute_query, query, params, fetch_one, fetch_all)

# ============= SERVER CONFIGURATION =============

async def load_all_configs() -> dict:
    """Load all server configurations"""
    results = await execute_query('SELECT * FROM server_configs', fetch_all=True)
    return {row['guild_id']: row for row in (results or [])}

async def set_server_config(guild_id: int, **kwargs) -> bool:
    """Set server configuration"""
    try:
        # Check if config exists
        existing = await execute_query(
            'SELECT guild_id FROM server_configs WHERE guild_id = ?',
            (guild_id,),
            fetch_one=True
        )
        
        if existing:
            # Update existing
            set_clause = ', '.join([f'{key} = ?' for key in kwargs.keys()])
            query = f'UPDATE server_configs SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE guild_id = ?'
            await execute_query(query, tuple(kwargs.values()) + (guild_id,))
        else:
            # Insert new
            keys = ', '.join(['guild_id'] + list(kwargs.keys()))
            placeholders = ', '.join(['?'] * (len(kwargs) + 1))
            query = f'INSERT INTO server_configs ({keys}) VALUES ({placeholders})'
            await execute_query(query, (guild_id,) + tuple(kwargs.values()))
        
        return True
    except Exception as e:
        logger.error(f'Error setting server config: {e}')
        return False

async def update_server_field(guild_id: int, field: str, value: Any) -> bool:
    """Update a single server configuration field"""
    try:
        query = f'UPDATE server_configs SET {field} = ?, updated_at = CURRENT_TIMESTAMP WHERE guild_id = ?'
        await execute_query(query, (value, guild_id))
        return True
    except Exception as e:
        logger.error(f'Error updating server field: {e}')
        return False

async def reset_server_config(guild_id: int) -> bool:
    """Reset server configuration"""
    try:
        await execute_query('DELETE FROM server_configs WHERE guild_id = ?', (guild_id,))
        return True
    except Exception as e:
        logger.error(f'Error resetting config: {e}')
        return False

# ============= LOGGING =============

async def add_log(guild_id: int, log_type: str, user_id: Optional[int] = None, details: Optional[dict] = None) -> bool:
    """Add a log entry"""
    try:
        details_json = json.dumps(details) if details else None
        query = 'INSERT INTO logs (guild_id, log_type, user_id, details) VALUES (?, ?, ?, ?)'
        await execute_query(query, (guild_id, log_type, user_id, details_json))
        return True
    except Exception as e:
        logger.error(f'Error adding log: {e}')
        return False

async def get_logs(guild_id: int, limit: int = 10) -> List[dict]:
    """Get recent logs for a guild"""
    try:
        query = '''
            SELECT id, guild_id, log_type, user_id, details, timestamp 
            FROM logs 
            WHERE guild_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        '''
        results = await execute_query(query, (guild_id, limit), fetch_all=True)
        
        # Parse JSON details
        for log in (results or []):
            if log['details']:
                log['details'] = json.loads(log['details'])
        
        return results or []
    except Exception as e:
        logger.error(f'Error getting logs: {e}')
        return []

# ============= WHITELIST =============

async def load_all_whitelists() -> dict:
    """Load all whitelists"""
    try:
        results = await execute_query('SELECT guild_id, user_id FROM whitelist', fetch_all=True)
        whitelists = {}
        for row in (results or []):
            guild_id = row['guild_id']
            if guild_id not in whitelists:
                whitelists[guild_id] = set()
            whitelists[guild_id].add(row['user_id'])
        return whitelists
    except Exception as e:
        logger.error(f'Error loading whitelists: {e}')
        return {}

async def is_whitelisted(guild_id: int, user_id: int) -> bool:
    """Check if user is whitelisted"""
    try:
        result = await execute_query(
            'SELECT id FROM whitelist WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch_one=True
        )
        return result is not None
    except Exception as e:
        logger.error(f'Error checking whitelist: {e}')
        return False

async def add_to_whitelist(guild_id: int, user_id: int, whitelist_type: str = 'user', added_by: Optional[int] = None) -> bool:
    """Add user to whitelist"""
    try:
        query = 'INSERT OR IGNORE INTO whitelist (guild_id, user_id, whitelist_type, added_by) VALUES (?, ?, ?, ?)'
        await execute_query(query, (guild_id, user_id, whitelist_type, added_by))
        return True
    except Exception as e:
        logger.error(f'Error adding to whitelist: {e}')
        return False

async def remove_from_whitelist(guild_id: int, user_id: int) -> bool:
    """Remove user from whitelist"""
    try:
        await execute_query('DELETE FROM whitelist WHERE guild_id = ? AND user_id = ?', (guild_id, user_id))
        return True
    except Exception as e:
        logger.error(f'Error removing from whitelist: {e}')
        return False

# ============= USER EMAILS =============

async def set_user_email(guild_id: int, user_id: int, email: str) -> bool:
    """Set user email for notifications"""
    try:
        query = '''
            INSERT INTO user_emails (guild_id, user_id, email) 
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET email = ?, updated_at = CURRENT_TIMESTAMP
        '''
        await execute_query(query, (guild_id, user_id, email, email))
        return True
    except Exception as e:
        logger.error(f'Error setting user email: {e}')
        return False

async def get_user_email(guild_id: int, user_id: int) -> Optional[str]:
    """Get user email"""
    try:
        result = await execute_query(
            'SELECT email FROM user_emails WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch_one=True
        )
        return result['email'] if result else None
    except Exception as e:
        logger.error(f'Error getting user email: {e}')
        return None

async def remove_user_email(guild_id: int, user_id: int) -> bool:
    """Remove user email"""
    try:
        await execute_query('DELETE FROM user_emails WHERE guild_id = ? AND user_id = ?', (guild_id, user_id))
        return True
    except Exception as e:
        logger.error(f'Error removing user email: {e}')
        return False

# ============= QUARANTINE =============

async def store_quarantine_roles(guild_id: int, user_id: int, role_ids: List[int]) -> bool:
    """Store roles before quarantine"""
    try:
        role_ids_json = json.dumps(role_ids)
        query = '''
            INSERT INTO quarantine_roles (guild_id, user_id, role_ids)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET role_ids = ?, quarantined_at = CURRENT_TIMESTAMP
        '''
        await execute_query(query, (guild_id, user_id, role_ids_json, role_ids_json))
        return True
    except Exception as e:
        logger.error(f'Error storing quarantine roles: {e}')
        return False

async def get_quarantine_roles(guild_id: int, user_id: int) -> List[int]:
    """Get stored quarantine roles"""
    try:
        result = await execute_query(
            'SELECT role_ids FROM quarantine_roles WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch_one=True
        )
        if result and result['role_ids']:
            return json.loads(result['role_ids'])
        return []
    except Exception as e:
        logger.error(f'Error getting quarantine roles: {e}')
        return []

# ============= VERIFICATION =============

async def create_verification(guild_id: int, user_id: int, verification_code: str) -> bool:
    """Create a new verification entry"""
    try:
        query = '''
            INSERT INTO verifications (guild_id, user_id, verification_code)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET verification_code = ?, created_at = CURRENT_TIMESTAMP
        '''
        await execute_query(query, (guild_id, user_id, verification_code, verification_code))
        return True
    except Exception as e:
        logger.error(f'Error creating verification: {e}')
        return False

async def get_verification(guild_id: int, user_id: int) -> Optional[dict]:
    """Get verification entry"""
    try:
        result = await execute_query(
            'SELECT * FROM verifications WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch_one=True
        )
        return result
    except Exception as e:
        logger.error(f'Error getting verification: {e}')
        return None

async def complete_verification(guild_id: int, user_id: int, roblox_id: int, roblox_username: str) -> bool:
    """Mark verification as complete"""
    try:
        query = '''
            UPDATE verifications 
            SET verified = 1, roblox_id = ?, roblox_username = ?, verified_at = CURRENT_TIMESTAMP
            WHERE guild_id = ? AND user_id = ?
        '''
        await execute_query(query, (roblox_id, roblox_username, guild_id, user_id))
        return True
    except Exception as e:
        logger.error(f'Error completing verification: {e}')
        return False

# ============= ROLE REQUESTS =============

async def create_role_request(guild_id: int, user_id: int, username: str, role_id: int, reason: str) -> Optional[int]:
    """Create a role request"""
    try:
        query = '''
            INSERT INTO role_requests (guild_id, user_id, username, role_id, reason)
            VALUES (?, ?, ?, ?, ?)
        '''
        request_id = await execute_query(query, (guild_id, user_id, username, role_id, reason))
        return request_id
    except Exception as e:
        logger.error(f'Error creating role request: {e}')
        return None

async def get_role_request(request_id: int) -> Optional[dict]:
    """Get a role request"""
    try:
        result = await execute_query(
            'SELECT * FROM role_requests WHERE id = ?',
            (request_id,),
            fetch_one=True
        )
        return result
    except Exception as e:
        logger.error(f'Error getting role request: {e}')
        return None

async def get_pending_role_requests(guild_id: int) -> List[dict]:
    """Get all pending role requests"""
    try:
        results = await execute_query(
            'SELECT * FROM role_requests WHERE guild_id = ? AND status = ? ORDER BY created_at DESC',
            (guild_id, 'pending'),
            fetch_all=True
        )
        return results or []
    except Exception as e:
        logger.error(f'Error getting pending role requests: {e}')
        return []

async def update_role_request_status(request_id: int, status: str, reviewed_by: int) -> bool:
    """Update role request status"""
    try:
        query = '''
            UPDATE role_requests 
            SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        '''
        await execute_query(query, (status, reviewed_by, request_id))
        return True
    except Exception as e:
        logger.error(f'Error updating role request status: {e}')
        return False

# ============= PARTNERSHIPS =============

async def create_partnership(guild_id: int, partner_guild_id: int, partner_server_name: str, contact: str, added_by: int) -> Optional[int]:
    """Create a partnership"""
    try:
        query = '''
            INSERT INTO partnerships (guild_id, partner_guild_id, partner_server_name, contact, added_by)
            VALUES (?, ?, ?, ?, ?)
        '''
        partnership_id = await execute_query(query, (guild_id, partner_guild_id, partner_server_name, contact, added_by))
        return partnership_id
    except Exception as e:
        logger.error(f'Error creating partnership: {e}')
        return None

async def get_partnership(partnership_id: int) -> Optional[dict]:
    """Get a partnership"""
    try:
        result = await execute_query(
            'SELECT * FROM partnerships WHERE id = ?',
            (partnership_id,),
            fetch_one=True
        )
        return result
    except Exception as e:
        logger.error(f'Error getting partnership: {e}')
        return None

async def get_partnerships(guild_id: int) -> List[dict]:
    """Get all partnerships for a guild"""
    try:
        results = await execute_query(
            'SELECT * FROM partnerships WHERE guild_id = ? ORDER BY created_at DESC',
            (guild_id,),
            fetch_all=True
        )
        return results or []
    except Exception as e:
        logger.error(f'Error getting partnerships: {e}')
        return []

async def delete_partnership(partnership_id: int) -> bool:
    """Delete a partnership"""
    try:
        await execute_query('DELETE FROM partnerships WHERE id = ?', (partnership_id,))
        return True
    except Exception as e:
        logger.error(f'Error deleting partnership: {e}')
        return False

# ============= THREAT LEVELS =============

async def set_threat_level(guild_id: int, level: int, reason: str, set_by: int) -> bool:
    """Set server threat level"""
    try:
        query = '''
            INSERT INTO threat_levels (guild_id, threat_level, reason, set_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(guild_id) DO UPDATE SET threat_level = ?, reason = ?, set_by = ?, set_at = CURRENT_TIMESTAMP
        '''
        await execute_query(query, (guild_id, level, reason, set_by, level, reason, set_by))
        return True
    except Exception as e:
        logger.error(f'Error setting threat level: {e}')
        return False

async def get_current_threat_level(guild_id: int) -> dict:
    """Get current threat level"""
    try:
        result = await execute_query(
            'SELECT threat_level, reason, set_by, set_at FROM threat_levels WHERE guild_id = ?',
            (guild_id,),
            fetch_one=True
        )
        if result:
            return result
        return {'threat_level': 0, 'reason': 'No threat', 'set_by': None, 'set_at': None}
    except Exception as e:
        logger.error(f'Error getting threat level: {e}')
        return {'threat_level': 0, 'reason': 'Error', 'set_by': None, 'set_at': None}