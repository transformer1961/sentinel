"""
SENTINEL SECURITY BOT v2.0 - DATABASE MODULE
Complete database operations for all bot features
"""

import aiosqlite
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger('SecurityBot.Database')

DATABASE_PATH = 'sentinel_security.db'

# ============= INITIALIZATION =============

async def init_database():
    """Initialize all database tables"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Server configurations
        await db.execute('''
            CREATE TABLE IF NOT EXISTS server_config (
                guild_id INTEGER PRIMARY KEY,
                log_channel_id INTEGER,
                quarantine_role_id INTEGER,
                verified_role_id INTEGER,
                unverified_role_id INTEGER,
                verification_channel_id INTEGER,
                verification_enabled BOOLEAN DEFAULT 0,
                lockdown_enabled BOOLEAN DEFAULT 0,
                onduty_role_id INTEGER,
                allstaff_role_id INTEGER,
                daily_reports_enabled BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Whitelists
        await db.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                entity_type TEXT DEFAULT 'user',
                added_by INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id)
            )
        ''')
        
        # Threat levels
        await db.execute('''
            CREATE TABLE IF NOT EXISTS threat_levels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                threat_level INTEGER NOT NULL,
                set_by INTEGER,
                set_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Activity logs
        await db.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                user_id INTEGER,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # User emails
        await db.execute('''
            CREATE TABLE IF NOT EXISTS user_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                verified BOOLEAN DEFAULT 0,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id)
            )
        ''')
        
        # Shifts
        await db.execute('''
            CREATE TABLE IF NOT EXISTS shifts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                department TEXT,
                callsign TEXT,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                duration_seconds INTEGER,
                force_ended BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Departments
        await db.execute('''
            CREATE TABLE IF NOT EXISTS departments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                department_head INTEGER,
                role_id INTEGER,
                suspended BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, name)
            )
        ''')
        
        # Department members
        await db.execute('''
            CREATE TABLE IF NOT EXISTS department_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                department TEXT NOT NULL,
                status TEXT DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id, department)
            )
        ''')
        
        # Department join requests
        await db.execute('''
            CREATE TABLE IF NOT EXISTS department_join_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                department TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                reason TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                processed_by INTEGER
            )
        ''')
        
        # Role requests
        await db.execute('''
            CREATE TABLE IF NOT EXISTS role_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed_at TIMESTAMP,
                processed_by INTEGER
            )
        ''')
        
        # Partnerships
        await db.execute('''
            CREATE TABLE IF NOT EXISTS partnerships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                partner_guild_id INTEGER NOT NULL,
                guild_name TEXT NOT NULL,
                description TEXT,
                added_by INTEGER,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, partner_guild_id)
            )
        ''')
        
        # Member tiers
        await db.execute('''
            CREATE TABLE IF NOT EXISTS member_tiers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                tier INTEGER DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(guild_id, user_id)
            )
        ''')
        
        # Verifications (Roblox)
        await db.execute('''
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
                UNIQUE(guild_id, user_id)
            )
        ''')
        
        await db.commit()
        logger.info("✅ Database initialized successfully")

# ============= SERVER CONFIG =============

async def get_server_config(guild_id: int) -> Optional[Dict[str, Any]]:
    """Get server configuration"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            'SELECT * FROM server_config WHERE guild_id = ?',
            (guild_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def set_server_config(guild_id: int, **kwargs):
    """Set server configuration fields"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        fields = ', '.join(f"{k} = ?" for k in kwargs.keys())
        values = list(kwargs.values()) + [guild_id]
        
        await db.execute(f'''
            INSERT INTO server_config (guild_id, {', '.join(kwargs.keys())})
            VALUES (?, {', '.join('?' * len(kwargs))})
            ON CONFLICT(guild_id) DO UPDATE SET {fields}, updated_at = CURRENT_TIMESTAMP
        ''', [guild_id] + list(kwargs.values()) + values[:-1])
        
        await db.commit()

async def update_server_field(guild_id: int, field: str, value: Any):
    """Update a single server config field"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(f'''
            INSERT INTO server_config (guild_id, {field})
            VALUES (?, ?)
            ON CONFLICT(guild_id) DO UPDATE SET {field} = ?, updated_at = CURRENT_TIMESTAMP
        ''', (guild_id, value, value))
        await db.commit()

async def load_all_configs() -> Dict[int, Dict[str, Any]]:
    """Load all server configs"""
    configs = {}
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('SELECT * FROM server_config') as cursor:
            async for row in cursor:
                configs[row['guild_id']] = dict(row)
    return configs

# ============= WHITELIST =============

async def add_to_whitelist(guild_id: int, user_id: int, entity_type: str = 'user', added_by: int = None):
    """Add user to whitelist"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT OR IGNORE INTO whitelist (guild_id, user_id, entity_type, added_by)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, user_id, entity_type, added_by))
        await db.commit()

async def remove_from_whitelist(guild_id: int, user_id: int) -> bool:
    """Remove user from whitelist"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute('''
            DELETE FROM whitelist WHERE guild_id = ? AND user_id = ?
        ''', (guild_id, user_id))
        await db.commit()
        return cursor.rowcount > 0

async def is_whitelisted(guild_id: int, user_id: int) -> bool:
    """Check if user is whitelisted"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute('''
            SELECT 1 FROM whitelist WHERE guild_id = ? AND user_id = ?
        ''', (guild_id, user_id)) as cursor:
            return await cursor.fetchone() is not None

async def load_all_whitelists() -> Dict[int, set]:
    """Load all whitelists"""
    whitelists = defaultdict(set)
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute('SELECT guild_id, user_id FROM whitelist') as cursor:
            async for row in cursor:
                whitelists[row[0]].add(row[1])
    return whitelists

# ============= THREAT LEVELS =============

async def set_threat_level(guild_id: int, level: int, set_by: int = None):
    """Set threat level"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO threat_levels (guild_id, threat_level, set_by)
            VALUES (?, ?, ?)
        ''', (guild_id, level, set_by))
        await db.commit()

async def get_current_threat_level(guild_id: int) -> Optional[Dict[str, Any]]:
    """Get current threat level"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM threat_levels
            WHERE guild_id = ?
            ORDER BY set_at DESC
            LIMIT 1
        ''', (guild_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

# ============= ACTIVITY LOGS =============

async def add_log(guild_id: int, category: str, user_id: int = None, details: Dict = None):
    """Add activity log"""
    import json
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO activity_logs (guild_id, category, user_id, details)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, category, user_id, json.dumps(details) if details else None))
        await db.commit()

async def get_logs(guild_id: int, category: str = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Get activity logs"""
    import json
    logs = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        if category:
            query = 'SELECT * FROM activity_logs WHERE guild_id = ? AND category = ? ORDER BY timestamp DESC LIMIT ?'
            params = (guild_id, category, limit)
        else:
            query = 'SELECT * FROM activity_logs WHERE guild_id = ? ORDER BY timestamp DESC LIMIT ?'
            params = (guild_id, limit)
        
        async with db.execute(query, params) as cursor:
            async for row in cursor:
                log_dict = dict(row)
                if log_dict.get('details'):
                    try:
                        log_dict['details'] = json.loads(log_dict['details'])
                    except:
                        pass
                logs.append(log_dict)
    return logs

async def get_recent_alerts(guild_id: int, hours: int = 6) -> List[Dict[str, Any]]:
    """Get recent security alerts"""
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM activity_logs
            WHERE guild_id = ? AND category = 'security_alert' AND timestamp > ?
            ORDER BY timestamp DESC
        ''', (guild_id, cutoff)) as cursor:
            return [dict(row) async for row in cursor]

async def delete_old_logs(cutoff: datetime):
    """Delete logs older than cutoff date"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            DELETE FROM activity_logs WHERE timestamp < ?
        ''', (cutoff.isoformat(),))
        await db.commit()

# ============= USER EMAILS =============

async def set_user_email(guild_id: int, user_id: int, email: str):
    """Set user email"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO user_emails (guild_id, user_id, email)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET email = ?, added_at = CURRENT_TIMESTAMP
        ''', (guild_id, user_id, email, email))
        await db.commit()

async def get_user_email(guild_id: int, user_id: int) -> Optional[str]:
    """Get user email"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute('''
            SELECT email FROM user_emails WHERE guild_id = ? AND user_id = ?
        ''', (guild_id, user_id)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

async def remove_user_email(guild_id: int, user_id: int) -> bool:
    """Remove user email"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute('''
            DELETE FROM user_emails WHERE guild_id = ? AND user_id = ?
        ''', (guild_id, user_id))
        await db.commit()
        return cursor.rowcount > 0

# ============= SHIFTS =============

async def create_shift(guild_id: int, user_id: int, department: str = None, start_time: datetime = None, callsign: str = None):
    """Create new shift"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO shifts (guild_id, user_id, department, callsign, start_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (guild_id, user_id, department, callsign, (start_time or datetime.now()).isoformat()))
        await db.commit()

async def end_shift(guild_id: int, user_id: int, end_time: datetime, duration: float, force_ended: bool = False):
    """End active shift"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            UPDATE shifts
            SET end_time = ?, duration_seconds = ?, force_ended = ?
            WHERE guild_id = ? AND user_id = ? AND end_time IS NULL
        ''', (end_time.isoformat(), int(duration), force_ended, guild_id, user_id))
        await db.commit()

async def get_shift_history(guild_id: int, user_id: int = None, limit: int = 10) -> List[Dict[str, Any]]:
    """Get shift history"""
    shifts = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        if user_id:
            query = '''
                SELECT * FROM shifts
                WHERE guild_id = ? AND user_id = ?
                ORDER BY start_time DESC
                LIMIT ?
            '''
            params = (guild_id, user_id, limit)
        else:
            query = '''
                SELECT * FROM shifts
                WHERE guild_id = ?
                ORDER BY start_time DESC
                LIMIT ?
            '''
            params = (guild_id, limit)
        
        async with db.execute(query, params) as cursor:
            async for row in cursor:
                shifts.append(dict(row))
    return shifts

async def detect_shift_violations(guild_id: int, hours: int = 24) -> List[Dict[str, Any]]:
    """Detect shift violations in time period"""
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    violations = []
    
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Find shifts longer than 12 hours
        async with db.execute('''
            SELECT user_id, department, duration_seconds, start_time
            FROM shifts
            WHERE guild_id = ? AND start_time > ? AND duration_seconds > 43200
        ''', (guild_id, cutoff)) as cursor:
            async for row in cursor:
                violations.append({
                    'user_id': row['user_id'],
                    'type': 'excessive_shift_duration',
                    'department': row['department'],
                    'timestamp': row['start_time']
                })
        
        # Find force-ended shifts
        async with db.execute('''
            SELECT user_id, department, start_time
            FROM shifts
            WHERE guild_id = ? AND start_time > ? AND force_ended = 1
        ''', (guild_id, cutoff)) as cursor:
            async for row in cursor:
                violations.append({
                    'user_id': row['user_id'],
                    'type': 'force_ended_shift',
                    'department': row['department'],
                    'timestamp': row['start_time']
                })
    
    return violations

async def detect_shift_overlaps(guild_id: int) -> List[Dict[str, Any]]:
    """Detect overlapping shifts"""
    overlaps = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT s1.user_id as user1, s2.user_id as user2, s1.department
            FROM shifts s1
            JOIN shifts s2 ON s1.guild_id = s2.guild_id
                AND s1.department = s2.department
                AND s1.id != s2.id
                AND s1.end_time IS NULL
                AND s2.end_time IS NULL
            WHERE s1.guild_id = ?
        ''', (guild_id,)) as cursor:
            async for row in cursor:
                overlaps.append({
                    'users': [row['user1'], row['user2']],
                    'department': row['department']
                })
    return overlaps

async def generate_shift_report(guild_id: int, days: int = 7) -> Dict[str, Any]:
    """Generate shift statistics report"""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Total shifts
        async with db.execute('''
            SELECT COUNT(*) FROM shifts
            WHERE guild_id = ? AND start_time > ? AND end_time IS NOT NULL
        ''', (guild_id, cutoff)) as cursor:
            total_shifts = (await cursor.fetchone())[0]
        
        # Total hours
        async with db.execute('''
            SELECT SUM(duration_seconds) FROM shifts
            WHERE guild_id = ? AND start_time > ? AND end_time IS NOT NULL
        ''', (guild_id, cutoff)) as cursor:
            total_seconds = (await cursor.fetchone())[0] or 0
            total_hours = total_seconds / 3600
        
        # Average duration
        avg_duration = total_hours / total_shifts if total_shifts > 0 else 0
        
        # Top user
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT user_id, COUNT(*) as shift_count
            FROM shifts
            WHERE guild_id = ? AND start_time > ? AND end_time IS NOT NULL
            GROUP BY user_id
            ORDER BY shift_count DESC
            LIMIT 1
        ''', (guild_id, cutoff)) as cursor:
            row = await cursor.fetchone()
            top_user = f"User {row['user_id']}" if row else "N/A"
        
        # Top department
        async with db.execute('''
            SELECT department, COUNT(*) as shift_count
            FROM shifts
            WHERE guild_id = ? AND start_time > ? AND end_time IS NOT NULL AND department IS NOT NULL
            GROUP BY department
            ORDER BY shift_count DESC
            LIMIT 1
        ''', (guild_id, cutoff)) as cursor:
            row = await cursor.fetchone()
            top_dept = row['department'] if row else "N/A"
        
        return {
            'total_shifts': total_shifts,
            'total_hours': total_hours,
            'avg_duration': avg_duration,
            'top_user': top_user,
            'top_dept': top_dept
        }

# ============= DEPARTMENTS =============

async def create_department(guild_id: int, name: str, description: str = None, role_id: int = None):
    """Create new department"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO departments (guild_id, name, description, role_id)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, name, description, role_id))
        await db.commit()

async def get_department(guild_id: int, name: str) -> Optional[Dict[str, Any]]:
    """Get department info"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM departments WHERE guild_id = ? AND name = ?
        ''', (guild_id, name)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_all_departments(guild_id: int) -> List[Dict[str, Any]]:
    """Get all departments"""
    departments = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM departments WHERE guild_id = ? ORDER BY name
        ''', (guild_id,)) as cursor:
            async for row in cursor:
                departments.append(dict(row))
    return departments

async def set_department_head(guild_id: int, department: str, user_id: int):
    """Set department head"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            UPDATE departments SET department_head = ?
            WHERE guild_id = ? AND name = ?
        ''', (user_id, guild_id, department))
        await db.commit()

async def update_department_field(guild_id: int, department: str, field: str, value: Any):
    """Update department field"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(f'''
            UPDATE departments SET {field} = ?
            WHERE guild_id = ? AND name = ?
        ''', (value, guild_id, department))
        await db.commit()

async def add_department_member(guild_id: int, user_id: int, department: str, status: str = 'member'):
    """Add member to department"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT OR REPLACE INTO department_members (guild_id, user_id, department, status)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, user_id, department, status))
        await db.commit()

async def is_department_member(guild_id: int, user_id: int, department: str) -> bool:
    """Check if user is department member"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        async with db.execute('''
            SELECT 1 FROM department_members
            WHERE guild_id = ? AND user_id = ? AND department = ?
        ''', (guild_id, user_id, department)) as cursor:
            return await cursor.fetchone() is not None

async def get_department_members(guild_id: int, department: str) -> List[Dict[str, Any]]:
    """Get department members"""
    members = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM department_members
            WHERE guild_id = ? AND department = ?
        ''', (guild_id, department)) as cursor:
            async for row in cursor:
                members.append(dict(row))
    return members

async def get_department_shifts(guild_id: int, department: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Get shifts for department"""
    shifts = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM shifts
            WHERE guild_id = ? AND department = ?
            ORDER BY start_time DESC
            LIMIT ?
        ''', (guild_id, department, limit)) as cursor:
            async for row in cursor:
                shifts.append(dict(row))
    return shifts

# ============= DEPARTMENT JOIN REQUESTS =============

async def create_department_join_request(guild_id: int, user_id: int, department: str, status: str = 'pending') -> int:
    """Create join request"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute('''
            INSERT INTO department_join_requests (guild_id, user_id, department, status)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, user_id, department, status))
        await db.commit()
        return cursor.lastrowid

async def get_department_join_request(guild_id: int, request_id: int) -> Optional[Dict[str, Any]]:
    """Get join request by ID"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM department_join_requests
            WHERE guild_id = ? AND id = ?
        ''', (guild_id, request_id)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def get_department_join_requests(guild_id: int, department: str = None, status: str = None) -> List[Dict[str, Any]]:
    """Get join requests"""
    requests = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        if department and status:
            query = 'SELECT * FROM department_join_requests WHERE guild_id = ? AND department = ? AND status = ?'
            params = (guild_id, department, status)
        elif status:
            query = 'SELECT * FROM department_join_requests WHERE guild_id = ? AND status = ?'
            params = (guild_id, status)
        else:
            query = 'SELECT * FROM department_join_requests WHERE guild_id = ?'
            params = (guild_id,)
        
        async with db.execute(query, params) as cursor:
            async for row in cursor:
                requests.append(dict(row))
    return requests

async def update_department_join_request_status(guild_id: int, request_id: int, status: str, reason: str = None):
    """Update join request status"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            UPDATE department_join_requests
            SET status = ?, reason = ?, processed_at = CURRENT_TIMESTAMP
            WHERE guild_id = ? AND id = ?
        ''', (status, reason, guild_id, request_id))
        await db.commit()

# ============= ROLE REQUESTS =============

async def add_role_request(guild_id: int, user_id: int, role_id: int, status: str = 'pending'):
    """Add role request"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO role_requests (guild_id, user_id, role_id, status)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, user_id, role_id, status))
        await db.commit()

async def get_role_requests(guild_id: int, status: str = None) -> List[Dict[str, Any]]:
    """Get role requests"""
    requests = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        if status:
            query = 'SELECT * FROM role_requests WHERE guild_id = ? AND status = ?'
            params = (guild_id, status)
        else:
            query = 'SELECT * FROM role_requests WHERE guild_id = ?'
            params = (guild_id,)
        
        async with db.execute(query, params) as cursor:
            async for row in cursor:
                requests.append(dict(row))
    return requests

async def update_role_request_status(guild_id: int, user_id: int, role_id: int, status: str):
    """Update role request status"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            UPDATE role_requests
            SET status = ?, processed_at = CURRENT_TIMESTAMP
            WHERE guild_id = ? AND user_id = ? AND role_id = ?
        ''', (status, guild_id, user_id, role_id))
        await db.commit()

# ============= PARTNERSHIPS =============

async def add_partnership(guild_id: int, partner_guild_id: int, guild_name: str, description: str = None):
    """Add partnership"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT OR IGNORE INTO partnerships (guild_id, partner_guild_id, guild_name, description)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, partner_guild_id, guild_name, description))
        await db.commit()

async def remove_partnership(guild_id: int, partner_guild_id: int) -> bool:
    """Remove partnership"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute('''
            DELETE FROM partnerships WHERE guild_id = ? AND partner_guild_id = ?
        ''', (guild_id, partner_guild_id))
        await db.commit()
        return cursor.rowcount > 0

async def get_partnerships(guild_id: int) -> List[Dict[str, Any]]:
    """Get all partnerships"""
    partnerships = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM partnerships WHERE guild_id = ? ORDER BY added_at DESC
        ''', (guild_id,)) as cursor:
            async for row in cursor:
                partnerships.append(dict(row))
    return partnerships

# ============= MEMBER TIERS =============

async def get_member_tier(guild_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Get member tier"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM member_tiers WHERE guild_id = ? AND user_id = ?
        ''', (guild_id, user_id)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def set_member_tier(guild_id: int, user_id: int, tier: int):
    """Set member tier"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO member_tiers (guild_id, user_id, tier)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET tier = ?, updated_at = CURRENT_TIMESTAMP
        ''', (guild_id, user_id, tier, tier))
        await db.commit()

# ============= VERIFICATIONS (ROBLOX) =============

async def create_verification(guild_id: int, user_id: int, verification_code: str):
    """Create verification entry"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            INSERT INTO verifications (guild_id, user_id, verification_code)
            VALUES (?, ?, ?)
            ON CONFLICT(guild_id, user_id) DO UPDATE SET verification_code = ?, created_at = CURRENT_TIMESTAMP
        ''', (guild_id, user_id, verification_code, verification_code))
        await db.commit()

async def get_verification(guild_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Get verification entry"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute('''
            SELECT * FROM verifications WHERE guild_id = ? AND user_id = ?
        ''', (guild_id, user_id)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def complete_verification(guild_id: int, user_id: int, roblox_id: int, roblox_username: str):
    """Complete verification"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute('''
            UPDATE verifications
            SET roblox_id = ?, roblox_username = ?, verified = 1, verified_at = CURRENT_TIMESTAMP
            WHERE guild_id = ? AND user_id = ?
        ''', (roblox_id, roblox_username, guild_id, user_id))
        await db.commit()

# ============= UTILITY FUNCTIONS =============

async def cleanup_database():
    """Clean up old/expired data"""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Delete old unverified verifications (older than 30 days)
        await db.execute('''
            DELETE FROM verifications
            WHERE verified = 0 AND created_at < datetime('now', '-30 days')
        ''')
        
        # Delete old processed requests (older than 90 days)
        await db.execute('''
            DELETE FROM department_join_requests
            WHERE status != 'pending' AND processed_at < datetime('now', '-90 days')
        ''')
        
        await db.execute('''
            DELETE FROM role_requests
            WHERE status != 'pending' AND processed_at < datetime('now', '-90 days')
        ''')
        
        await db.commit()

async def get_database_stats() -> Dict[str, int]:
    """Get database statistics"""
    stats = {}
    async with aiosqlite.connect(DATABASE_PATH) as db:
        tables = [
            'server_config', 'whitelist', 'threat_levels', 'activity_logs',
            'user_emails', 'shifts', 'departments', 'department_members',
            'department_join_requests', 'role_requests', 'partnerships',
            'member_tiers', 'verifications'
        ]
        
        for table in tables:
            async with db.execute(f'SELECT COUNT(*) FROM {table}') as cursor:
                count = (await cursor.fetchone())[0]
                stats[table] = count
    
    return stats