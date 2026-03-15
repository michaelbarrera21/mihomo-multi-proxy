import sqlite3
import os
from datetime import datetime

DB_PATH = "data.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Sources table
    c.execute('''
        CREATE TABLE IF NOT EXISTS sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT NOT NULL, -- 'subscription', 'text', 'vless', 'yaml'
            content TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Port mappings table
    c.execute('''
        CREATE TABLE IF NOT EXISTS port_mappings (
            proxy_name TEXT PRIMARY KEY,
            port INTEGER NOT NULL,
            last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_all_sources():
    conn = get_db_connection()
    sources = conn.execute('SELECT * FROM sources').fetchall()
    conn.close()
    return [dict(s) for s in sources]

def add_source(name, type, content):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('INSERT INTO sources (name, type, content) VALUES (?, ?, ?)', (name, type, content))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return new_id

def update_source_status(id, enabled):
    conn = get_db_connection()
    conn.execute('UPDATE sources SET enabled = ? WHERE id = ?', (enabled, id))
    conn.commit()
    conn.close()

def update_source(id, name, source_type, content):
    conn = get_db_connection()
    conn.execute('''
        UPDATE sources 
        SET name = ?, type = ?, content = ?, updated_at = ? 
        WHERE id = ?
    ''', (name, source_type, content, datetime.now(), id))
    conn.commit()
    conn.close()

def get_source_by_id(id):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM sources WHERE id = ?', (id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def delete_source(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM sources WHERE id = ?', (id,))
    conn.commit()
    conn.close()

def get_existing_port(proxy_name):
    conn = get_db_connection()
    row = conn.execute('SELECT port FROM port_mappings WHERE proxy_name = ?', (proxy_name,)).fetchone()
    conn.close()
    if row:
        return row['port']
    return None

def save_port_mapping(proxy_name, port):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO port_mappings (proxy_name, port, last_seen_at) 
        VALUES (?, ?, ?) 
        ON CONFLICT(proxy_name) DO UPDATE SET 
            last_seen_at=excluded.last_seen_at
    ''', (proxy_name, port, datetime.now()))
    conn.commit()
    conn.close()

def get_all_mappings():
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM port_mappings ORDER BY port').fetchall()
    conn.close()
    return [dict(r) for r in rows]

def delete_port_mapping(proxy_name):
    conn = get_db_connection()
    conn.execute('DELETE FROM port_mappings WHERE proxy_name = ?', (proxy_name,))
    conn.commit()
    conn.close()

def update_port_mapping(proxy_name, new_port):
    conn = get_db_connection()
    conn.execute('UPDATE port_mappings SET port = ?, last_seen_at = ? WHERE proxy_name = ?', 
                 (new_port, datetime.now(), proxy_name))
    conn.commit()
    conn.close()

def get_duplicate_ports():
    """返回有重复的端口及其对应的代理名称"""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT port, GROUP_CONCAT(proxy_name) as names, COUNT(*) as cnt 
        FROM port_mappings 
        GROUP BY port 
        HAVING cnt > 1
    ''').fetchall()
    conn.close()
    return [dict(r) for r in rows]

