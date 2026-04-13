import sqlite3
import os
import requests
import json
import time

# --- Configuration & Paths ---
APP_NAME = "stalker_converter"

# Check if we are in NextToken or standalone
if os.path.exists(f"apps/{APP_NAME}/backend"):
    BASE_DIR = f"apps/{APP_NAME}/backend"
else:
    # Standalone mode in Docker
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(BASE_DIR, "data")
DB_DIR = os.path.join(DATA_DIR, "db")
DB_PATH = os.path.join(DB_DIR, "app.db")

# Standard Headers for MAG Devices
MAG_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
    'X-User-Agent': 'Model: MAG250; Link: WiFi',
    'Accept': '*/*',
    'Connection': 'keep-alive'
}

# --- Database Helpers ---

def _get_db():
    """Open a connection with recommended settings."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def _init_db():
    """Initialize the database schema."""
    conn = _get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                portal_url TEXT NOT NULL,
                mac TEXT NOT NULL,
                sn TEXT DEFAULT '0000000000000',
                device_id TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Migration: Add user_id column if it doesn't exist
        cursor = conn.execute("PRAGMA table_info(subscriptions)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'user_id' not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN user_id TEXT DEFAULT 'global'")
        conn.commit()
    finally:
        conn.close()

# --- RPC Functions ---

def get_subscriptions(user_id: str = "global"):
    """List all saved portal configurations for a specific user."""
    print(f"[BACKEND_START] get_subscriptions for user_id={user_id}")
    _init_db()
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC", 
            (user_id,)
        ).fetchall()
        result = [dict(r) for r in rows]
        print(f"[BACKEND_SUCCESS] Found {len(result)} subscriptions")
        return result
    except Exception as e:
        print(f"[BACKEND_ERROR] get_subscriptions failed: {str(e)}")
        raise
    finally:
        conn.close()

def save_subscription(name: str, portal_url: str, mac: str, sn: str = '0000000000000', device_id: str = '', user_id: str = 'global'):
    """Save or update a portal configuration for a specific user."""
    print(f"[BACKEND_START] save_subscription: user={user_id}, name={name}, portal={portal_url}, mac={mac}")
    _init_db()
    conn = _get_db()
    try:
        # Simple upsert logic based on user_id, portal_url and mac
        existing = conn.execute(
            "SELECT id FROM subscriptions WHERE user_id = ? AND portal_url = ? AND mac = ?", 
            (user_id, portal_url, mac)
        ).fetchone()
        
        if existing:
            conn.execute(
                "UPDATE subscriptions SET name = ?, sn = ?, device_id = ? WHERE id = ?",
                (name, sn, device_id, existing['id'])
            )
            sub_id = existing['id']
            print(f"[BACKEND_STEP] Updated existing subscription ID {sub_id}")
        else:
            cursor = conn.execute(
                "INSERT INTO subscriptions (user_id, name, portal_url, mac, sn, device_id) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, name, portal_url, mac, sn, device_id)
            )
            sub_id = cursor.lastrowid
            print(f"[BACKEND_STEP] Created new subscription ID {sub_id}")
            
        conn.commit()
        row = conn.execute("SELECT * FROM subscriptions WHERE id = ?", (sub_id,)).fetchone()
        result = dict(row)
        print("[BACKEND_SUCCESS] save_subscription complete")
        return result
    except Exception as e:
        print(f"[BACKEND_ERROR] save_subscription failed: {str(e)}")
        raise
    finally:
        conn.close()

def delete_subscription(id: int, user_id: str = 'global'):
    """Delete a portal configuration for a specific user."""
    print(f"[BACKEND_START] delete_subscription: id={id}, user={user_id}")
    conn = _get_db()
    try:
        conn.execute("DELETE FROM subscriptions WHERE id = ? AND user_id = ?", (id, user_id))
        conn.commit()
        print(f"[BACKEND_SUCCESS] Deleted subscription {id}")
        return {"success": True, "id": id}
    except Exception as e:
        print(f"[BACKEND_ERROR] delete_subscription failed: {str(e)}")
        raise
    finally:
        conn.close()

# --- Stalker API Implementation ---

def _stalker_request(portal_url: str, mac: str, params: dict, token: str = None):
    """Helper to make requests to Stalker portal."""
    base_url = portal_url.rstrip('/')
    # Avoid doubling up portal.php if user included it in the portal_url
    if "/portal.php" in base_url:
        url = base_url
    else:
        url = f"{base_url}/portal.php"
    
    headers = MAG_HEADERS.copy()
    headers['Cookie'] = f"mac={mac}"
    if token:
        headers['Authorization'] = f"Bearer {token}"
    
    # Stalker often requires JsHttpRequest
    if 'JsHttpRequest' not in params:
        params['JsHttpRequest'] = '1-json'
        
    try:
        print(f"[BACKEND_STEP] Requesting URL: {url} with action={params.get('action')}")
        response = requests.get(url, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        
        # Stalker sometimes returns JSON inside a JsHttpRequest wrapper
        # usually it looks like: { "js": { ... } }
        data = response.json()
        if isinstance(data, dict) and "js" in data:
            return data["js"]
        return data
    except Exception as e:
        print(f"[BACKEND_ERROR] Stalker request failed for {url}: {str(e)}")
        raise Exception(f"Portal request failed: {str(e)}")

def test_portal_connection(portal_url: str, mac: str, sn: str = '0000000000000', device_id: str = ''):
    """Perform handshake and profile check to verify credentials."""
    print(f"[BACKEND_START] test_portal_connection: {portal_url}, mac={mac}")
    try:
        # 1. Handshake
        print("[BACKEND_STEP] Performing handshake...")
        handshake_params = {
            "type": "stb",
            "action": "handshake",
            "JsHttpRequest": "1-json"
        }
        hs_data = _stalker_request(portal_url, mac, handshake_params)
        token = hs_data.get("token")
        if not token:
            print("[BACKEND_ERROR] No token received during handshake")
            return {"success": False, "message": "Failed to get token from portal."}
            
        print(f"[BACKEND_STEP] Handshake success, token: {token[:5]}...")
        
        # 2. Get Profile
        print("[BACKEND_STEP] Verifying profile...")
        profile_params = {
            "type": "stb",
            "action": "get_profile",
            "token": token,
            "stb_type": "MAG250",
            "sn": sn,
            "device_id": device_id,
            "JsHttpRequest": "1-json"
        }
        profile_data = _stalker_request(portal_url, mac, profile_params, token=token)
        
        if not profile_data:
            return {"success": False, "message": "Portal returned empty profile."}
            
        print("[BACKEND_SUCCESS] Connection verified")
        return {"success": True, "message": "Successfully connected to portal."}
        
    except Exception as e:
        print(f"[BACKEND_ERROR] test_portal_connection failed: {str(e)}")
        return {"success": False, "message": str(e)}

def convert_stalker_to_m3u(portal_url: str, mac: str, sn: str = '0000000000000', device_id: str = ''):
    """Fetch channels and format as M3U."""
    print(f"[BACKEND_START] convert_stalker_to_m3u: {portal_url}, mac={mac}")
    try:
        # 1. Handshake
        print("[BACKEND_STEP] Handshake...")
        hs_params = {"type": "stb", "action": "handshake"}
        hs_data = _stalker_request(portal_url, mac, hs_params)
        token = hs_data.get("token")
        if not token:
            raise Exception("Handshake failed: No token received.")
            
        # 2. Profile check (optional but recommended for session)
        print("[BACKEND_STEP] Profile check...")
        _stalker_request(portal_url, mac, {
            "type": "stb", 
            "action": "get_profile", 
            "token": token,
            "sn": sn,
            "device_id": device_id
        }, token=token)
        
        # 3. Get Channels
        print("[BACKEND_STEP] Fetching channels...")
        channel_params = {
            "type": "itv",
            "action": "get_all_channels",
            "token": token,
            "JsHttpRequest": "1-json"
        }
        channel_data = _stalker_request(portal_url, mac, channel_params, token=token)
        
        channels = []
        if isinstance(channel_data, list):
            channels = channel_data
        elif isinstance(channel_data, dict) and "data" in channel_data:
            channels = channel_data["data"]
            
        print(f"[BACKEND_STEP] Found {len(channels)} channels")
        
        # 4. Format as M3U
        print("[BACKEND_STEP] Formatting M3U content...")
        m3u_lines = ["#EXTM3U"]
        
        for ch in channels:
            name = ch.get("name", "Unknown Channel")
            cmd = ch.get("cmd", "")
            if not cmd:
                continue
            
            # Extract stream ID from cmd (e.g., "ffmpeg http://..." or "ffrt http://...")
            # Stalker 'cmd' usually looks like: "ffmpeg http://localhost/ch/12345" or "ffrt 12345"
            # We want to extract the numeric ID or the last part of the path.
            stream_id = ""
            if " " in cmd:
                parts = cmd.split(" ")
                url_part = parts[-1]
                if "/" in url_part:
                    stream_id = url_part.split("/")[-1]
                else:
                    stream_id = url_part
            
            if not stream_id:
                # Fallback to create_link if we can't parse a direct ID
                stream_url = f"{portal_url.rstrip('/')}/portal.php?type=itv&action=create_link&cmd={cmd}&token={token}"
            else:
                # Construct the direct play URL format common for many providers:
                # http://domain:port/play/live.php?mac=MAC&stream=ID&extension=ts
                # We'll use the domain/port from the portal_url
                from urllib.parse import urlparse
                parsed = urlparse(portal_url)
                base_host = f"{parsed.scheme}://{parsed.netloc}"
                stream_url = f"{base_host}/play/live.php?mac={mac}&stream={stream_id}&extension=ts"
            
            # Additional metadata if available
            logo = ch.get("logo", "")
            group = ch.get("tv_genre_name", "General")
            
            inf_line = f'#EXTINF:-1 tvg-logo="{logo}" group-title="{group}",{name}'
            m3u_lines.append(inf_line)
            m3u_lines.append(stream_url)
            
        m3u_content = "\n".join(m3u_lines)
        
        print(f"[BACKEND_SUCCESS] M3U conversion complete: {len(channels)} channels")
        return {
            "m3u_content": m3u_content,
            "channel_count": len(channels),
            "portal_name": portal_url
        }
        
    except Exception as e:
        print(f"[BACKEND_ERROR] convert_stalker_to_m3u failed: {str(e)}")
        raise

# Re-export all RPC functions
__all__ = [
    "get_subscriptions", 
    "save_subscription", 
    "delete_subscription", 
    "convert_stalker_to_m3u", 
    "test_portal_connection"
]
