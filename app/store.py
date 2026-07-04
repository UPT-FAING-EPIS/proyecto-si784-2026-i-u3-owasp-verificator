from threading import Lock
from datetime import datetime, timezone
from typing import Optional
import os
import uuid
import json
import sqlite3
import hashlib
from pathlib import Path

from app.models import Scan, Finding

class APIToken:
    def __init__(self, token: str, user: str, created_at=None, last_used=None, is_active=True):
        self.token = token
        self.user = user
        self.created_at = created_at or datetime.now(timezone.utc)
        self.last_used = last_used or datetime.now(timezone.utc)
        self.is_active = is_active

class InMemoryScanStore:
    def __init__(self) -> None:
        self._scans: list[Scan] = []
        self._next_id = 1
        self._lock = Lock()
        self._accesses: list[dict] = []
        self._api_tokens: dict[str, APIToken] = {}
        self._admin_sessions: dict[str, dict] = {}
        
        # Load environment database settings
        self._db_type = os.getenv("DB_TYPE", "sqlite" if os.getenv("APP_ENV") == "test" else "mysql").lower()
        
        # --- CONEXIÓN DE BASE DE DATOS LOCAL ---
        self._mysql_host = os.getenv("MYSQL_HOST", "localhost")
        self._mysql_user = os.getenv("MYSQL_USER", "root")
        self._mysql_password = os.getenv("MYSQL_PASSWORD", "")  # Cambia por tu contraseña local de MySQL si tiene
        self._mysql_db = os.getenv("MYSQL_DATABASE", "owasp_verificador")
        
        # --- CONEXIÓN DE BASE DE DATOS DE LA VM (PRODUCCIÓN - COMENTADA) ---
        # self._mysql_host = os.getenv("MYSQL_HOST", "38.250.116.71")
        # self._mysql_user = os.getenv("MYSQL_USER", "root")
        # self._mysql_password = os.getenv("MYSQL_PASSWORD", "upt2026")
        # self._mysql_db = os.getenv("MYSQL_DATABASE", "owasp_verificador")
        
        try:
            self._mysql_port = int(os.getenv("MYSQL_PORT", "3306"))
        except ValueError:
            self._mysql_port = 3306

        # prepare persistent data directory and files for SQLite fallback
        self._data_path = Path(os.getenv("APP_DATA_PATH", Path(__file__).parent.parent)) / "data"
        self._data_path.mkdir(parents=True, exist_ok=True)
        self._db_path = self._data_path / "scans.sqlite3"
        self._scans_file = self._data_path / "scans.json"
        
        self._init_db()
        self._init_tokens()
        try:
            self._load_persisted()
        except Exception as e:
            err_load = e

    def _get_mysql_conn(self):
        import pymysql
        return pymysql.connect(
            host=self._mysql_host,
            port=self._mysql_port,
            user=self._mysql_user,
            password=self._mysql_password,
            database=self._mysql_db,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )

    def _init_db(self) -> None:
        """Create MySQL or SQLite schema on first run."""
        if self._db_type == "mysql":
            import pymysql
            # Connect first to MySQL server without db to create the database if not exists
            conn = pymysql.connect(
                host=self._mysql_host,
                port=self._mysql_port,
                user=self._mysql_user,
                password=self._mysql_password,
                charset='utf8mb4'
            )
            try:
                with conn.cursor() as cursor:
                    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self._mysql_db} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                conn.commit()
            finally:
                conn.close()

            # Now connect to database to create tables
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS scans (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            target_type VARCHAR(50) NOT NULL,
                            target_value LONGTEXT NOT NULL,
                            status VARCHAR(50) NOT NULL,
                            score INT NOT NULL,
                            created_at DATETIME NOT NULL,
                            findings_json LONGTEXT NOT NULL,
                            username VARCHAR(255) NULL
                        ) ENGINE=InnoDB
                        """
                    )
                    try:
                        cursor.execute("ALTER TABLE scans ADD COLUMN username VARCHAR(255) NULL")
                    except Exception:
                        pass
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS api_tokens (
                            token VARCHAR(255) PRIMARY KEY,
                            user VARCHAR(255) NOT NULL,
                            created_at DATETIME NOT NULL,
                            last_used DATETIME NOT NULL,
                            is_active TINYINT(1) NOT NULL DEFAULT 1
                        ) ENGINE=InnoDB
                        """
                    )
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS access_logs (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            path VARCHAR(255) NOT NULL,
                            ip VARCHAR(50) NOT NULL,
                            user_agent TEXT NOT NULL,
                            username VARCHAR(255) NULL,
                            created_at DATETIME NOT NULL
                        ) ENGINE=InnoDB
                        """
                    )
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS admin_sessions (
                            session_id VARCHAR(255) PRIMARY KEY,
                            username VARCHAR(255) NOT NULL,
                            created_at DATETIME NOT NULL,
                            expires_at DOUBLE NOT NULL
                        ) ENGINE=InnoDB
                        """
                    )
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS users (
                            username VARCHAR(255) PRIMARY KEY,
                            password_hash VARCHAR(255) NOT NULL,
                            role VARCHAR(50) NOT NULL DEFAULT 'user',
                            created_at DATETIME NOT NULL
                        ) ENGINE=InnoDB
                        """
                    )
                    try:
                        cursor.execute("ALTER TABLE users ADD COLUMN github_token VARCHAR(255) NULL")
                    except Exception:
                        pass
                    try:
                        cursor.execute("ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL")
                    except Exception:
                        pass
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS system_settings (
                            setting_key VARCHAR(255) PRIMARY KEY,
                            setting_value VARCHAR(255) NOT NULL
                        ) ENGINE=InnoDB
                        """
                    )
                    cursor.execute(
                        "INSERT IGNORE INTO system_settings (setting_key, setting_value) VALUES ('donate_btn_enabled', 'true')"
                    )
                    admin_pass_hash = hashlib.sha256("123456".encode("utf-8")).hexdigest()
                    cursor.execute(
                        "INSERT IGNORE INTO users (username, password_hash, role, created_at, email) VALUES ('admin', %s, 'admin', NOW(), 'admin@localhost')",
                        (admin_pass_hash,)
                    )
                conn.commit()
            finally:
                conn.close()
        else:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY,
                        target_type TEXT NOT NULL,
                        target_value TEXT NOT NULL,
                        status TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        findings_json TEXT NOT NULL,
                        username TEXT NULL
                    )
                    """
                )
                try:
                    conn.execute("ALTER TABLE scans ADD COLUMN username TEXT NULL")
                except Exception:
                    pass
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user',
                        created_at TEXT NOT NULL
                    )
                    """
                )
                try:
                    conn.execute("ALTER TABLE users ADD COLUMN github_token TEXT NULL")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE users ADD COLUMN email TEXT NULL")
                except Exception:
                    pass
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS system_settings (
                        setting_key TEXT PRIMARY KEY,
                        setting_value TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    "INSERT OR IGNORE INTO system_settings (setting_key, setting_value) VALUES ('donate_btn_enabled', 'true')"
                )
                admin_pass_hash = hashlib.sha256("123456".encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT OR IGNORE INTO users (username, password_hash, role, created_at, email) VALUES ('admin', ?, 'admin', ?, 'admin@localhost')",
                    (admin_pass_hash, datetime.now(timezone.utc).isoformat())
                )
                conn.commit()

    def _init_tokens(self):
        """Initialize API tokens from environment variables."""
        demo_token = os.getenv("DEMO_API_TOKEN", "demo-token-12345")
        admin_token = os.getenv("ADMIN_API_TOKEN", "admin-token-67890")

        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    # Insert default tokens if they do not exist
                    cursor.execute(
                        "INSERT IGNORE INTO api_tokens (token, user, created_at, last_used, is_active) VALUES (%s, %s, NOW(), NOW(), 1)",
                        (demo_token, "demo")
                    )
                    cursor.execute(
                        "INSERT IGNORE INTO api_tokens (token, user, created_at, last_used, is_active) VALUES (%s, %s, NOW(), NOW(), 1)",
                        (admin_token, "admin")
                    )
                conn.commit()
            finally:
                conn.close()
        else:
            # Demo token for testing
            self._api_tokens[demo_token] = APIToken(token=demo_token, user="demo")
            # Admin token
            self._api_tokens[admin_token] = APIToken(token=admin_token, user="admin")

    def generate_token(self, user: str) -> str:
        """Generate a new API token for a user."""
        token = str(uuid.uuid4())
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO api_tokens (token, user, created_at, last_used, is_active) VALUES (%s, %s, NOW(), NOW(), 1)",
                        (token, user)
                    )
                conn.commit()
            finally:
                conn.close()
        else:
            with self._lock:
                self._api_tokens[token] = APIToken(token=token, user=user)
        return token

    def validate_token(self, token: str) -> Optional[dict]:
        """Validate an API token and return user info."""
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT token, user, is_active FROM api_tokens WHERE token = %s AND is_active = 1",
                        (token,)
                    )
                    row = cursor.fetchone()
                    if row:
                        cursor.execute(
                            "UPDATE api_tokens SET last_used = NOW() WHERE token = %s",
                            (token,)
                        )
                        conn.commit()
                        return {"user": row["user"], "token": token}
            finally:
                conn.close()
            return None
        else:
            with self._lock:
                api_token = self._api_tokens.get(token)
                if api_token and api_token.is_active:
                    api_token.last_used = datetime.now(timezone.utc)
                    return {"user": api_token.user, "token": token}
                return None

    def get_all_tokens(self) -> list[dict]:
        """Get all API tokens (for admin dashboard)."""
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            tokens_list = []
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT token, user, created_at, last_used, is_active FROM api_tokens")
                    rows = cursor.fetchall()
                    for row in rows:
                        tokens_list.append({
                            "token": row["token"][:20] + "...",
                            "user": row["user"],
                            "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"]),
                            "last_used": row["last_used"].isoformat() if isinstance(row["last_used"], datetime) else str(row["last_used"]),
                            "is_active": bool(row["is_active"]),
                        })
            finally:
                conn.close()
            return tokens_list
        else:
            with self._lock:
                return [
                    {
                        "token": t.token[:20] + "...",
                        "user": t.user,
                        "created_at": t.created_at.isoformat(),
                        "last_used": t.last_used.isoformat(),
                        "is_active": t.is_active,
                    }
                    for t in self._api_tokens.values()
                ]

    def create_admin_session(self, user: str = "admin") -> str:
        """Create admin session token."""
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc).timestamp() + (6 * 60 * 60)
        
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO admin_sessions (session_id, username, created_at, expires_at) VALUES (%s, %s, NOW(), %s)",
                        (session_id, user, expires_at)
                    )
                conn.commit()
            finally:
                conn.close()
        else:
            with self._lock:
                self._admin_sessions[session_id] = {
                    "user": user,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "expires_at": expires_at,
                }
        return session_id

    def validate_admin_session(self, session_id: str | None) -> bool:
        """Validate admin session token and check expiry."""
        if not session_id:
            return False
            
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT session_id, username, expires_at FROM admin_sessions WHERE session_id = %s",
                        (session_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        if row["expires_at"] < datetime.now(timezone.utc).timestamp():
                            cursor.execute("DELETE FROM admin_sessions WHERE session_id = %s", (session_id,))
                            conn.commit()
                            return False
                        return True
            finally:
                conn.close()
            return False
        else:
            with self._lock:
                session = self._admin_sessions.get(session_id)
                if not session:
                    return False
                if session["expires_at"] < datetime.now(timezone.utc).timestamp():
                    del self._admin_sessions[session_id]
                    return False
                return True

    def revoke_admin_session(self, session_id: str | None) -> None:
        """Revoke admin session token."""
        if not session_id:
            return
            
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM admin_sessions WHERE session_id = %s", (session_id,))
                conn.commit()
            finally:
                conn.close()
        else:
            with self._lock:
                self._admin_sessions.pop(session_id, None)

    def get_admin_session_user(self, session_id: str | None) -> Optional[dict]:
        """Get user details of the active session."""
        if not session_id:
            return None
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT s.username, u.role, u.github_token, u.email 
                        FROM admin_sessions s
                        LEFT JOIN users u ON s.username = u.username
                        WHERE s.session_id = %s
                        """,
                        (session_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        return {
                            "username": row["username"],
                            "role": row["role"] or "user",
                            "github_token": row["github_token"],
                            "email": row["email"]
                        }
            finally:
                conn.close()
        else:
            with self._lock:
                session = self._admin_sessions.get(session_id)
                if session:
                    username = session["user"]
                    role = "user"
                    github_token = None
                    email = None
                    try:
                        with sqlite3.connect(self._db_path) as conn:
                            row = conn.execute("SELECT role, github_token, email FROM users WHERE username = ?", (username,)).fetchone()
                            if row:
                                role = row[0]
                                github_token = row[1]
                                email = row[2]
                            elif username == "admin":
                                role = "admin"
                    except Exception:
                        if username == "admin":
                            role = "admin"
                    return {"username": username, "role": role, "github_token": github_token, "email": email}
        return None

    def get_user(self, username: str) -> Optional[dict]:
        """Fetch user details by username."""
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT username, password_hash, role, github_token, email FROM users WHERE username = %s", (username,))
                    row = cursor.fetchone()
                    if row:
                        return row
            finally:
                conn.close()
        else:
            try:
                with sqlite3.connect(self._db_path) as conn:
                    row = conn.execute("SELECT username, password_hash, role, github_token, email FROM users WHERE username = ?", (username,)).fetchone()
                    if row:
                        return {"username": row[0], "password_hash": row[1], "role": row[2], "github_token": row[3], "email": row[4]}
            except Exception:
                pass
        return None

    def update_user_github_token(self, username: str, token: Optional[str]) -> bool:
        """Update the saved GitHub token for a user."""
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("UPDATE users SET github_token = %s WHERE username = %s", (token, username))
                conn.commit()
                return True
            except Exception:
                return False
            finally:
                conn.close()
        else:
            try:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute("UPDATE users SET github_token = ? WHERE username = ?", (token, username))
                    conn.commit()
                return True
            except Exception:
                return False

    def create_user(self, username: str, password_plain: str, role: str = 'user', email: Optional[str] = None) -> bool:
        """Register a new user, hashing the password."""
        if self.get_user(username):
            return False # Already exists
            
        password_hash = hashlib.sha256(password_plain.encode("utf-8")).hexdigest()
        
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO users (username, password_hash, role, created_at, email) VALUES (%s, %s, %s, NOW(), %s)",
                        (username, password_hash, role, email)
                    )
                conn.commit()
                return True
            except Exception:
                return False
            finally:
                conn.close()
        else:
            try:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, role, created_at, email) VALUES (?, ?, ?, ?, ?)",
                        (username, password_hash, role, datetime.now(timezone.utc).isoformat(), email)
                    )
                    conn.commit()
                return True
            except Exception:
                return False

    def list_users(self) -> list[dict]:
        """Get all registered users."""
        users_list = []
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT username, role, created_at, email FROM users ORDER BY username ASC")
                    rows = cursor.fetchall()
                    for row in rows:
                        users_list.append({
                            "username": row["username"],
                            "role": row["role"],
                            "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"]),
                            "email": row.get("email")
                        })
            finally:
                conn.close()
        else:
            try:
                with sqlite3.connect(self._db_path) as conn:
                    rows = conn.execute("SELECT username, role, created_at, email FROM users ORDER BY username ASC").fetchall()
                    for row in rows:
                        users_list.append({
                            "username": row[0],
                            "role": row[1],
                            "created_at": row[2],
                            "email": row[3]
                        })
            except Exception:
                pass
        return users_list

    def delete_user(self, username: str) -> bool:
        """Delete a user account."""
        if username == 'admin':
            return False # Protect main administrator
            
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM users WHERE username = %s", (username,))
                conn.commit()
                return True
            except Exception:
                return False
            finally:
                conn.close()
        else:
            try:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute("DELETE FROM users WHERE username = ?", (username,))
                    conn.commit()
                return True
            except Exception:
                return False

    def get_tokens_by_user(self, username: str) -> list[dict]:
        """Get API tokens filtered by user."""
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            tokens_list = []
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT token, user, created_at, last_used, is_active FROM api_tokens WHERE user = %s",
                        (username,)
                    )
                    rows = cursor.fetchall()
                    for row in rows:
                        tokens_list.append({
                            "token": row["token"][:20] + "...",
                            "user": row["user"],
                            "created_at": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"]),
                            "last_used": row["last_used"].isoformat() if isinstance(row["last_used"], datetime) else str(row["last_used"]),
                            "is_active": bool(row["is_active"]),
                        })
            finally:
                conn.close()
            return tokens_list
        else:
            with self._lock:
                return [
                    {
                        "token": t.token[:20] + "...",
                        "user": t.user,
                        "created_at": t.created_at.isoformat(),
                        "last_used": t.last_used.isoformat(),
                        "is_active": t.is_active,
                    }
                    for t in self._api_tokens.values()
                    if t.user == username
                ]

    def create_scan(self, scan: Scan) -> Scan:
        if self._db_type == "mysql":
            findings = [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "penalty": getattr(f, "penalty", 0),
                    "remediation": getattr(f, "remediation", ""),
                }
                for f in scan.findings
            ]
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO scans (target_type, target_value, status, score, created_at, findings_json, username)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            scan.target_type,
                            scan.target_value,
                            scan.status,
                            scan.score,
                            scan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                            json.dumps(findings, ensure_ascii=False),
                            scan.username,
                        )
                    )
                    scan.id = cursor.lastrowid
                conn.commit()
            finally:
                conn.close()
            
            with self._lock:
                self._scans.insert(0, scan)
            return scan
        else:
            with self._lock:
                scan.id = self._next_id
                self._next_id += 1
                self._scans.insert(0, scan)
                try:
                    self._persist()
                except Exception as e:
                    err_p = e
                try:
                    self._persist_sqlite(scan)
                except Exception as e:
                    err_s = e
                return scan

    def get_scan(self, scan_id: int) -> Optional[Scan]:
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "SELECT id, target_type, target_value, status, score, created_at, findings_json, username FROM scans WHERE id = %s",
                        (scan_id,)
                    )
                    row = cursor.fetchone()
                    if row:
                        findings = []
                        try:
                            findings_data = json.loads(row["findings_json"] or "[]")
                        except Exception:
                            findings_data = []
                        for f in findings_data:
                            findings.append(Finding(
                                rule_id=f.get("rule_id"),
                                title=f.get("title"),
                                severity=f.get("severity"),
                                description=f.get("description"),
                                evidence=f.get("evidence"),
                                penalty=f.get("penalty", 0),
                                remediation=f.get("remediation", ""),
                            ))
                        created_dt = row["created_at"]
                        if isinstance(created_dt, str):
                            try:
                                created_dt = datetime.fromisoformat(created_dt)
                            except Exception:
                                created_dt = datetime.now(timezone.utc)
                        return Scan(
                            id=row["id"],
                            target_type=row["target_type"],
                            target_value=row["target_value"],
                            status=row["status"],
                            score=row["score"],
                            created_at=created_dt,
                            findings=findings,
                            username=row.get("username")
                        )
            finally:
                conn.close()
            return None
        else:
            with self._lock:
                return next((scan for scan in self._scans if scan.id == scan_id), None)

    def list_scans(self, limit: int | None = None, username: str | None = None) -> list[Scan]:
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            loaded = []
            try:
                with conn.cursor() as cursor:
                    query = "SELECT id, target_type, target_value, status, score, created_at, findings_json, username FROM scans"
                    params = []
                    if username is not None:
                        query += " WHERE username = %s"
                        params.append(username)
                    query += " ORDER BY id DESC"
                    if limit is not None:
                        query += f" LIMIT {int(limit)}"
                    cursor.execute(query, params)
                    rows = cursor.fetchall()
                    for row in rows:
                        findings = []
                        try:
                            findings_data = json.loads(row["findings_json"] or "[]")
                        except Exception:
                            findings_data = []
                        for f in findings_data:
                            findings.append(Finding(
                                rule_id=f.get("rule_id"),
                                title=f.get("title"),
                                severity=f.get("severity"),
                                description=f.get("description"),
                                evidence=f.get("evidence"),
                                penalty=f.get("penalty", 0),
                                remediation=f.get("remediation", ""),
                            ))
                        created_dt = row["created_at"]
                        if isinstance(created_dt, str):
                            try:
                                created_dt = datetime.fromisoformat(created_dt)
                            except Exception:
                                created_dt = datetime.now(timezone.utc)
                        loaded.append(Scan(
                            id=row["id"],
                            target_type=row["target_type"],
                            target_value=row["target_value"],
                            status=row["status"],
                            score=row["score"],
                            created_at=created_dt,
                            findings=findings,
                            username=row.get("username")
                        ))
            finally:
                conn.close()
            return loaded
        else:
            with self._lock:
                scans = list(self._scans)
            if username is not None:
                scans = [s for s in scans if s.username == username]
            if limit is None:
                return scans
            return scans[:limit]

    def clear(self) -> None:
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("TRUNCATE TABLE scans")
                    cursor.execute("TRUNCATE TABLE access_logs")
                    cursor.execute("TRUNCATE TABLE admin_sessions")
                conn.commit()
            finally:
                conn.close()
            with self._lock:
                self._scans.clear()
                self._accesses.clear()
        else:
            with self._lock:
                self._scans.clear()
                self._next_id = 1
                self._accesses.clear()
                try:
                    self._persist()
                except Exception as e:
                    err_p = e
                try:
                    self._clear_sqlite()
                except Exception as e:
                    err_s = e

    def _persist(self) -> None:
        """Persist scans and meta (next id) to disk as JSON."""
        data = []
        for s in self._scans:
            data.append({
                "id": s.id,
                "target_type": s.target_type,
                "target_value": s.target_value,
                "status": s.status,
                "score": s.score,
                "created_at": s.created_at.isoformat(),
                "username": s.username,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "severity": f.severity,
                        "description": f.description,
                        "evidence": f.evidence,
                        "penalty": getattr(f, 'penalty', 0),
                        "remediation": getattr(f, 'remediation', ''),
                    }
                    for f in s.findings
                ],
            })
        tmp = self._scans_file.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump({"scans": data, "next_id": self._next_id}, fh, ensure_ascii=False, indent=2)
        tmp.replace(self._scans_file)

    def _load_persisted(self) -> None:
        """Load persisted scans from disk if available."""
        if self._db_type == "mysql":
            scans_loaded = self.list_scans()
            with self._lock:
                self._scans = scans_loaded
            return

        if self._db_path.exists():
            try:
                self._load_sqlite()
                return
            except Exception as e:
                err_db = e
        if not self._scans_file.exists():
            return
        with self._scans_file.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
        scans = payload.get("scans", [])
        loaded = []
        for s in scans:
            findings = []
            for f in s.get("findings", []):
                findings.append(Finding(
                    rule_id=f.get("rule_id"),
                    title=f.get("title"),
                    severity=f.get("severity"),
                    description=f.get("description"),
                    evidence=f.get("evidence"),
                    penalty=f.get("penalty", 0),
                    remediation=f.get("remediation", ""),
                ))
            created_at = None
            try:
                created_at = datetime.fromisoformat(s.get("created_at"))
            except Exception:
                created_at = datetime.now(timezone.utc)
            loaded.append(Scan(
                id=s.get("id", 0),
                target_type=s.get("target_type", ""),
                target_value=s.get("target_value", ""),
                status=s.get("status", ""),
                score=s.get("score", 0),
                created_at=created_at,
                findings=findings,
                username=s.get("username")
            ))
        with self._lock:
            self._scans = loaded
            self._next_id = int(payload.get("next_id", max([c.id for c in loaded], default=0) + 1))

    def _persist_sqlite(self, scan: Scan) -> None:
        findings = [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "penalty": getattr(f, "penalty", 0),
                "remediation": getattr(f, "remediation", ""),
            }
            for f in scan.findings
        ]
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (id, target_type, target_value, status, score, created_at, findings_json, username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan.id,
                    scan.target_type,
                    scan.target_value,
                    scan.status,
                    scan.score,
                    scan.created_at.isoformat(),
                    json.dumps(findings, ensure_ascii=False),
                    scan.username,
                ),
            )
            conn.commit()

    def _load_sqlite(self) -> None:
        with sqlite3.connect(self._db_path) as conn:
            rows = conn.execute(
                "SELECT id, target_type, target_value, status, score, created_at, findings_json, username FROM scans ORDER BY id DESC"
            ).fetchall()
        loaded = []
        max_id = 0
        for row in rows:
            scan_id, target_type, target_value, status, score, created_at, findings_json, username = row
            max_id = max(max_id, int(scan_id))
            findings = []
            try:
                findings_data = json.loads(findings_json or "[]")
            except Exception:
                findings_data = []
            for f in findings_data:
                findings.append(Finding(
                    rule_id=f.get("rule_id"),
                    title=f.get("title"),
                    severity=f.get("severity"),
                    description=f.get("description"),
                    evidence=f.get("evidence"),
                    penalty=f.get("penalty", 0),
                    remediation=f.get("remediation", ""),
                ))
            try:
                created_dt = datetime.fromisoformat(created_at)
            except Exception:
                created_dt = datetime.now(timezone.utc)
            loaded.append(Scan(id=scan_id, target_type=target_type, target_value=target_value, status=status, score=score, created_at=created_dt, findings=findings, username=username))
        with self._lock:
            self._scans = loaded
            self._next_id = max_id + 1 if max_id else 1

    def _clear_sqlite(self) -> None:
        if not self._db_path.exists():
            return
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("DELETE FROM scans")
            conn.commit()

    def get_setting(self, key: str, default: str = "") -> str:
        """Fetch a system setting value."""
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT setting_value FROM system_settings WHERE setting_key = %s", (key,))
                    row = cursor.fetchone()
                    if row:
                        return row["setting_value"]
            except Exception:
                pass
            finally:
                conn.close()
        else:
            try:
                with sqlite3.connect(self._db_path) as conn:
                    row = conn.execute("SELECT setting_value FROM system_settings WHERE setting_key = ?", (key,)).fetchone()
                    if row:
                        return row[0]
            except Exception:
                pass
        return default

    def set_setting(self, key: str, value: str) -> None:
        """Save/update a system setting."""
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO system_settings (setting_key, setting_value) VALUES (%s, %s) "
                        "ON DUPLICATE KEY UPDATE setting_value = %s",
                        (key, value, value)
                    )
                conn.commit()
            except Exception:
                pass
            finally:
                conn.close()
        else:
            try:
                with sqlite3.connect(self._db_path) as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO system_settings (setting_key, setting_value) VALUES (?, ?)",
                        (key, value)
                    )
                    conn.commit()
            except Exception:
                pass

    # Access log methods
    def log_access(self, path: str, ip: str, user_agent: str, user: str | None = None, timestamp: str | None = None) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO access_logs (path, ip, user_agent, username, created_at) VALUES (%s, %s, %s, %s, %s)",
                        (path, ip, user_agent, user, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
                    )
                conn.commit()
            except Exception:
                pass # Ignore logging failure
            finally:
                conn.close()
        else:
            with self._lock:
                self._accesses.insert(0, {"path": path, "ip": ip, "user_agent": user_agent, "username": user, "created_at": ts})

    def list_accesses(self, limit: int | None = 100) -> list[dict]:
        if self._db_type == "mysql":
            conn = self._get_mysql_conn()
            accesses_list = []
            try:
                with conn.cursor() as cursor:
                    query = "SELECT path, ip, user_agent, username, created_at FROM access_logs ORDER BY id DESC"
                    if limit is not None:
                        query += f" LIMIT {int(limit)}"
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    for row in rows:
                        accesses_list.append({
                            "path": row["path"],
                            "ip": row["ip"],
                            "user_agent": row["user_agent"],
                            "username": row["username"],
                            "timestamp": row["created_at"].isoformat() if isinstance(row["created_at"], datetime) else str(row["created_at"]),
                        })
            finally:
                conn.close()
            return accesses_list
        else:
            with self._lock:
                if limit is None:
                    return list(self._accesses)
                return list(self._accesses)[:limit]

scan_store = InMemoryScanStore()
