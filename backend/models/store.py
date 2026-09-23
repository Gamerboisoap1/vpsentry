"""Small SQLite repository; connections never cross thread boundaries."""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

class Store:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / 'vpsentry.sqlite3'
        with self.connect() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, type TEXT NOT NULL,
              category TEXT NOT NULL, source_ip TEXT, severity TEXT NOT NULL,
              description TEXT NOT NULL, details TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
            CREATE INDEX IF NOT EXISTS events_type ON events(type, timestamp);
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS samples (timestamp REAL PRIMARY KEY, cpu REAL, ram REAL, disk REAL);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def event(self, kind, category, severity, description, source_ip=None, details=None, demo=False, timestamp=None):
        with self.connect() as db:
            row = db.execute('INSERT INTO events(timestamp,type,category,source_ip,severity,description,details,demo) VALUES(?,?,?,?,?,?,?,?)',
                (timestamp or time.time(), kind, category, source_ip, severity, description, json.dumps(details or {}), int(demo)))
            return row.lastrowid

    def update_incident(self, event_id, details):
        with self.connect() as db:
            db.execute('UPDATE events SET details=? WHERE id=?', (json.dumps(details), event_id))

    def events(self, category=None, kind=None, severity=None, query='', limit=50, offset=0, since=0, demo=False):
        clauses, args = ['timestamp>=?', 'demo=?'], [since, int(demo)]
        for column, value in [('category', category), ('type', kind), ('severity', severity)]:
            if value:
                clauses.append(column + '=?'); args.append(value)
        if query:
            clauses.append('(description LIKE ? OR source_ip LIKE ?)'); args.extend(['%' + query + '%'] * 2)
        where = ' AND '.join(clauses)
        with self.connect() as db:
            total = db.execute('SELECT COUNT(*) FROM events WHERE ' + where, args).fetchone()[0]
            rows = db.execute('SELECT * FROM events WHERE ' + where + ' ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?', args + [limit, offset]).fetchall()
        return {'total': total, 'items': [{**dict(row), 'details': json.loads(row['details']), 'demo': bool(row['demo'])} for row in rows]}

    def attack_sources(self, now=None):
        now = time.time() if now is None else now
        where = "demo=0 AND source_ip IS NOT NULL AND type IN ('SSH_BRUTE_FORCE','PORT_SCAN') AND COALESCE(json_extract(details, '$.last_seen'), timestamp) BETWEEN ? AND ?"
        with self.connect() as db:
            total = db.execute('SELECT COUNT(DISTINCT source_ip) FROM events WHERE ' + where, (now - 86400, now)).fetchone()[0]
            rows = db.execute("SELECT source_ip, COUNT(*) AS incidents, MAX(COALESCE(json_extract(details, '$.last_seen'), timestamp)) AS last_seen, GROUP_CONCAT(DISTINCT type) AS types FROM events WHERE " + where + " GROUP BY source_ip ORDER BY last_seen DESC LIMIT 100", (now - 86400, now)).fetchall()
        return {'total': total, 'items': [{**dict(row), 'types': row['types'].split(',')} for row in rows]}

    def active_alerts(self, now=None):
        """Use last observation, not creation time, for ongoing deduplicated attacks."""
        now = time.time() if now is None else now
        where = "demo=0 AND type IN ('SSH_BRUTE_FORCE','PORT_SCAN') AND COALESCE(json_extract(details, '$.last_seen'), timestamp) BETWEEN ? AND ?"
        with self.connect() as db:
            total = db.execute('SELECT COUNT(*) FROM events WHERE ' + where, (now - 120, now)).fetchone()[0]
            rows = db.execute("SELECT * FROM events WHERE " + where + " ORDER BY COALESCE(json_extract(details, '$.last_seen'), timestamp) DESC, id DESC LIMIT 3", (now - 120, now)).fetchall()
        return {'total': total, 'items': [{**dict(row), 'details': json.loads(row['details'])} for row in rows]}

    def set(self, key, value):
        with self.connect() as db:
            db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, json.dumps(value)))

    def get(self, key, default=None):
        with self.connect() as db:
            row = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def sample(self, stats):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO samples VALUES(?,?,?,?)', (stats['timestamp'], stats['cpu'], stats['ram']['percent'], stats['disk']['percent']))
            db.execute('DELETE FROM samples WHERE timestamp<?', (time.time() - 3600,))

    def history(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute('SELECT * FROM samples ORDER BY timestamp')]

    def prune(self, days):
        with self.connect() as db:
            db.execute("DELETE FROM events WHERE COALESCE(json_extract(details, '$.last_seen'), timestamp)<?", (time.time() - days * 86400,))
            db.execute("DELETE FROM state WHERE key LIKE 'geoip:%' AND json_extract(value, '$.expires')<?", (time.time(),))
