from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from urllib.parse import parse_qs, urlparse

APP_NAME = "Chronicle Inventory"
MAX_BODY = 10 * 1024 * 1024
SESSION_SECONDS = 30 * 60
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def password_hash(password: str, salt: bytes | None = None) -> str:
    if not 12 <= len(password) <= 256:
        raise ValueError("Password must contain 12–256 characters")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def password_verify(password: str, encoded: str) -> bool:
    try:
        _, n, r, p, salt_hex, expected_hex = encoded.split("$")
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(actual, bytes.fromhex(expected_hex))
    except (ValueError, TypeError):
        return False


def csv_safe(value: object) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


class Store:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        self._connections_lock = threading.Lock()
        self.init()

    def conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
            with self._connections_lock:
                self._connections.append(conn)
        return self._local.conn

    def init(self) -> None:
        conn = self.conn()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_login_at TEXT
        );
        CREATE TABLE IF NOT EXISTS watches (
          id INTEGER PRIMARY KEY, brand TEXT NOT NULL, model TEXT NOT NULL,
          reference_number TEXT, sku TEXT NOT NULL COLLATE NOCASE,
          unit_code TEXT NOT NULL UNIQUE COLLATE NOCASE, serial_number TEXT,
          condition TEXT NOT NULL CHECK(condition IN ('New','Excellent','Very good','Good','Fair')),
          status TEXT NOT NULL CHECK(status IN ('Available','Reserved','Sold','Quarantine','Repair')),
          purchase_cost_minor INTEGER NOT NULL DEFAULT 0 CHECK(purchase_cost_minor >= 0),
          selling_price_minor INTEGER NOT NULL DEFAULT 0 CHECK(selling_price_minor >= 0),
          currency TEXT NOT NULL DEFAULT 'USD' CHECK(currency='USD'),
          location TEXT NOT NULL DEFAULT 'Main inventory', notes TEXT,
          acquired_on TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1, archived_at TEXT
        );
        CREATE INDEX IF NOT EXISTS ix_watches_sku ON watches(sku COLLATE NOCASE);
        CREATE TABLE IF NOT EXISTS audit_events (
          id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, username TEXT,
          action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT,
          detail_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS import_batches (
          id INTEGER PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL,
          status TEXT NOT NULL, total_rows INTEGER NOT NULL, imported_rows INTEGER NOT NULL,
          error_rows INTEGER NOT NULL, errors_json TEXT NOT NULL, username TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS suppliers (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT, phone TEXT,
          website TEXT, notes TEXT, status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active','Inactive')),
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS purchase_orders (
          id INTEGER PRIMARY KEY, po_number TEXT NOT NULL UNIQUE COLLATE NOCASE,
          supplier_id INTEGER NOT NULL REFERENCES suppliers(id),
          status TEXT NOT NULL DEFAULT 'Draft' CHECK(status IN ('Draft','Ordered','Part received','Received','Cancelled')),
          order_date TEXT, expected_date TEXT, shipping_minor INTEGER NOT NULL DEFAULT 0,
          tax_minor INTEGER NOT NULL DEFAULT 0, notes TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS purchase_order_lines (
          id INTEGER PRIMARY KEY, purchase_order_id INTEGER NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
          description TEXT NOT NULL, sku TEXT, quantity INTEGER NOT NULL CHECK(quantity>0),
          unit_cost_minor INTEGER NOT NULL CHECK(unit_cost_minor>=0)
        );
        """)
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(watches)")}
        if "archived_at" not in columns:
            conn.execute("ALTER TABLE watches ADD COLUMN archived_at TEXT")
        conn.execute("INSERT OR IGNORE INTO settings(key,value_json,updated_at) VALUES('aging_days','[30,60,90]',?)", (utc_now(),))
        self._migrate_sku_to_shared()

    def _migrate_sku_to_shared(self) -> None:
        """Remove the legacy UNIQUE constraint from SKU while preserving all rows."""
        conn = self.conn()
        legacy_unique = False
        for index in conn.execute("PRAGMA index_list(watches)").fetchall():
            if not index["unique"]:
                continue
            columns = [r["name"] for r in conn.execute(f"PRAGMA index_info('{index['name']}')").fetchall()]
            if columns == ["sku"]:
                legacy_unique = True
                break
        if not legacy_unique:
            return
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("ALTER TABLE watches RENAME TO watches_legacy_unique_sku")
            conn.execute("""CREATE TABLE watches (
              id INTEGER PRIMARY KEY, brand TEXT NOT NULL, model TEXT NOT NULL,
              reference_number TEXT, sku TEXT NOT NULL COLLATE NOCASE,
              unit_code TEXT NOT NULL UNIQUE COLLATE NOCASE, serial_number TEXT,
              condition TEXT NOT NULL CHECK(condition IN ('New','Excellent','Very good','Good','Fair')),
              status TEXT NOT NULL CHECK(status IN ('Available','Reserved','Sold','Quarantine','Repair')),
              purchase_cost_minor INTEGER NOT NULL DEFAULT 0 CHECK(purchase_cost_minor >= 0),
              selling_price_minor INTEGER NOT NULL DEFAULT 0 CHECK(selling_price_minor >= 0),
              currency TEXT NOT NULL DEFAULT 'USD' CHECK(currency='USD'),
              location TEXT NOT NULL DEFAULT 'Main inventory', notes TEXT,
              acquired_on TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              version INTEGER NOT NULL DEFAULT 1, archived_at TEXT
            )""")
            legacy_columns = {r["name"] for r in conn.execute("PRAGMA table_info(watches_legacy_unique_sku)")}
            if "archived_at" in legacy_columns:
                conn.execute("INSERT INTO watches SELECT * FROM watches_legacy_unique_sku")
            else:
                conn.execute("""INSERT INTO watches(id,brand,model,reference_number,sku,unit_code,serial_number,condition,status,
                    purchase_cost_minor,selling_price_minor,currency,location,notes,acquired_on,created_at,updated_at,version)
                    SELECT id,brand,model,reference_number,sku,unit_code,serial_number,condition,status,
                    purchase_cost_minor,selling_price_minor,currency,location,notes,acquired_on,created_at,updated_at,version
                    FROM watches_legacy_unique_sku""")
            conn.execute("DROP TABLE watches_legacy_unique_sku")
            conn.execute("CREATE INDEX ix_watches_sku ON watches(sku COLLATE NOCASE)")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        with self._connections_lock:
            connections, self._connections = self._connections, []
        for conn in connections:
            try: conn.close()
            except sqlite3.Error: pass
        if hasattr(self._local, "conn"):
            del self._local.conn

    def audit(self, username: str | None, action: str, entity_type: str, entity_id: object = None, detail: dict | None = None) -> None:
        self.conn().execute(
            "INSERT INTO audit_events(occurred_at,username,action,entity_type,entity_id,detail_json) VALUES(?,?,?,?,?,?)",
            (utc_now(), username, action, entity_type, None if entity_id is None else str(entity_id), json.dumps(detail or {}, separators=(",", ":"))),
        )

    def user_count(self) -> int:
        return self.conn().execute("SELECT count(*) FROM users").fetchone()[0]

    def create_user(self, username: str, password: str) -> None:
        username = username.strip()
        if not 3 <= len(username) <= 50 or not all(c.isalnum() or c in "._-" for c in username):
            raise ValueError("Username must be 3–50 letters, numbers, dots, dashes, or underscores")
        self.conn().execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)", (username, password_hash(password), utc_now()))
        self.audit(username, "account.created", "user", username)

    def authenticate(self, username: str, password: str) -> bool:
        row = self.conn().execute("SELECT password_hash FROM users WHERE username=? COLLATE NOCASE", (username.strip(),)).fetchone()
        ok = bool(row and password_verify(password, row[0]))
        if ok:
            self.conn().execute("UPDATE users SET last_login_at=? WHERE username=? COLLATE NOCASE", (utc_now(), username.strip()))
            self.audit(username.strip(), "account.login", "session")
        return ok

    def change_password(self, username: str, current_password: str, new_password: str) -> None:
        row = self.conn().execute("SELECT password_hash FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
        if not row or not password_verify(current_password, row[0]):
            raise ValueError("Current password is incorrect")
        if current_password == new_password:
            raise ValueError("New password must be different")
        self.conn().execute("UPDATE users SET password_hash=? WHERE username=? COLLATE NOCASE", (password_hash(new_password), username))
        self.audit(username, "account.password_changed", "user", username)

    def watches(self, q: str = "", status: str = "", condition: str = "", include_archived: bool = False, sort: str = "newest") -> list[dict]:
        term = f"%{q.strip()}%"
        order = {"newest":"updated_at DESC,id DESC", "oldest":"updated_at ASC,id ASC", "brand":"brand COLLATE NOCASE,model COLLATE NOCASE", "cost_high":"purchase_cost_minor DESC", "price_high":"selling_price_minor DESC"}.get(sort, "updated_at DESC,id DESC")
        rows = self.conn().execute(
            f"""SELECT * FROM watches WHERE (? OR archived_at IS NULL) AND (?='' OR status=?) AND (?='' OR condition=?)
               AND (?='' OR brand LIKE ? OR model LIKE ? OR sku LIKE ? OR unit_code LIKE ? OR coalesce(serial_number,'') LIKE ?
               OR coalesce(reference_number,'') LIKE ?) ORDER BY {order} LIMIT 1000""",
            (include_archived, status, status, condition, condition, q.strip(), term, term, term, term, term, term),
        ).fetchall()
        return [dict(r) for r in rows]

    def _check_serial(self, brand: str, serial: str | None, exclude_id: int | None = None) -> None:
        if not serial: return
        row = self.conn().execute("SELECT id FROM watches WHERE brand=? COLLATE NOCASE AND serial_number=? COLLATE NOCASE AND (? IS NULL OR id!=?)", (brand, serial, exclude_id, exclude_id)).fetchone()
        if row: raise Conflict("Serial number already exists for this brand")

    def create_watch(self, data: dict, username: str) -> dict:
        item = validate_watch(data)
        self._check_serial(item["brand"], item["serial_number"])
        now = utc_now()
        cur = self.conn().execute(
            """INSERT INTO watches(brand,model,reference_number,sku,unit_code,serial_number,condition,status,
               purchase_cost_minor,selling_price_minor,currency,location,notes,acquired_on,created_at,updated_at)
               VALUES(:brand,:model,:reference_number,:sku,:unit_code,:serial_number,:condition,:status,
               :purchase_cost_minor,:selling_price_minor,'USD',:location,:notes,:acquired_on,:created_at,:updated_at)""",
            {**item, "created_at": now, "updated_at": now},
        )
        self.audit(username, "watch.created", "watch", cur.lastrowid, {"sku": item["sku"], "unit_code": item["unit_code"]})
        return dict(self.conn().execute("SELECT * FROM watches WHERE id=?", (cur.lastrowid,)).fetchone())

    def update_watch(self, watch_id: int, data: dict, username: str) -> dict:
        item = validate_watch(data)
        self._check_serial(item["brand"], item["serial_number"], watch_id)
        expected = int(data.get("version", 0))
        cur = self.conn().execute(
            """UPDATE watches SET brand=:brand,model=:model,reference_number=:reference_number,sku=:sku,
               unit_code=:unit_code,serial_number=:serial_number,condition=:condition,status=:status,
               purchase_cost_minor=:purchase_cost_minor,selling_price_minor=:selling_price_minor,
               location=:location,notes=:notes,acquired_on=:acquired_on,updated_at=:updated_at,version=version+1
               WHERE id=:id AND version=:version""",
            {**item, "updated_at": utc_now(), "id": watch_id, "version": expected},
        )
        if cur.rowcount != 1:
            raise Conflict("Record changed or no longer exists; refresh and try again")
        self.audit(username, "watch.updated", "watch", watch_id, {"sku": item["sku"], "prior_version": expected})
        return dict(self.conn().execute("SELECT * FROM watches WHERE id=?", (watch_id,)).fetchone())

    def archive_watch(self, watch_id: int, username: str) -> None:
        row = self.conn().execute("SELECT status,archived_at FROM watches WHERE id=?", (watch_id,)).fetchone()
        if not row: raise ValueError("Watch not found")
        if row["archived_at"]: raise ValueError("Watch is already archived")
        if row["status"] == "Reserved": raise ValueError("Release the reservation before archiving this watch")
        self.conn().execute("UPDATE watches SET archived_at=?,updated_at=?,version=version+1 WHERE id=?", (utc_now(), utc_now(), watch_id))
        self.audit(username, "watch.archived", "watch", watch_id)

    def aging_days(self) -> list[int]:
        return json.loads(self.conn().execute("SELECT value_json FROM settings WHERE key='aging_days'").fetchone()[0])

    def set_aging_days(self, values: object, username: str) -> list[int]:
        if not isinstance(values, list) or len(values) != 3:
            raise ValueError("Provide exactly three aging boundaries")
        try: days = [int(x) for x in values]
        except (ValueError, TypeError) as exc: raise ValueError("Aging boundaries must be whole days") from exc
        if not (1 <= days[0] < days[1] < days[2] <= 3650):
            raise ValueError("Aging boundaries must increase and remain between 1 and 3,650 days")
        self.conn().execute("UPDATE settings SET value_json=?,updated_at=? WHERE key='aging_days'", (json.dumps(days), utc_now()))
        self.audit(username, "settings.aging_updated", "settings", "aging_days", {"days":days})
        return days

    def suppliers(self) -> list[dict]:
        return [dict(r) for r in self.conn().execute("""SELECT s.*,
          (SELECT count(*) FROM purchase_orders p WHERE p.supplier_id=s.id) purchase_order_count
          FROM suppliers s ORDER BY s.status='Inactive',s.name COLLATE NOCASE""")]

    def create_supplier(self, data: dict, username: str) -> dict:
        name = clean_text(data.get("name"), "Supplier name", True, 150)
        email = clean_text(data.get("email"), "Email", False, 254) or None
        if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): raise ValueError("Supplier email is invalid")
        phone = clean_text(data.get("phone"), "Phone", False, 40) or None
        website = clean_text(data.get("website"), "Website", False, 300) or None
        if website and not re.fullmatch(r"https?://[^\s]+", website): raise ValueError("Website must begin with http:// or https://")
        status = clean_text(data.get("status") or "Active", "Status", True, 20)
        if status not in {"Active","Inactive"}: raise ValueError("Supplier status is invalid")
        notes = clean_text(data.get("notes"), "Notes", False, 2000) or None; now=utc_now()
        cur=self.conn().execute("INSERT INTO suppliers(name,email,phone,website,notes,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",(name,email,phone,website,notes,status,now,now))
        self.audit(username,"supplier.created","supplier",cur.lastrowid,{"name":name})
        return dict(self.conn().execute("SELECT * FROM suppliers WHERE id=?",(cur.lastrowid,)).fetchone())

    def purchase_orders(self) -> list[dict]:
        return [dict(r) for r in self.conn().execute("""SELECT p.*,s.name supplier_name,
          coalesce((SELECT sum(quantity*unit_cost_minor) FROM purchase_order_lines l WHERE l.purchase_order_id=p.id),0) items_minor,
          coalesce((SELECT sum(quantity*unit_cost_minor) FROM purchase_order_lines l WHERE l.purchase_order_id=p.id),0)+p.shipping_minor+p.tax_minor total_minor,
          coalesce((SELECT sum(quantity) FROM purchase_order_lines l WHERE l.purchase_order_id=p.id),0) total_quantity
          FROM purchase_orders p JOIN suppliers s ON s.id=p.supplier_id ORDER BY p.created_at DESC,p.id DESC""")]

    def create_purchase_order(self, data: dict, username: str) -> dict:
        po_number=clean_text(data.get("po_number"),"PO number",True,60)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{1,59}",po_number): raise ValueError("PO number format is invalid")
        try: supplier_id=int(data.get("supplier_id"))
        except (ValueError,TypeError) as exc: raise ValueError("Supplier is required") from exc
        if not self.conn().execute("SELECT 1 FROM suppliers WHERE id=? AND status='Active'",(supplier_id,)).fetchone(): raise ValueError("Select an active supplier")
        status=clean_text(data.get("status") or "Draft","Status",True,20)
        if status not in {"Draft","Ordered","Part received","Received","Cancelled"}: raise ValueError("Purchase-order status is invalid")
        order_date=validate_date(data.get("order_date"),"Order date",allow_future=False)
        expected_date=validate_date(data.get("expected_date"),"Expected date",allow_future=True)
        if order_date and expected_date and expected_date<order_date: raise ValueError("Expected date cannot be before order date")
        lines=data.get("lines")
        if not isinstance(lines,list) or not 1<=len(lines)<=100: raise ValueError("Add between 1 and 100 purchase-order lines")
        clean_lines=[]
        for line in lines:
            if not isinstance(line,dict): raise ValueError("Purchase-order line is invalid")
            description=clean_text(line.get("description"),"Line description",True,200)
            sku=clean_text(line.get("sku"),"Line SKU",False,80) or None
            try: quantity=int(line.get("quantity"))
            except (ValueError,TypeError) as exc: raise ValueError("Line quantity must be a whole number") from exc
            if not 1<=quantity<=10000: raise ValueError("Line quantity is outside the allowed range")
            clean_lines.append((description,sku,quantity,money_to_minor(line.get("unit_cost",0))))
        now=utc_now(); conn=self.conn(); conn.execute("BEGIN IMMEDIATE")
        try:
            cur=conn.execute("INSERT INTO purchase_orders(po_number,supplier_id,status,order_date,expected_date,shipping_minor,tax_minor,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(po_number,supplier_id,status,order_date,expected_date,money_to_minor(data.get("shipping",0)),money_to_minor(data.get("tax",0)),clean_text(data.get("notes"),"Notes",False,2000) or None,now,now))
            conn.executemany("INSERT INTO purchase_order_lines(purchase_order_id,description,sku,quantity,unit_cost_minor) VALUES(?,?,?,?,?)",[(cur.lastrowid,*line) for line in clean_lines])
            conn.execute("COMMIT")
        except Exception: conn.execute("ROLLBACK"); raise
        self.audit(username,"purchase_order.created","purchase_order",cur.lastrowid,{"po_number":po_number,"lines":len(clean_lines)})
        return dict(conn.execute("SELECT * FROM purchase_orders WHERE id=?",(cur.lastrowid,)).fetchone())

    def dashboard(self) -> dict:
        row = self.conn().execute("""SELECT count(*) units,
            coalesce(sum(CASE WHEN status!='Sold' THEN purchase_cost_minor ELSE 0 END),0) inventory_value_minor,
            coalesce(sum(CASE WHEN status!='Sold' THEN selling_price_minor ELSE 0 END),0) retail_value_minor,
            coalesce(sum(CASE WHEN status!='Sold' THEN selling_price_minor-purchase_cost_minor ELSE 0 END),0) potential_profit_minor,
            sum(CASE WHEN status='Available' THEN 1 ELSE 0 END) available,
            sum(CASE WHEN status='Reserved' THEN 1 ELSE 0 END) reserved,
            sum(CASE WHEN status='Sold' THEN 1 ELSE 0 END) sold,
            sum(CASE WHEN status IN ('Quarantine','Repair') THEN 1 ELSE 0 END) attention
            FROM watches WHERE archived_at IS NULL""").fetchone()
        statuses = [dict(r) for r in self.conn().execute("SELECT status label,count(*) count FROM watches WHERE archived_at IS NULL GROUP BY status ORDER BY count(*) DESC,status")]
        brands = [dict(r) for r in self.conn().execute("""SELECT brand label,count(*) count,
            coalesce(sum(CASE WHEN status!='Sold' THEN purchase_cost_minor ELSE 0 END),0) value_minor
            FROM watches WHERE archived_at IS NULL GROUP BY brand ORDER BY value_minor DESC,label LIMIT 8""")]
        conditions = [dict(r) for r in self.conn().execute("SELECT condition label,count(*) count FROM watches WHERE archived_at IS NULL GROUP BY condition ORDER BY count(*) DESC,condition")]
        bounds = self.aging_days(); counts = [0,0,0,0]; unknown = 0; today = dt.date.today()
        for aged in self.conn().execute("SELECT acquired_on FROM watches WHERE archived_at IS NULL AND status!='Sold'"):
            if not aged[0]: unknown += 1; continue
            age = (today-dt.date.fromisoformat(aged[0])).days
            counts[0 if age<=bounds[0] else 1 if age<=bounds[1] else 2 if age<=bounds[2] else 3] += 1
        labels = [f"0–{bounds[0]} days",f"{bounds[0]+1}–{bounds[1]} days",f"{bounds[1]+1}–{bounds[2]} days",f"{bounds[2]+1}+ days"]
        aging = [{"label":label,"count":count} for label,count in zip(labels,counts) if count]
        if unknown: aging.append({"label":"Unknown","count":unknown})
        recent = [dict(r) for r in self.conn().execute("""SELECT id,brand,model,sku,unit_code,status,condition,
            purchase_cost_minor,selling_price_minor,acquired_on FROM watches WHERE archived_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 10""")]
        archived = self.conn().execute("SELECT count(*) FROM watches WHERE archived_at IS NOT NULL").fetchone()[0]
        return {**dict(row), "statuses": statuses, "brands": brands, "conditions": conditions, "aging": aging, "aging_days":bounds, "recent": recent, "archived":archived}

    def import_csv(self, raw: bytes, filename: str, username: str) -> dict:
        if len(raw) > MAX_BODY:
            raise ValueError("File exceeds 10 MB")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("CSV must use UTF-8 encoding") from exc
        reader = csv.DictReader(io.StringIO(text))
        required = {"brand", "model", "sku", "unit_code", "condition", "status"}
        if not reader.fieldnames or not required.issubset({x.strip() for x in reader.fieldnames}):
            raise ValueError("Missing required headers: " + ", ".join(sorted(required)))
        imported, errors = 0, []
        conn = self.conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            for number, row in enumerate(reader, start=2):
                if number > 5002:
                    errors.append({"row": number, "error": "Maximum 5,000 data rows"})
                    break
                try:
                    existing = conn.execute("SELECT id,version FROM watches WHERE unit_code=? COLLATE NOCASE", (row.get("unit_code", ""),)).fetchone()
                    payload = dict(row)
                    if existing:
                        payload["version"] = existing["version"]
                        self.update_watch(existing["id"], payload, username)
                    else:
                        self.create_watch(payload, username)
                    imported += 1
                except (ValueError, sqlite3.IntegrityError, Conflict) as exc:
                    errors.append({"row": number, "error": str(exc)[:250]})
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        digest = hashlib.sha256(raw).hexdigest()
        status = "completed" if not errors else "completed_with_errors"
        cur = conn.execute("INSERT INTO import_batches(filename,sha256,status,total_rows,imported_rows,error_rows,errors_json,username,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                           (Path(filename).name[:200], digest, status, imported + len(errors), imported, len(errors), json.dumps(errors), username, utc_now()))
        self.audit(username, "csv.imported", "import_batch", cur.lastrowid, {"rows": imported, "errors": len(errors), "sha256": digest})
        return {"batch_id": cur.lastrowid, "imported": imported, "errors": errors}

    def export_csv(self, username: str) -> bytes:
        fields = ["brand", "model", "reference_number", "sku", "unit_code", "serial_number", "condition", "status", "purchase_cost", "selling_price", "currency", "location", "notes", "acquired_on"]
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\r\n")
        writer.writeheader()
        rows = self.watches()
        for r in rows:
            record = {k: r.get(k, "") for k in fields}
            record["purchase_cost"] = f"{r['purchase_cost_minor'] / 100:.2f}"
            record["selling_price"] = f"{r['selling_price_minor'] / 100:.2f}"
            writer.writerow({k: csv_safe(v) for k, v in record.items()})
        payload = ("\ufeff" + output.getvalue()).encode("utf-8")
        self.audit(username, "csv.exported", "watch", detail={"rows": len(rows), "sha256": hashlib.sha256(payload).hexdigest()})
        return payload


class Conflict(Exception):
    pass


def clean_text(value: object, name: str, required: bool = False, maximum: int = 500) -> str:
    text = "" if value is None else str(value).strip()
    if required and not text:
        raise ValueError(f"{name} is required")
    if len(text) > maximum or any(ord(c) < 32 and c not in "\t\n\r" for c in text):
        raise ValueError(f"{name} is invalid or too long")
    return text


def money_to_minor(value: object) -> int:
    try:
        text = str(value or "0").strip().replace("$", "").replace(",", "")
        if not re.fullmatch(r"\d+(\.\d{1,2})?", text): raise ValueError
        amount = int((Decimal(text).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) * 100))
    except (ValueError, InvalidOperation, OverflowError) as exc:
        raise ValueError("Money value is invalid") from exc
    if not 0 <= amount <= 1_000_000_000:
        raise ValueError("Money value is outside the allowed range")
    return amount


def validate_date(value: object, name: str, allow_future: bool) -> str | None:
    text=clean_text(value,name,False,10) or None
    if not text: return None
    try: parsed=dt.date.fromisoformat(text)
    except ValueError as exc: raise ValueError(f"{name} must be a valid date") from exc
    if not allow_future and parsed>dt.date.today(): raise ValueError(f"{name} cannot be in the future")
    return text


def validate_watch(data: dict) -> dict:
    condition = clean_text(data.get("condition"), "Condition", True, 20)
    status = clean_text(data.get("status"), "Status", True, 20)
    if condition not in {"New", "Excellent", "Very good", "Good", "Fair"}:
        raise ValueError("Condition is not allowed")
    if status not in {"Available", "Reserved", "Sold", "Quarantine", "Repair"}:
        raise ValueError("Status is not allowed")
    acquired_on = validate_date(data.get("acquired_on"),"Acquired date",False)
    sku = clean_text(data.get("sku"), "SKU", True, 80)
    unit_code = clean_text(data.get("unit_code"), "Unit code", True, 80)
    code_pattern = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{1,79}$")
    if not code_pattern.fullmatch(sku): raise ValueError("SKU may use letters, numbers, dots, dashes, underscores, and slashes")
    if not code_pattern.fullmatch(unit_code): raise ValueError("Unit code may use letters, numbers, dots, dashes, underscores, and slashes")
    def minor(field: str) -> int:
        if field+"_minor" in data:
            try: value = int(data[field+"_minor"])
            except (ValueError,TypeError) as exc: raise ValueError("Money value is invalid") from exc
            if not 0<=value<=1_000_000_000: raise ValueError("Money value is outside the allowed range")
            return value
        return money_to_minor(data.get(field,0))
    return {
        "brand": clean_text(data.get("brand"), "Brand", True, 100),
        "model": clean_text(data.get("model"), "Model", True, 150),
        "reference_number": clean_text(data.get("reference_number"), "Reference", False, 100) or None,
        "sku": sku, "unit_code": unit_code,
        "serial_number": clean_text(data.get("serial_number"), "Serial number", False, 120) or None,
        "condition": condition, "status": status,
        "purchase_cost_minor": minor("purchase_cost"),
        "selling_price_minor": minor("selling_price"),
        "location": clean_text(data.get("location") or "Main inventory", "Location", True, 100),
        "notes": clean_text(data.get("notes"), "Notes", False, 2000) or None,
        "acquired_on": acquired_on,
    }


@dataclass
class Session:
    username: str
    csrf: str
    expires_at: float


class App:
    def __init__(self, data_dir: Path, static_dir: Path):
        self.data_dir = data_dir
        self.static_dir = static_dir
        self.store = Store(data_dir / "inventory.sqlite3")
        self.sessions: dict[str, Session] = {}
        self.failures: dict[str, tuple[int, float]] = {}

    def new_session(self, username: str) -> tuple[str, Session]:
        sid = secrets.token_urlsafe(32)
        session = Session(username, secrets.token_urlsafe(24), time.time() + SESSION_SECONDS)
        self.sessions[sid] = session
        return sid, session

    def get_session(self, sid: str | None) -> Session | None:
        session = self.sessions.get(sid or "")
        if not session or session.expires_at < time.time():
            if sid:
                self.sessions.pop(sid, None)
            return None
        session.expires_at = time.time() + SESSION_SECONDS
        return session


class Handler(BaseHTTPRequestHandler):
    server_version = "ChronicleLocal/0.1"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def json_response(self, status: int, data: dict | list, cookie: str | None = None) -> None:
        payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(payload)

    def error(self, status: int, message: str) -> None:
        self.json_response(status, {"error": message})

    def body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid content length") from exc
        if length < 0 or length > MAX_BODY:
            raise ValueError("Request exceeds 10 MB")
        return self.rfile.read(length)

    def json_body(self) -> dict:
        if "application/json" not in self.headers.get("Content-Type", ""):
            raise ValueError("Content-Type must be application/json")
        try:
            data = json.loads(self.body().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def cookie_sid(self) -> str | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        return cookie.get("chronicle_session").value if cookie.get("chronicle_session") else None

    def session(self, csrf: bool = False) -> Session | None:
        session = self.app.get_session(self.cookie_sid())
        if not session:
            self.error(HTTPStatus.UNAUTHORIZED, "Sign in required")
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session.csrf):
            self.error(HTTPStatus.FORBIDDEN, "CSRF validation failed")
            return None
        return session

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/status":
                session = self.app.get_session(self.cookie_sid())
                return self.json_response(200, {"api_version": 3, "setup_required": self.app.store.user_count() == 0, "authenticated": bool(session), "username": session.username if session else None, "csrf": session.csrf if session else None})
            if parsed.path == "/api/watches":
                session = self.session()
                if session:
                    params = parse_qs(parsed.query)
                    q = params.get("q", [""])[0][:100]
                    status = params.get("status", [""])[0]
                    condition = params.get("condition", [""])[0]
                    sort = params.get("sort", ["newest"])[0]
                    include_archived = params.get("archived", ["0"])[0] == "1"
                    self.json_response(200, self.app.store.watches(q,status,condition,include_archived,sort))
                return
            if parsed.path == "/api/settings/inventory":
                if self.session(): self.json_response(200, {"aging_days":self.app.store.aging_days()})
                return
            if parsed.path == "/api/dashboard":
                if self.session():
                    self.json_response(200, self.app.store.dashboard())
                return
            if parsed.path == "/api/suppliers":
                if self.session(): self.json_response(200,self.app.store.suppliers())
                return
            if parsed.path == "/api/purchase-orders":
                if self.session(): self.json_response(200,self.app.store.purchase_orders())
                return
            if parsed.path == "/api/export.csv":
                session = self.session()
                if not session:
                    return
                payload = self.app.store.export_csv(session.username)
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="chronicle-inventory.csv"')
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers(); self.wfile.write(payload); return
            self.serve_static(parsed.path)
        except Exception as exc:
            self.error(500, "Unexpected local server error")
            print("GET error:", repr(exc), file=sys.stderr)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            if path == "/api/setup":
                if self.app.store.user_count() != 0:
                    return self.error(409, "Account already configured")
                data = self.json_body(); self.app.store.create_user(data.get("username", ""), data.get("password", ""))
                sid, session = self.app.new_session(data["username"].strip())
                return self.json_response(201, {"username": session.username, "csrf": session.csrf}, f"chronicle_session={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}")
            if path == "/api/login":
                data = self.json_body(); ip = self.client_address[0]; count, until = self.app.failures.get(ip, (0, 0))
                if until > time.time():
                    return self.error(429, "Too many attempts; wait before trying again")
                if not self.app.store.authenticate(data.get("username", ""), data.get("password", "")):
                    count += 1; self.app.failures[ip] = (count, time.time() + (60 if count >= 5 else 0))
                    return self.error(401, "Invalid username or password")
                self.app.failures.pop(ip, None); sid, session = self.app.new_session(data["username"].strip())
                return self.json_response(200, {"username": session.username, "csrf": session.csrf}, f"chronicle_session={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}")
            if path == "/api/logout":
                session = self.session(csrf=True)
                if not session: return
                self.app.sessions.pop(self.cookie_sid() or "", None)
                return self.json_response(200, {"ok": True}, "chronicle_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            if path == "/api/change-password":
                session = self.session(csrf=True)
                if not session: return
                data = self.json_body()
                self.app.store.change_password(session.username, data.get("current_password", ""), data.get("new_password", ""))
                self.app.sessions.clear()
                return self.json_response(200, {"ok": True}, "chronicle_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
            if path == "/api/watches":
                session = self.session(csrf=True)
                if session:
                    self.json_response(201, self.app.store.create_watch(self.json_body(), session.username))
                return
            if path == "/api/suppliers":
                session=self.session(csrf=True)
                if session: self.json_response(201,self.app.store.create_supplier(self.json_body(),session.username))
                return
            if path == "/api/purchase-orders":
                session=self.session(csrf=True)
                if session: self.json_response(201,self.app.store.create_purchase_order(self.json_body(),session.username))
                return
            if path.startswith("/api/watches/") and path.endswith("/archive"):
                session = self.session(csrf=True)
                if not session: return
                watch_id = int(path.split("/")[3]); self.app.store.archive_watch(watch_id, session.username)
                return self.json_response(200, {"ok":True})
            if path == "/api/settings/inventory":
                session = self.session(csrf=True)
                if not session: return
                days = self.app.store.set_aging_days(self.json_body().get("aging_days"), session.username)
                return self.json_response(200, {"aging_days":days})
            if path == "/api/import.csv":
                session = self.session(csrf=True)
                if not session: return
                filename = Path(self.headers.get("X-Filename", "inventory.csv")).name
                if not filename.lower().endswith(".csv"):
                    return self.error(415, "Only CSV import is enabled in this dependency-free build")
                return self.json_response(200, self.app.store.import_csv(self.body(), filename, session.username))
            self.error(404, "Not found")
        except Conflict as exc:
            self.error(409, str(exc))
        except sqlite3.IntegrityError:
            self.error(409, "Unit code already exists")
        except ValueError as exc:
            self.error(400, str(exc))
        except Exception as exc:
            self.error(500, "Unexpected local server error")
            print("POST error:", repr(exc), file=sys.stderr)

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/watches/"):
            return self.error(404, "Not found")
        session = self.session(csrf=True)
        if not session: return
        try:
            watch_id = int(path.rsplit("/", 1)[1])
            self.json_response(200, self.app.store.update_watch(watch_id, self.json_body(), session.username))
        except Conflict as exc: self.error(409, str(exc))
        except sqlite3.IntegrityError: self.error(409, "Unit code already exists")
        except (ValueError, TypeError) as exc: self.error(400, str(exc))

    def serve_static(self, url_path: str) -> None:
        name = "index.html" if url_path in ("", "/") else url_path.lstrip("/")
        if name not in {"index.html", "app.js", "style.css"}:
            return self.error(404, "Not found")
        path = self.app.static_dir / name
        if not path.is_file(): return self.error(404, "Not found")
        payload = path.read_bytes(); content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type", content_type); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)


def default_data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return base / "ChronicleInventory" / "data"


def main() -> None:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir", type=Path, default=default_data_dir())
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    if args.host not in LOOPBACK:
        parser.error("Privacy protection: host must be 127.0.0.1, ::1, or localhost")
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535")
    static_dir = Path(__file__).resolve().parent / "static"
    app = App(args.data_dir.resolve(), static_dir)
    server = ThreadingHTTPServer((args.host, args.port), Handler); server.app = app  # type: ignore[attr-defined]
    url = f"http://127.0.0.1:{args.port}"
    print(f"{APP_NAME} is private on this PC at {url}")
    print(f"Data: {app.data_dir}")
    if not args.no_browser: threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()


if __name__ == "__main__":
    main()
