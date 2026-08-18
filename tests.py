import http.client
import json
import tempfile
import threading
import unittest
import sqlite3
import datetime as dt
from pathlib import Path

from server import App, Handler, ThreadingHTTPServer, csv_safe, password_hash, password_verify


class LiveAppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(__file__).resolve().parent
        cls.app = App(Path(cls.temp.name), root / "static")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.app = cls.app
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(timeout=2); cls.app.store.close(); cls.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        payload = body
        if isinstance(body, dict):
            payload = json.dumps(body).encode(); headers = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, path, body=payload, headers=headers or {})
        response = conn.getresponse(); raw = response.read(); response_headers = dict(response.getheaders()); conn.close()
        data = json.loads(raw) if "application/json" in response_headers.get("Content-Type", "") else raw
        return response.status, response_headers, data

    def test_01_security_headers_and_setup(self):
        status, headers, data = self.request("GET", "/api/status")
        self.assertEqual(status, 200); self.assertTrue(data["setup_required"]); self.assertEqual(data["api_version"], 3)
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        status, headers, data = self.request("POST", "/api/setup", {"username": "owner", "password": "A-secure-local-password-123"})
        self.assertEqual(status, 201); self.assertIn("HttpOnly", headers["Set-Cookie"]); self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        self.__class__.cookie = headers["Set-Cookie"].split(";", 1)[0]; self.__class__.csrf = data["csrf"]

    def test_02_auth_and_csrf_required(self):
        status, _, _ = self.request("GET", "/api/watches")
        self.assertEqual(status, 401)
        status, _, _ = self.request("POST", "/api/watches", {"brand": "Omega"}, {"Cookie": self.cookie})
        self.assertEqual(status, 403)

    def test_03_create_search_update_dashboard(self):
        headers = {"Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        watch = {"brand":"Omega","model":"Seamaster 300M","reference_number":"210.30","sku":"OMG-SM-001","unit_code":"U-0001","serial_number":"ABC123","condition":"Excellent","status":"Available","purchase_cost":"4120.00","selling_price":"5950.00","location":"Main inventory","notes":"Second-hand","acquired_on":"2026-08-01"}
        status, _, created = self.request("POST", "/api/watches", watch, headers)
        self.assertEqual(status, 201); self.assertEqual(created["purchase_cost_minor"], 412000)
        status, _, rows = self.request("GET", "/api/watches?q=Seamaster", headers={"Cookie": self.cookie})
        self.assertEqual(status, 200); self.assertEqual(len(rows), 1)
        watch.update({"version":created["version"], "status":"Reserved"})
        status, _, updated = self.request("PUT", f"/api/watches/{created['id']}", watch, headers)
        self.assertEqual(status, 200); self.assertEqual(updated["status"], "Reserved")
        status, _, dashboard = self.request("GET", "/api/dashboard", headers={"Cookie": self.cookie})
        self.assertEqual(dashboard["units"], 1); self.assertEqual(dashboard["reserved"], 1)
        self.assertEqual(dashboard["retail_value_minor"], 595000); self.assertEqual(dashboard["potential_profit_minor"], 183000)
        self.assertEqual(dashboard["statuses"][0]["label"], "Reserved"); self.assertEqual(len(dashboard["recent"]), 1)

    def test_04_csv_import_update_and_export(self):
        headers = {"Cookie":self.cookie,"X-CSRF-Token":self.csrf,"Content-Type":"text/csv","X-Filename":"inventory.csv"}
        csv_data = b"brand,model,sku,unit_code,condition,status,purchase_cost,selling_price,notes\r\nOmega,Seamaster 300M,OMG-SM-001,U-0001,Excellent,Available,4200.00,6100.00,Updated\r\nTudor,Black Bay 58,TDR-BB-001,U-0002,New,Available,3000.00,4200.00,New unit\r\n"
        status, _, result = self.request("POST", "/api/import.csv", csv_data, headers)
        self.assertEqual(status, 200); self.assertEqual(result["imported"], 2); self.assertEqual(result["errors"], [])
        status, headers, payload = self.request("GET", "/api/export.csv", headers={"Cookie":self.cookie})
        self.assertEqual(status, 200); self.assertIn(b"Tudor", payload); self.assertIn("attachment", headers["Content-Disposition"])

    def test_05_same_sku_multiple_units_but_unit_code_unique(self):
        headers = {"Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        second = {"brand":"Omega","model":"Seamaster 300M","sku":"OMG-SM-001","unit_code":"U-0003","condition":"Good","status":"Available","purchase_cost":"3900.00","selling_price":"5500.00"}
        status, _, created = self.request("POST", "/api/watches", second, headers)
        self.assertEqual(status, 201); self.assertEqual(created["sku"], "OMG-SM-001")
        duplicate_unit = {**second, "sku":"DIFFERENT-SKU"}
        status, _, data = self.request("POST", "/api/watches", duplicate_unit, headers)
        self.assertEqual(status, 409); self.assertIn("Unit code", data["error"])

    def test_06_validation_and_formula_safety(self):
        self.assertEqual(csv_safe("=2+2"), "'=2+2")
        headers = {"Cookie":self.cookie,"X-CSRF-Token":self.csrf}
        bad = {"brand":"X","model":"Y","sku":"BAD","unit_code":"BAD","condition":"Unknown","status":"Available"}
        status, _, _ = self.request("POST", "/api/watches", bad, headers)
        self.assertEqual(status, 400)
        future = {"brand":"Seiko","model":"Future Watch","sku":"FUTURE-SKU","unit_code":"FUTURE-UNIT","condition":"New","status":"Available","acquired_on":(dt.date.today()+dt.timedelta(days=1)).isoformat()}
        status, _, data = self.request("POST", "/api/watches", future, headers)
        self.assertEqual(status, 400); self.assertIn("future", data["error"].lower())
        invalid_date = {**future, "unit_code":"INVALID-DATE-UNIT", "acquired_on":"2026-02-30"}
        status, _, data = self.request("POST", "/api/watches", invalid_date, headers)
        self.assertEqual(status, 400); self.assertIn("valid date", data["error"].lower())

    def test_07_filters_archive_settings_and_whole_dollars(self):
        headers = {"Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        whole = {"brand":"Citizen","model":"Promaster","sku":"CIT-PRO-1","unit_code":"U-WHOLE-DOLLARS","condition":"Very good","status":"Repair","purchase_cost":"325","selling_price":"495"}
        status, _, created = self.request("POST", "/api/watches", whole, headers)
        self.assertEqual(status, 201); self.assertEqual(created["purchase_cost_minor"], 32500); self.assertEqual(created["selling_price_minor"], 49500)
        status, _, rows = self.request("GET", "/api/watches?status=Repair&condition=Very%20good&sort=cost_high", headers={"Cookie":self.cookie})
        self.assertEqual(status, 200); self.assertEqual([r["unit_code"] for r in rows], ["U-WHOLE-DOLLARS"])
        status, _, data = self.request("POST", "/api/settings/inventory", {"aging_days":[15,45,120]}, headers)
        self.assertEqual(status, 200); self.assertEqual(data["aging_days"], [15,45,120])
        status, _, _ = self.request("POST", f"/api/watches/{created['id']}/archive", {}, headers)
        self.assertEqual(status, 200)
        status, _, active = self.request("GET", "/api/watches?q=U-WHOLE-DOLLARS", headers={"Cookie":self.cookie})
        self.assertEqual(active, [])
        status, _, archived = self.request("GET", "/api/watches?q=U-WHOLE-DOLLARS&archived=1", headers={"Cookie":self.cookie})
        self.assertEqual(len(archived), 1); self.assertIsNotNone(archived[0]["archived_at"])

    def test_08_suppliers_and_purchase_orders(self):
        headers = {"Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        status, _, supplier = self.request("POST", "/api/suppliers", {"name":"Authorized Watch Distributor","email":"orders@example.com","website":"https://example.com","status":"Active"}, headers)
        self.assertEqual(status, 201)
        order = {"po_number":"PO-TEST-001","supplier_id":supplier["id"],"status":"Ordered","order_date":dt.date.today().isoformat(),"expected_date":(dt.date.today()+dt.timedelta(days=7)).isoformat(),"shipping":"25.00","tax":"10.00","lines":[{"description":"Seiko Prospex","sku":"SEI-PRO","quantity":2,"unit_cost":"300.00"}]}
        status, _, _ = self.request("POST", "/api/purchase-orders", order, headers)
        self.assertEqual(status, 201)
        status, _, orders = self.request("GET", "/api/purchase-orders", headers={"Cookie":self.cookie})
        self.assertEqual(status, 200); self.assertEqual(orders[0]["total_quantity"], 2); self.assertEqual(orders[0]["total_minor"], 63500)
        status, _, suppliers = self.request("GET", "/api/suppliers", headers={"Cookie":self.cookie})
        self.assertEqual(suppliers[0]["purchase_order_count"], 1)
        bad = {**order, "po_number":"PO-TEST-002", "expected_date":(dt.date.today()-dt.timedelta(days=1)).isoformat()}
        status, _, data = self.request("POST", "/api/purchase-orders", bad, headers)
        self.assertEqual(status, 400); self.assertIn("before order date", data["error"])

    def test_09_change_password_invalidates_session(self):
        headers = {"Cookie": self.cookie, "X-CSRF-Token": self.csrf}
        status, response_headers, data = self.request("POST", "/api/change-password", {"current_password":"A-secure-local-password-123","new_password":"A-different-local-password-456"}, headers)
        self.assertEqual(status, 200); self.assertIn("Max-Age=0", response_headers["Set-Cookie"])
        status, _, _ = self.request("GET", "/api/watches", headers={"Cookie":self.cookie})
        self.assertEqual(status, 401)
        status, headers, data = self.request("POST", "/api/login", {"username":"owner","password":"A-different-local-password-456"})
        self.assertEqual(status, 200)


class PasswordTest(unittest.TestCase):
    def test_scrypt_hash(self):
        encoded = password_hash("A-secure-local-password-123")
        self.assertTrue(password_verify("A-secure-local-password-123", encoded))
        self.assertFalse(password_verify("wrong-password-value", encoded))
        self.assertNotIn("A-secure-local-password-123", encoded)

    def test_legacy_unique_sku_database_migrates(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "inventory.sqlite3"
            conn = sqlite3.connect(path)
            conn.executescript("""CREATE TABLE watches (
              id INTEGER PRIMARY KEY, brand TEXT NOT NULL, model TEXT NOT NULL, reference_number TEXT,
              sku TEXT NOT NULL UNIQUE COLLATE NOCASE, unit_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
              serial_number TEXT, condition TEXT NOT NULL, status TEXT NOT NULL,
              purchase_cost_minor INTEGER NOT NULL DEFAULT 0, selling_price_minor INTEGER NOT NULL DEFAULT 0,
              currency TEXT NOT NULL DEFAULT 'USD', location TEXT NOT NULL DEFAULT 'Main inventory', notes TEXT,
              acquired_on TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1);
              INSERT INTO watches(brand,model,sku,unit_code,condition,status,created_at,updated_at)
              VALUES('Seiko','Prospex','SEI-PRO','U-1','New','Available','now','now');""")
            conn.close()
            store = App(Path(folder), Path(__file__).resolve().parent / "static").store
            store.conn().execute("INSERT INTO watches(brand,model,sku,unit_code,condition,status,created_at,updated_at) VALUES('Seiko','Prospex','SEI-PRO','U-2','New','Available','now','now')")
            self.assertEqual(store.conn().execute("SELECT count(*) FROM watches WHERE sku='SEI-PRO'").fetchone()[0], 2)
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
