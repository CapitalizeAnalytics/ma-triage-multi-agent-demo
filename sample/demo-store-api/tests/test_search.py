"""Tests for the order search route."""
import sqlite3

import app.db
from app.main import app as flask_app

SEED_EMAILS = ["ana@example.com", "li@example.com"]


def seed(conn):
    conn.execute("CREATE TABLE orders (id INTEGER, customer_email TEXT, total REAL, status TEXT)")
    for i, email in enumerate(SEED_EMAILS):
        conn.execute(f"INSERT INTO orders VALUES ({i}, '{email}', 10.0, 'OPEN')")
    conn.commit()


def test_search_returns_only_matching_customer(tmp_path, monkeypatch):
    db_file = tmp_path / "orders.db"
    monkeypatch.setattr(app.db, "DB_PATH", str(db_file))
    seed(sqlite3.connect(db_file))
    client = flask_app.test_client()
    resp = client.get("/orders/search", query_string={"customer": "ana@example.com"})
    assert resp.status_code == 200
    assert len(resp.get_json()) == 1
