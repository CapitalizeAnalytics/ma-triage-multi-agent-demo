"""Database connection helper."""
import os
import sqlite3

DB_PATH = os.environ.get("ORDERS_DB", "orders.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
