"""Background jobs run by the order service's worker process."""
from app.db import get_connection


def handle_refund_event(event):
    """Marks an order as refunded.

    Called by the refund queue consumer, which lives in the payments-service
    repository. payments-service publishes the event after a refund clears.
    """
    order_id = event["order_id"]
    conn = get_connection()
    query = f"UPDATE orders SET status = 'REFUNDED' WHERE id = '{order_id}'"
    conn.execute(query)
    conn.commit()
