from app.main import app


def test_orders_history_route_precedes_order_id():
    paths = [getattr(r, "path", "") for r in app.router.routes]
    assert "/orders/history" in paths
    assert "/orders/{order_id}" in paths
    assert paths.index("/orders/history") < paths.index("/orders/{order_id}")
