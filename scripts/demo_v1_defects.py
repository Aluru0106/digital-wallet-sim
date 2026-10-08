"""Reproduces defect DEF-01 (double spending) on v1 and shows v2 is fixed.

Run:  python -m scripts.demo_v1_defects
"""
import os
import tempfile
import threading
import uuid

os.chdir(tempfile.mkdtemp())
os.environ["DB_PATH"] = os.path.join(os.getcwd(), "v2.db")

from legacy import wallet_v1 as v1  # noqa: E402


def race(confirm_fn, n=10):
    out, barrier = [], threading.Barrier(n)

    def w():
        barrier.wait()
        out.append(confirm_fn())
    ts = [threading.Thread(target=w) for _ in range(n)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    return out


print("=== v1 (before) ===")
v1.init()
alice, shop = v1.register("alice", "pw"), v1.register("shop", "pw")
v1.add_funds(alice, 100)
pid = v1.initiate(alice, shop, 100)
res = race(lambda: v1.confirm(alice, pid))
print("confirm results :", res)
print("alice balance   :", v1.balance(alice), "| shop balance:", v1.balance(shop))
print("money created   :", v1.balance(alice) + v1.balance(shop) - 100)

print("\n=== v2 (after) ===")
from app import services  # noqa: E402
from app.db import init_db  # noqa: E402

init_db()
a = services.register_user("alice2", "Str0ng-Passw0rd!", "customer")
services.create_wallet(a)
services.add_funds(a, 10_000)
m = services.register_user("shop2", "Str0ng-Passw0rd!", "merchant")
mid = services.register_merchant(m, "Shop Two", "retail")["merchant_id"]
pid = services.initiate_payment(a, mid, 10_000, uuid.uuid4().hex)["payment_id"]


def c2():
    try:
        return services.confirm_payment(a, pid)["status"]
    except services.DomainError as e:
        return f"{e.status} {e.message}"


res = race(c2)
print("confirm results :", res)
print("alice balance   :", services.get_wallet(a)["balance"], "| shop balance:", services.get_wallet(m)["balance"])
