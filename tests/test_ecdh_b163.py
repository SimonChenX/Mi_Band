import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from miband2021 import ecdh_b163 as e

ok = True
def check(name, cond):
    global ok
    print(("PASS " if cond else "FAIL ") + name)
    ok = ok and cond

check("base point on curve", e._on_curve(e.BASE_X, e.BASE_Y))
check("coeff_b / base_order computed", e.CURVE_B.bit_length() in range(160,164))

t=time.time()
inf = e._mul_point(e.BASE_X, e.BASE_Y, e.BASE_ORDER)
print("  base_order*G =", inf, " (%.2fs)" % (time.time()-t))
check("base_order*G == infinity", e._is_zero(*inf))

# ECDH round trip
a = os.urandom(24); b = os.urandom(24)
pubA = e.generate_public(a); pubB = e.generate_public(b)
check("generate_public returns 48 bytes", pubA is not None and len(pubA)==48 and len(pubB)==48)
check("pubA on curve", e._on_curve(int.from_bytes(pubA[:24],'little'), int.from_bytes(pubA[24:],'little')))
shA = e.generate_shared(a, pubB)
shB = e.generate_shared(b, pubA)
check("shared secrets match", shA is not None and shA == shB)
print("  shared =", shA.hex())
sys.exit(0 if ok else 1)
