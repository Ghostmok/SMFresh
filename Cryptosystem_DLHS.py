import hashlib
import secrets
from Crypto.Util.number import getPrime


p = getPrime(128)
g = 3

sk = secrets.randbelow(p - 2) + 1
pk = pow(g, sk, p)


def normalize(e):
    if isinstance(e, tuple) and len(e) == 2:
        return str(tuple(sorted(e)))
    return str(e)


def e_to_scalar(e):
    norm_e = normalize(e)
    e_hash = int(hashlib.sha256(norm_e.encode()).hexdigest(), 16)
    return e_hash
