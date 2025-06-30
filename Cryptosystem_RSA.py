import hashlib
import numpy as np
import random
import secrets
from sympy import mod_inverse, randprime


def generate_prime(bits):
    return randprime(2**(bits - 1), 2**bits)


def generate_rsa_p_q(bits):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)
    return p, q


def generate_rsa_keys(e=65537):
    p, q = generate_rsa_p_q(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    assert (e * d) % phi == 1, "Invalid RSA Key Pair"
    return n, e, d

N, E, D = generate_rsa_keys()


class CuckooFilter:
    def __init__(self, capacity, bucket_size=4, max_kicks=10**5):
        self.num_bucket = capacity
        self.bucket_size = bucket_size
        self.max_kicks = max_kicks
        self.fp_size = 12
        self.fp_mask = (1 << self.fp_size) - 1
        self.table = np.zeros((self.num_bucket, self.bucket_size), dtype=np.uint16)
        self.item_count = 0

    @staticmethod
    def to_int_hash(data_bytes, salt=b''):
        hasher = hashlib.sha256()
        hasher.update(salt)
        hasher.update(data_bytes)
        digest = hasher.digest()
        return int.from_bytes(digest[:8], byteorder='big', signed=False)

    def get_fp_and_indices(self, e):
        e_bytes = str(e).encode('utf-8')
        fp_val = self.to_int_hash(e_bytes, salt=b"fp_salt_")
        fp = fp_val & self.fp_mask
        fp = fp if fp != 0 else 1
        idx1 = self.to_int_hash(e_bytes, salt=b"idx1_salt_") % self.num_bucket
        fp_bytes = int(fp).to_bytes((self.fp_size + 7) // 8, 'big')
        fp_hash = self.to_int_hash(fp_bytes, salt=b"idx2_salt_")
        idx2 = (idx1 ^ fp_hash) % self.num_bucket
        return fp, idx1, idx2

    def get_alternate_idx(self, idx, fp):
        fp_bytes = int(fp).to_bytes((self.fp_size + 7) // 8, 'big')
        fp_hash = self.to_int_hash(fp_bytes, salt=b"idx2_salt_")
        return (idx ^ fp_hash) % self.num_bucket

    def insert(self, e):
        fp, idx1, idx2 = self.get_fp_and_indices(e)
        if np.any(self.table[idx1] == 0):
            empty_slot = np.where(self.table[idx1] == 0)[0][0]
            self.table[idx1, empty_slot] = fp
            self.item_count += 1
            return True
        if np.any(self.table[idx2] == 0):
            empty_slot = np.where(self.table[idx2] == 0)[0][0]
            self.table[idx2, empty_slot] = fp
            self.item_count += 1
            return True
        f = fp
        current_idx = random.choice([idx1, idx2])
        for _ in range(self.max_kicks):
            kick_slot = secrets.choice(range(self.bucket_size))
            f, self.table[current_idx, kick_slot] = self.table[current_idx, kick_slot], f
            current_idx = self.get_alternate_idx(current_idx, f)
            if np.any(self.table[current_idx] == 0):
                empty_slot = np.where(self.table[current_idx] == 0)[0][0]
                self.table[current_idx, empty_slot] = f
                self.item_count += 1
                return True
        return False

    def delete(self, s):
        deleted_count = 0
        for e in s:
            fp, idx1, idx2 = self.get_fp_and_indices(e)
            for i in range(self.bucket_size):
                if self.table[idx1, i] == fp:
                    self.table[idx1, i] = 0
                    self.item_count -= 1
                    deleted_count += 1
            for i in range(self.bucket_size):
                if self.table[idx2, i] == fp:
                    self.table[idx2, i] = 0
                    self.item_count -= 1
                    deleted_count += 1
        return deleted_count

    def seek(self, element):
        fp, idx1, idx2 = self.get_fp_and_indices(element)
        if np.any(self.table[idx1] == fp) or np.any(self.table[idx2] == fp):
            return True
        return False


def Reinsertion(cf, s, verbose, threshold=10, max_retries=22):
    retry_count = 0
    previous_missing = float('inf')
    while retry_count < max_retries:
        missing_elements = {e for e in s if not cf.seek(e)}
        current_missing = len(missing_elements)
        if not missing_elements:
            if verbose: print("✅ No missing elements found")
            break
        if current_missing < threshold:
            if verbose: print(f"✅ Found {current_missing} missing elements, which is below the threshold of {threshold}")
            break
        if current_missing > 1.5 * previous_missing:
            if verbose: print("⚠️ Re-insertion is causing more elements to be kicked out. Filter capacity might be too low")
            break
        if verbose: print(f"⚠️ Found {current_missing} missing elements. Re-inserting (Attempt {retry_count + 1}/{max_retries})...")
        previous_missing = current_missing
        for e in missing_elements:
            cf.insert(e)
        retry_count += 1
    else:
        if verbose: print("⚠️ Reached max retries, the filter's capacity might be too low")
    if verbose: print()
