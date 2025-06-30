import hashlib
from MerkleTree import MerkleTree


class Incremental_MerkleTree:
    def __init__(self, initial_list):
        self.initial_list = initial_list
        self.initial_tree = MerkleTree(self.initial_list)
        self.history = []
        self.root_hash = self.initial_tree.root_hash

    def recompute_root_hash(self):
        initial_root = int.from_bytes(bytes.fromhex(self.initial_tree.root_hash), 'big')
        addition_root = 0
        deletion_root = 0
        for op in self.history:
            tree = op['tree']
            tree_root = int.from_bytes(bytes.fromhex(tree.root_hash), 'big')
            if op['type'] == 'Addition':
                addition_root += tree_root
            elif op['type'] == 'Deletion':
                deletion_root += tree_root
        immht_root = hex(abs(initial_root + addition_root - deletion_root))[2:]
        if len(immht_root) % 2 != 0:
            immht_root = '0' + immht_root
        self.root_hash = immht_root

    def addition(self, s):
        self.history.append({'type': 'Addition', 'tree': MerkleTree(s)})
        self.recompute_root_hash()

    def deletion(self, s):
        self.history.append({'type': 'Deletion', 'tree': MerkleTree(s)})
        self.recompute_root_hash()

    @staticmethod
    def merge_hashes(hashes):
        sum_hash = 0
        for h in hashes:
            h = int.from_bytes(bytes.fromhex(h), 'big')
            sum_hash += h
        sum_hash = hex(sum_hash)[2:]
        if len(sum_hash) % 2 != 0:
            sum_hash = '0' + sum_hash
        return sum_hash

    def get_proof(self, e):
        e_hash = self.initial_tree.get_hash(e)
        sub_proof = None
        for op in reversed(self.history):
            tree = op['tree']
            if e_hash in tree.hash_to_index:
                if op['type'] == 'Deletion':
                    raise ValueError("Element exists in history but was removed")
                elif op['type'] == 'Addition':
                    sub_proof = tree.get_proof(e)
                    break
        if sub_proof is None:
            if e_hash in self.initial_tree.hash_to_index:
                sub_proof = self.initial_tree.get_proof(e)
            else:
                # raise ValueError("Element does not exist in the initial graph or any subsequent updates")
                print(f"😭Error: Element \033[31m{e}\033[0m does not exist in the graph.")
                return None
        addition_root_hashes = [op['tree'].root_hash for op in self.history if op['type'] == 'Addition']
        deletion_root_hashes = [op['tree'].root_hash for op in self.history if op['type'] == 'Deletion']
        merged_addition_root = self.merge_hashes(addition_root_hashes)
        merged_deletion_root = self.merge_hashes(deletion_root_hashes)
        immht_proof = {"element": e,
                       "sub_hash_chain": sub_proof["hash_chain"],
                       "sub_root": sub_proof["root_hash"],
                       "initial_root": self.initial_tree.root_hash,
                       "addition_root": merged_addition_root,
                       "deletion_root": merged_deletion_root,
                       "Root_Hash": self.root_hash if self.root_hash else "0"}
        return immht_proof

    @staticmethod
    def immht_recompute(immht_proof):
        if not isinstance(immht_proof, dict):
            print(f"😭Error: The provided proof is not a dictionary. Instead, it's of type {type(immht_proof)}")
            return "FA15E"
        e = immht_proof.get("element")
        sub_hash_chain = immht_proof.get("sub_hash_chain")
        claimed_sub_root = immht_proof.get("sub_root")
        minor_proof = {"element": e, "hash_chain": sub_hash_chain}
        recomputed_sub_root = MerkleTree.mht_recompute(minor_proof)
        if recomputed_sub_root != claimed_sub_root:
            raise ValueError("Sub-proof verification failed")
        try:
            initial_root = immht_proof["initial_root"]
            addition_root = immht_proof["addition_root"]
            deletion_root = immht_proof["deletion_root"]
            initial_root_val = int.from_bytes(bytes.fromhex(initial_root), 'big') if initial_root else 0
            addition_root_val = int.from_bytes(bytes.fromhex(addition_root), 'big') if addition_root else 0
            deletion_root_val = int.from_bytes(bytes.fromhex(deletion_root), 'big') if deletion_root else 0
            Recomputed_Root_Hash = abs(initial_root_val + addition_root_val - deletion_root_val)
            Recomputed_Root_Hash = hex(Recomputed_Root_Hash)[2:]
            if len(Recomputed_Root_Hash) % 2 != 0:
                Recomputed_Root_Hash = '0' + Recomputed_Root_Hash
            return Recomputed_Root_Hash
        except (KeyError, ValueError) as e:
            raise ValueError(f"Failed to compute final arithmetic root: {e}")