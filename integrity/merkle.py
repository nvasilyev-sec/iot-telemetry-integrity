"""Ordered Merkle tree; an unpaired node is promoted unchanged."""
from hashlib import sha256


def leaf(record: bytes) -> bytes:
    return sha256(b'\x00' + record).digest()


def branch(left: bytes, right: bytes) -> bytes:
    return sha256(b'\x01' + left + right).digest()


class MerkleTree:
    def __init__(self, records):
        bottom = [leaf(record) for record in records]
        if not bottom:
            raise ValueError('empty datasets are not supported')
        self.layers = [bottom]
        while len(self.layers[-1]) > 1:
            nodes = self.layers[-1]
            self.layers.append([branch(nodes[i], nodes[i+1]) if i+1 < len(nodes)
                                else nodes[i] for i in range(0, len(nodes), 2)])

    @property
    def root(self):
        return self.layers[-1][0].hex()

    def proof(self, index):
        if type(index) is not int or not 0 <= index < len(self.layers[0]):
            raise ValueError('index outside dataset')
        path = []
        for nodes in self.layers[:-1]:
            sibling = index ^ 1
            if sibling < len(nodes):
                path.append(nodes[sibling].hex())
            index //= 2
        return path


def decode_digest(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('invalid SHA-256 digest')
    return bytes.fromhex(value)


def verify_path(record, index, count, path, root):
    if type(index) is not int or type(count) is not int or not 0 <= index < count:
        raise ValueError('invalid proof index or record count')
    if not isinstance(path, list):
        raise ValueError('proof path must be a list')
    node = leaf(record)
    used = 0
    width = count
    while width > 1:
        if (index ^ 1) < width:
            if used == len(path):
                raise ValueError('missing sibling')
            sibling = decode_digest(path[used])
            node = branch(sibling, node) if index % 2 else branch(node, sibling)
            used += 1
        index //= 2
        width = (width + 1) // 2
    return used == len(path) and node == decode_digest(root)
