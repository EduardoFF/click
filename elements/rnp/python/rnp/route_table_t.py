"""LCM type definitions
This file automatically generated by lcm.
DO NOT MODIFY BY HAND!!!!
"""

try:
    import cStringIO.StringIO as BytesIO
except ImportError:
    from io import BytesIO
import struct

import rnp.route_entry_t

class route_table_t(object):
    __slots__ = ["node", "n", "entries"]

    def __init__(self):
        self.node = ""
        self.n = 0
        self.entries = []

    def encode(self):
        buf = BytesIO()
        buf.write(route_table_t._get_packed_fingerprint())
        self._encode_one(buf)
        return buf.getvalue()

    def _encode_one(self, buf):
        __node_encoded = self.node.encode('utf-8')
        buf.write(struct.pack('>I', len(__node_encoded)+1))
        buf.write(__node_encoded)
        buf.write(b"\0")
        buf.write(struct.pack(">i", self.n))
        for i0 in range(self.n):
            assert self.entries[i0]._get_packed_fingerprint() == rnp.route_entry_t._get_packed_fingerprint()
            self.entries[i0]._encode_one(buf)

    def decode(data):
        if hasattr(data, 'read'):
            buf = data
        else:
            buf = BytesIO(data)
        if buf.read(8) != route_table_t._get_packed_fingerprint():
            raise ValueError("Decode error")
        return route_table_t._decode_one(buf)
    decode = staticmethod(decode)

    def _decode_one(buf):
        self = route_table_t()
        __node_len = struct.unpack('>I', buf.read(4))[0]
        self.node = buf.read(__node_len)[:-1].decode('utf-8', 'replace')
        self.n = struct.unpack(">i", buf.read(4))[0]
        self.entries = []
        for i0 in range(self.n):
            self.entries.append(rnp.route_entry_t._decode_one(buf))
        return self
    _decode_one = staticmethod(_decode_one)

    _hash = None
    def _get_hash_recursive(parents):
        if route_table_t in parents: return 0
        newparents = parents + [route_table_t]
        tmphash = (0x7736c24c73b46136+ rnp.route_entry_t._get_hash_recursive(newparents)) & 0xffffffffffffffff
        tmphash  = (((tmphash<<1)&0xffffffffffffffff)  + (tmphash>>63)) & 0xffffffffffffffff
        return tmphash
    _get_hash_recursive = staticmethod(_get_hash_recursive)
    _packed_fingerprint = None

    def _get_packed_fingerprint():
        if route_table_t._packed_fingerprint is None:
            route_table_t._packed_fingerprint = struct.pack(">Q", route_table_t._get_hash_recursive([]))
        return route_table_t._packed_fingerprint
    _get_packed_fingerprint = staticmethod(_get_packed_fingerprint)

