import time
import json
import struct
from .const import *
from .utils import string_to_name
from .sign import sign
import hashlib

class Tx(object):
    def __init__(self):

        self.expiration = 0
        self.ref_block_num = 0
        self.ref_block_prefix = 0
        self.max_net_usage_words = 0
        self.max_kcpu_usage = 0
        self.delay_sec = 0
        self.context_free_actions = []
        self.actions = []
        self.transaction_extensions = []
        self.signatures = []
        self.context_free_data = []
        self.chain_id = CHAIN_ID
        self.input = None
        self.data = ""

    def to_json(self):
        pass

    def to_hex(self):
        self.serialize()
        return self.input.hex()

    def sign(self, prvkey):
        return sign(prvkey, self.input)

    def write(self, value):  # Initialize with string of bytes
        if self.input is None:
          self.input = value
        else:
          self.input += value

    def _read_num(self, format):
      (i,) = struct.unpack_from(format, self.input, self.read_cursor)
      self.read_cursor += struct.calcsize(format)
      return i

    def _write_num(self, format, num):
      s = struct.pack(format, num)
      self.write(s) 

    def read_compact_size(self):
      v = 0
      b = 0
      by = 0
      while True:
          b = self.read_uint8()
          v |= (b & 0x7f) << by
          by += 7
          if (( b & 0x80) and by < 32 ):
             continue
          else:
             break
      return v

    def write_compact_size(self, value):
      val = value
      while True:
        b = val & 0x7f
        val >>= 7
        b |= ((val > 0) << 7)
        self.write_uint8(b)
        if not val:
     
    def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
    def read_int16  (self): return self._read_num('<h')
    def read_uint16 (self): return self._read_num('<H')
    def read_int32  (self): return self._read_num('<i')
    def read_uint32 (self): return self._read_num('<I')
    def read_int64  (self): return self._read_num('<q')
    def read_uint64 (self): return self._read_num('<Q')

    def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
    def write_int8   (self, val): return self._write_num('<b', val)
    def write_uint8  (self, val): return self._write_num('<B', val)
    def write_int16  (self, val): return self._write_num('<h', val)
    def write_uint16 (self, val): return self._write_num('<H', val)
    def write_int32  (self, val): return self._write_num('<i', val)
    def write_uint32 (self, val): return self._write_num('<I', val)
    def write_int64  (self, val): return self._write_num('<q', val)
    def write_uint64 (self, val): return self._write_num('<Q', val)

    def write_permission(self, val_list):
        self.write_compact_size(len(val_list))
        for i in val_list:
            self.write_uint64(string_to_name(i["actor"]))
            self.write_uint64(string_to_name(i["permission"]))

    def write_data(self, val):
        bytes = bytearray.fromhex(val)
        self.write_compact_size(len(bytes))
        for i in bytes:
            self.write_uint8(i)

    def write_free_actions(self, val):
        self.write_compact_size(len(val))

    def serial_context_free_actions(self, val):
        self.write_compact_size(len(val))

    def serial_actions(self, act_list):
        self.write_compact_size(len(act_list))
        for act in act_list:
            self.write_uint64(string_to_name(act["account"]))
            self.write_uint64(string_to_name(act["name"]))
            self.write_permission(act["authorization"])
            if act["data"]:
                self.write_data(act["data"])
            else:
                self.write_compact_size(0)

    def serial_transaction_extensions(self, val):
        self.write_compact_size(len(val))

    def serialize(self):
        self.input = None
        self.write_uint32(self.expiration)
        self.write_uint16(self.ref_block_num)
        self.write_uint32(self.ref_block_prefix)
        self.write_compact_size(self.max_net_usage_words)
        self.write_compact_size(self.max_kcpu_usage)
        self.write_compact_size(self.delay_sec)
        self.serial_context_free_actions(self.context_free_actions)
        self.serial_actions(self.actions)
        self.serial_transaction_extensions(self.transaction_extensions)

    def get_digest(self):
        padding = bytearray([0 for n in range(32)])
        data = bytes.fromhex(self.chain_id) + self.input + padding
        sha = hashlib.sha256(data)
        return sha.digest()

    def signature(self, prv):
        digest = self.get_digest()
        return sign(prv, digest)

    def to_str(self):
        tx = {}
        expiration = time.strftime("%Y-%m-%dT%H:%M:%S.000",
                                   time.gmtime(self.expiration))
        tx["expiration"] = expiration
        tx["ref_block_num"] = self.ref_block_num
        tx["ref_block_prefix"] = self.ref_block_prefix
        tx["max_net_usage_words"] = self.max_net_usage_words
        tx["max_cpu_usage_ms"] = self.max_cpu_usage_ms
        tx["delay_sec"] = self.delay_sec
        tx["context_free_actions"] = self.context_free_actions
        tx["actions"] = self.actions
        tx["transaction_extensions"] = []
        tx["signatures"] = []
        tx["context_free_data"] = []
        return json.dumps(tx)
 
    def deserialize(self, f):
        # Fixme
        pass
