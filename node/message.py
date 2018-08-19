import sys
import hashlib
import asyncore
import socket
import time
import calendar
import struct
import logging
import collections
from threading import Thread
import binascii
from pyeos.sign import *
import config
from secp256k1 import PrivateKey, PublicKey, ECDSA
from .peer import Peer
from pyeos.utils import string_to_name

# net_message type
HANDSHAKE_MESSAGE = 0
CHAIN_SIZE_MESSAGE = 1
GO_AWAY_MESSAGE = 2
TIME_MESSAGE = 3
NOTICE_MESSAGE = 4
REQUEST_MESSAGE = 5
SYNC_REQUEST_MESSAGE = 6
SIGNED_BLOCK =  7
PACKED_TRANSACTION = 8

class Message(object):

    def __init__(self):
        self.length = 0
        self.read_cursor = 0

    def write(self, value):  # Initialize with string of bytes
        if self.input is None:
          self.input = value
        else:
          self.input += value

    def read(self, length):
        data = self.input[self.read_cursor: self.read_cursor + length]
        self.read_cursor += length
        return data

    def _read_num(self, format):
      (i,) = struct.unpack_from(format, self.input, self.read_cursor)
      self.read_cursor += struct.calcsize(format)
      return i

    def _write_num(self, format, num):
      s = struct.pack(format, num)
      self.write(s) 

    def read_packed_uint32(self):
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

    def write_packed_uint32(self, value):
      val = value
      while True:
        b = val & 0x7f
        val >>= 7
        b |= ((val > 0) << 7)
        self.write_uint8(b)
        if not val:
           break

    def read_compact_size(self):
      size = ord(self.input[self.read_cursor])
      self.read_cursor += 1
      if size == 253:
        size = self._read_num('<H')
      elif size == 254:
        size = self._read_num('<I')
      elif size == 255:
        size = self._read_num('<Q')
      return size

    def write_compact_size(self, size):
      if size < 0:
        raise SerializationError("attempt to write size < 0")
      elif size < 253:
         self._write_num('<B', size)
      elif size < 2**16:
        self.write(b'\xfd')
        self._write_num('<H', size)
      elif size < 2**32:
        self.write(b'\xfe')
        self._write_num('<I', size)
      elif size < 2**64:
        self.write(b'\xff')
        self._write_num('<Q', size)

    def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
    def read_int8   (self): return self._read_num('<b')
    def read_uint8   (self): return self._read_num('<B')
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

    def get_msg(self):
        buf = self.input 
        self.length = len(self.input)
        self.input = None
        self.write_uint32(self.length)
        return self.input + buf

    def json (self, data):
        pass


class handshake_message (Message):

      def __init__(self, node_id, port):
          super().__init__()
          self.type = HANDSHAKE_MESSAGE
          self.sigtype = 0

          self.network_version = int('0x04b6', 16)
          self.chain_id =  bytes.fromhex(config.CHAIN_ID)
          self.node_id = node_id #hashlib.sha256().digest() # random sha256
          self.key = bytes([0 for n in range(34)])
          self.time = int(time.time() *1000000000)
          self.token = bytes([0 for n in range(32)]) 
          #self.token = hashlib.sha256(self.time).digest()
          pri = get_private_ket_by_wif(config.prvkey)
          privkey = PrivateKey(bytes(pri), raw=True)
          #self.sig,_ = privkey.ecdsa_sign(self.token, raw=True, count=0)
          #self.sig = bytes(self.sig.data)
          self.sig = bytes([0 for n in range(66)])
          self.p2p_address = "fakenode:%d - %s" % (port, self.node_id.hex()[0:7])
          self.p2p_address = self.p2p_address.encode('unicode_escape')
          self.last_irreversible_block_num = config.last_irreversible_block_num
          self.last_irreversible_block_id = bytes.fromhex(config.last_irreversible_block_id)
          self.head_num = config.head_num
          self.head_id = bytes.fromhex(config.head_id)
          self.os = "linux" # linux/osx/win32/other
          self.os = self.os.encode('unicode_escape')
          self.agent = '"Fuck eos"'
          self.agent = self.agent.encode('unicode_escape')
          self.generation = 1

      def serialize(self):
          self.input = b''
          self.write_uint8(self.type)
          #self.write_uint16(self.network_version)
          #self.input += b'04b6'
          self.write_uint16(1206)
          self.input += self.chain_id
          self.input += self.node_id
          self.input += self.key

          logging.debug('hand key %s' % (self.key.hex()))
          logging.debug('hand time %d' % (self.time))
          self.input += self.time.to_bytes(8, byteorder='little')
          self.input += self.token
          logging.debug('hand token %s' % (self.token.hex()))
          #self.write_compact_size(self.sigtype)
          self.input += self.sig
          logging.debug('hand sig %s' % (self.sig.hex()))
          self.write_uint8(len(self.p2p_address))
          self.input += self.p2p_address
          #self.input += bytes([0 for n in range(32 - len(self.p2p_address))]) 
          self.write_uint32(self.last_irreversible_block_num)
          self.input += self.last_irreversible_block_id
          self.write_uint32(self.head_num)
          self.input += self.head_id
          self.write_uint8(len(self.os))
          self.input += self.os
          #self.input += bytes([0 for n in range(32 - len(self.os))]) 
          self.write_uint8(len(self.agent))
          self.input += self.agent
          #self.input += bytes([0 for n in range(32 - len(self.agent))]) 
          self.write_uint16(self.generation)
          #b = self.input 
          #length = len(self.input)
          #self.input  = None
          #self.write_uint32(length)
          #return self.input + b
          return self.get_msg()

      def parse(self, data):
          self.input = data
          self.length = self.read_uint32()
          self.type = self.read_uint8()
          assert self.type == HANDSHAKE_MESSAGE
          self.network_version = self.read_uint16()
          assert self.network_version == 1206

          self.chain_id = self.read(32)
          self.node_id = self.read(32)
          self.key = self.read(34)
          self.time = self.read_uint64()
          self.token = self.read(32)
          self.sig = self.read(66)
          length = self.read_uint8()
          self.p2p_address = self.read(length)
          self.last_irreversible_block_num = self.read_uint32()
          self.last_irreversible_block_id = self.read(32)
          self.head_num = self.read_uint32()
          self.head_id = self.read(32)
          length = self.read_uint8()
          self.os = self.read(length)
          length = self.read_uint8()
          self.agent = self.read(length)
          self.generation = self.read_uint16()

      def json (self):
          r = {}
          r['length'] = self.length
          r['type'] = self.type
          r['network_version'] = self.network_version 
          r['chain_id'] = self.chain_id.hex()
          r['node_id'] = self.node_id.hex()
          r['node_key'] = self.node_id.hex()
          r['time'] = self.time
          r['token'] = self.token.hex()
          r['sig'] = self.sig.hex()
          r['p2p_address'] = self.p2p_address.decode('unicode_escape')
          r['last_irreversible_block_num'] = self.last_irreversible_block_num
          r['last_irreversible_block_id'] = self.last_irreversible_block_id.hex()
          r['head_num'] = self.head_num
          r['head_id'] = self.head_id.hex()
          r['os'] = self.os
          r['agent'] = self.agent
          r['generation'] = self.generation
          return r

class chain_size_message(Message):
      #uint32_t                   last_irreversible_block_num = 0;
      #block_id_type              last_irreversible_block_id;
      #uint32_t                   head_num = 0;
      #block_id_type              head_id;
# 74 '210000000300000000000000000000000000000000cb349fd020534a1580e63d0400000000'
    def __init__(self, host, port):
         super().__init__()
         self.type = CHAIN_SIZE_MESSAGE
         self.last_irreversible_block_num = 0
         self.last_irreversible_block_id = bytes([0 for n in range(32)])
         self.head_num = 1
         self.head_id = bytes([0 for n in range(32)])
 
    def serialize(self):
          self.input = None
          self.write_uint32(self.last_irreversible_block_num)
          self.input += self.last_irreversible_block_id
          self.write_uint32(self.head_num)
          self.input += self.head_id
          b = self.input 
          length = len(self.input)
          self.input  = None
          self.write_uint32(length)
          return self.input + b
 

reason = (
    "no_reason", # no reason to go away
    "self", # the connection is to itself
    "duplicate", # the connection is redundant
    "wrong_chain", # the peer's chain id doesn't match
    "wrong_version", # the peer's network version doesn't match
    "forked", # the peer's irreversible blocks are different
    "unlinkable", # the peer sent a block we couldn't use
    "bad_transaction", # the peer sent a transaction that failed verification
    "validation", # the peer sent a block that failed validation
    "benign_other", # reasons such as a timeout. not fatal but warrant resetting
    "fatal_other", # a catch-all for errors we don't have discriminated
    "authentication" # peer failed authenicatio
)

class go_away_message(Message):
#210000000300000000000000000000000000000000ebd1ae2a37534a1580e63d0400000000
    def __init__(self, node_id):
        super().__init__()
        self.type = CHAIN_SIZE_MESSAGE
        self.reason = 0
        self.node_id = node_id #hashlib.sha256().digest() # random sha256
 
    def serialize(self):
        self.input = None
        self.write_uint32(self.reason)
        self.input += self.node_id
        b = self.input 
        length = len(self.input)
        self.input  = None
        self.write_uint32(length)
        return self.input + b
 
 
 
class time_message(Message):
    def __init__(self):
        super().__init__()
        self.type = TIME_MESSAGE

        self.org = 0#self.time.to_bytes(8, byteorder='little')  #origin timestamp
        #self.time = self.time.to_bytes(8, byteorder='little')
        self.rec = 0 #receive timestamp
        #self.xmt = int(time.time() *1000000000)
        self.xmt = int(calendar.timegm(time.gmtime()) *1000)
        self.dst = 0 #destination timestamp

    def serialize(self):
        self.input = None
        self.write_uint8(self.type)
        self.input += self.org.to_bytes(8, byteorder='little') #transmit timestamp
        self.input += self.rec.to_bytes(8, byteorder='little') #transmit timestamp
        self.input += self.xmt.to_bytes(8, byteorder='little') #transmit timestamp
        self.input += self.dst.to_bytes(8, byteorder='little') #transmit timestamp
        return self.get_msg()

    def parse(self, data):
        self.input = data
        length = self.read_uint32()
        assert length == 33
        msg_type = self.read_uint8()
        assert msg_type == TIME_MESSAGE
        self.org = self.read_uint64()
        self.rec = self.read_uint64()
        self.xmt = self.read_uint64()
        self.dst = self.read_uint64()
        return self
    def json (self):
       r = {}
       r['org'] = self.org
       r['rec'] = self.rec
       r['xmt'] = self.xmt
       r['dst'] = self.dst
       return r
 


class notice_message(Message):
    '13000000040200000032c97900000200000033c9790000'
    def __init__(self):
        super().__init__()
        self.type = NOTICE_MESSAGE
        self.known_trx  = Ids()
        self.known_trx.mode = 2 # last_irr_catch_up
        self.known_trx.pending = config.last_irreversible_block_num 
        self.known_blocks = Ids()
        self.known_blocks.mode = 2 
        self.known_blocks.pending = config.head_num
        self.txids = []
        self.blkids = []

    def serialize(self):
        self.input = None
        self.write_uint8(self.type)
        self.write_uint32(self.known_trx.mode)
        self.write_uint32(self.known_trx.pending)
        self.write_uint8(self.known_trx.ids)
        self.write_uint32(self.known_blocks.mode)
        self.write_uint32(self.known_blocks.pending)
        self.write_uint8(self.known_blocks.ids)
        return self.get_msg()

    def parse(self, data):
        self.input = data
        self.length = self.read_uint32()
        assert self.length == 0x13
        self.type = self.read_uint8()
        assert self.type == NOTICE_MESSAGE
        self.known_trx.mode = self.read_uint32()
        self.known_trx.pending = self.read_uint32()
        self.known_trx.ids = self.read_uint8()
        if self.known_trx.ids > 0:
           length = self.read_uint32()
           txid = self.read(length)
           self.txids.append(txid)  
           logging.debug('request txid:%s' % (txid.hex()))

        self.known_blocks.mode = self.read_uint32()
        self.known_blocks.pending = self.read_uint32()
        self.known_blocks.ids = self.read_uint8()
        if self.known_blocks.ids > 0:
           length = self.read_uint32()
           blkid = self.read(length)
           self.blkids.append(blkid)  
           logging.debug('request blkid:%s' % (blkid.hex()))
        return self

    def json (self):
       r = {}
       r['length'] = self.length
       r['type'] = self.type
       r['known_trx'] = {}
       r['known_trx']['mode'] = self.known_trx.mode
       r['known_trx']['pending'] = self.known_trx.pending
       if self.known_trx.ids > 0 or self.known_trx.mode != 0:
          r['txids'] = self.txids
       r['known_blocks'] = {}
       r['known_blocks']['mode'] = self.known_blocks.mode
       r['known_blocks']['pending'] = self.known_blocks.pending
       if self.known_blocks.ids > 0 or self.known_blocks.mode != 0:
          r['blkids'] = self.blkids
       return r
 
 


class Ids (object):
    def __init__(self):
        #0 none,
        #1 catch_up,
        #2 last_irr_catch_up,
        #3 normal
        self.mode = 0

        self.pending = 0
        self.ids = 0

class request_message(Message):
    '''130000000500000000000000000001000000000000000021000000030089c7941cad4a15bf73ce941cad4a15b275ce941cad4a15655ec2876a550000'''

    def __init__(self):
        super().__init__()
        self.type = REQUEST_MESSAGE

        self.req_trx = Ids()
        self.req_blocks = Ids()
        self.ids = 0
        self.txids = []
        self.blkids = []
 
    def serialize(self):
        self.input = None
        self.write_uint8(self.type)
        self.write_uint32(self.req_trx.mode)
        self.write_uint32(self.req_trx.pending)
        self.write_uint8(self.req_trx.ids)
        self.write_uint32(self.req_blocks.mode)
        self.write_uint32(self.req_blocks.pending)
        self.write_uint8(self.req_blocks.ids)
        return self.get_msg()

    def parse(self, data):
        self.input = data
        self.length = self.read_uint32()
        assert self.length == 0x13
        self.type = self.read_uint8()
        assert self.type == REQUEST_MESSAGE
        self.req_trx.mode = self.read_uint32()
        self.req_trx.pending = self.read_uint32()
        self.req_trx.ids = self.read_uint8()
        if self.req_trx.ids > 0 or self.req_trx.mode != 0:
           length = self.read_uint32()
           txid = self.read(length)
           self.txids.append(txid)  
           logging.debug('request txid:%s' % (txid.hex()))
        self.req_blocks.mode = self.read_uint32()
        self.req_blocks.pending = self.read_uint32()
        self.req_blocks.ids = self.read_uint8()
        if self.req_blocks.ids > 0 or self.req_blocks.mode != 0:
           length = self.read_uint32()
           blkid = self.read(length)
           self.blkids.append(blkid)  
           logging.debug('request blkid:%s' % (blkid.hex()))
        return self

    def json (self):
       r = {}
       r['length'] = self.length
       r['type'] = self.type
       r['req_trx'] = {}
       r['req_trx']['mode'] = self.req_trx.mode
       r['req_trx']['pending'] = self.req_trx.pending
       if self.req_trx.ids > 0 or self.req_trx.mode != 0:
          r['txids'] = self.txids
       r['req_blocks'] = {}
       r['req_blocks']['mode'] = self.req_blocks.mode
       r['req_blocks']['pending'] = self.req_blocks.pending
       if self.req_blocks.ids > 0 or self.req_blocks.mode != 0:
          r['blkids'] = self.blkids
       return r
 
 

class sync_request_message(Message):
    '09000000060100000064000000'
    def __init__(self):
        super().__init__()
        self.type = SYNC_REQUEST_MESSAGE

        self.start_block = 0
        self.end_block = 0
    def serialize(self):
        self.input = None
        self.write_uint8(self.type)
        self.write_uint32(self.start_block)
        self.write_uint32(self.end_block)
        return self.get_msg()

    def parse(self, data):
        self.input = data
        self.length = self.read_uint32()
        assert self.length == 0x09
        self.type = self.read_uint8()
        assert self.type == SYNC_REQUEST_MESSAGE
        self.start_block = self.read_uint32()
        self.end_block = self.read_uint32()
        return self

    def json (self):
       r = {}
       r['length'] = self.length
       r['type'] = self.type
       r['start_block'] = self.start_block
       r['end_block'] = self.end_block
       return r
 
 
class Transaction (object):
    def __init__(self):
      # executed  = 0 soft_fail = 1 hard_fail = 2 delayed   = 3 expired   = 4 
      self.status = 0
      self.cpu_usage_us    = 0
      self.net_usage_words = 0

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
      self.chain_id = config.CHAIN_ID


class signed_block_message(Message):
    'b90000000780e347450000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000cf057bbfb72640471fd910bcb67639c22df9f92470936cddc1ade0e2f2e7dc4f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    def __init__(self):
        super().__init__()
        self.type = SIGNED_BLOCK

        self.timestamp = 0
        self.producer = 0
        self.confirmed = 1 #uInt16
        self.previous = 0
        self.transaction_mroot = 0
        self.action_mroot = 0
        self.schedule_version = 0
        self.new_producers = ''
        self.header_extensions = ''
        self.transactions_num = 0
        self.transactions = []
        self.input = None
        self.data = ""
 
    def serialize(self):
        pass

    def parse(self, data):
        self.input = data
        self.length = self.read_uint32()
        self.type = self.read_uint8()
        assert self.type == SIGNED_BLOCK
        self.timestamp = self.read_uint32()
        self.producer = self.read(8)
        self.confirmed = self.read_uint16()
        self.previous = self.read(32)
        self.transaction_mroot = self.read(32)
        self.action_mroot = self.read(32)
        self.schedule_version = self.read_uint32()
        self.new_producers = self.read_packed_uint32() 
        self.header_extensions = self.read_packed_uint32()
        self.producer_signature = self.read(66)
        self.transactions_num = self.read_packed_uint32()
        #if self.timestamp==1166825299:
        #   print (self.timestamp)
        return 
        for i in range(self.transactions_num):
           tx = Transaction()
           tx.status =  self.read_uint8()
           tx.cpu_usage_us    = self.read_uint32()
           val = self.read_uint32()
           tx.net_usage_words = self.read_packed_uint32()
           tx.packedtr_count = self.read_uint8()
           tx.packedtr_type = self.read_uint16()
           tx.packedtx_sign = self.read(66)
           #tx.packedtx_compression = self.read_uint8()
           #tx.packedtx_compression_unkown = self.read_uint16()
           import zlib
           if  data[self.read_cursor:][:2].hex() == '78da': 
               data = zlib.decompress(self.input[self.read_cursor:])
               self.input = data
               self.read_cursor = 0
           #tx.packed_context_free_data_len = self.read_uint8()
           #tx.packed_context_free_data = self.read_uint8()
           #tx.packed_trx = self.read_uint8()
           tx.expiration = self.read_uint32()
           tx.ref_block_num = self.read_uint16()
           tx.ref_block_prefix = self.read_uint32()
           tx.max_net_usage_words = self.read_packed_uint32()
           tx.max_kcpu_usage = self.read_packed_uint32()
           tx.delay_sec = self.read_packed_uint32()

           tx.context_free_actions_count = self.read_packed_uint32()
           for i in range(tx.context_free_actions_count): 
                action = {}
                action['account'] = self.read_uint64()
                action['name'] = self.read_uint64()
                action_permission_count = self.read_packed_uint32()
                for j in range(action_permission_count):
                    permission = {}
                    permission['actor'] = self.read_uint64()
                    permission['permission'] = self.read_uint64()
                length = self.read_packed_uint32()
                action["data"] = self.read(length)

           tx.actions_count = self.read_packed_uint32()
           tx.actions = []
           for i in range(tx.actions_count): 
                action = {}
                action['account'] = self.read_uint64()
                action['name'] = self.read_uint64()
                action_permission_count = self.read_packed_uint32()
                for j in range(action_permission_count):
                    permission = {}
                    permission['actor'] = self.read_uint64()
                    permission['permission'] = self.read_uint64()
                length = self.read_packed_uint32()
                action["data"] = self.read(length)
           #transaction_extensions_count = self.read_packed_uint32()
           #if transaction_extensions_count > 0:
        #block_extensions_count = self.read_packed_uint32()
        #if block_extensions_count > 0:
        #      import pdb;pdb.set_trace()


    def json (self):
        r = {}
        r['length'] = self.length
        r['type'] = self.type
        r['timestamp'] = self.timestamp
        r['producer']= self.producer.hex()
        r['confirmed'] = self.confirmed
        r['previous']= self.previous.hex()
        r['transaction_mroot ']= self.transaction_mroot.hex() 
        r['action_mroot ']= self.action_mroot.hex()
        r['schedule_version']= self.schedule_version
        r['new_producers ']= self.new_producers
        r['producer_signature']= self.producer_signature.hex()
        r['transactions_num']= self.transactions_num
        r['transactions']= self.transactions
        for tx in self.transactions:
            tx = {}
            #status = 0
            #cpu_usage_us    = 0
            #net_usage_words = 0
        return r

class packed_transaction_message(Message):
    def __init__(self):
        super().__init__()
        self.type = PACKED_TRANSACTION

        self.signatures = None
        self.compression = 0 # 0: none, 1 compress
        self.packed_context_free_data = []
        self.packed_trx = None

    def serialize(self):
        pass

    def json (self):
        r = {}
        r['signatures'] = self.length
        r['compression'] = self.compression
        r['packed_context_free_data']= self.packed_context_free_data
        r['packed_trx']= self.packed_trx
        return r
 
