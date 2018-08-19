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
from config import VERSION
import config
from .peer import Peer
from pyeos.utils import string_to_name, int_from_bytes
from .message import *

peers = []

blocks_idx = {} # {id: hash}
blocks = {} # {hash: blk_data}
 
class Node(object):
    def __init__(self, node_id=None, db=None):
        self.version = VERSION

        self.db = db

        self.code = config.code
        self.chain_id = config.CHAIN_ID

        # time
        self.org = 0
        self.rec = 0
        self.dst = 0
        self.xmt = int(time.time() *1000000000)

        self.head_num = config.head_num
        self.head_id = config.head_id
        self.last_irreversible_block_num = config.last_irreversible_block_num
        self.last_irreversible_block_id = config.last_irreversible_block_id

        self.request_start_height = 0
        self.request_end_height = 0
        self.sync_height = 0

        self.network_head_num = config.head_num 
        self.network_last_irreversible_block_num = config.last_irreversible_block_num

        if config.storage == 'leveldb':
            self.head_num = self.db.read_last_head()
            if self.head_num is None:
                self.head_num = config.head_num
            else:
                self.head_num = int_from_bytes(self.head_num)
                self.head_id = self.db.read_hash(self.head_num + 1) 

            self.last_irreversible_block_num = self.db.read_last_irr()
            if self.last_irreversible_block_num is None:
                self.last_irreversible_block_num = config.last_irreversible_block_num
            else:
                self.last_irreversible_block_num = int_from_bytes(self.last_irreversible_block_num)
                slast_irreversible_block_id = self.db.read_hash(self.last_irreversible_block_num + 1)

        self.request_num = 100

        self.peer = Peer()
 
        if node_id == None:
            self.node_id = hashlib.sha256().digest()
        else:
            self.node_id = node_id

        self.blocks = [0]* 1000000

        # network
        self.last_handcount = 0

        self.port = 9999
        self.ip = '127.0.0.1'

        self.buf = None

    def send_time_msg(self):
        send_msg = time_message()
        send_msg.xmt = int(calendar.timegm(time.gmtime()) *1000)
        send_msg.rec = self.rec
        send_msg.dst = self.dst
        send_msg.org = self.org
        data = send_msg.serialize()
        self.send_msg(data)
        logging.debug('send time msg: %s' % (data.hex()))

    def send_notice_msg(self):
        send_msg = notice_message()
        send_msg.head_num = self.head_num
        send_msg.head_id = self.head_id
        send_msg.last_irreversible_block_num = self.last_irreversible_block_num
        send_msg.last_irreversible_block_id = self.last_irreversible_block_id
        self.send_msg(send_msg.serialize())

    def send_sync_request_msg(self):
        if self.network_last_irreversible_block_num <= (self.head_num + 100):
            return

        send_msg = sync_request_message()
        send_msg.start_block = self.head_num + 1
        send_msg.end_block = self.head_num + self.request_num
        self.send_msg(send_msg.serialize())

        self.request_start_height =  self.head_num + 1 
        self.request_end_height = self.head_num + 101

    def send_handshake_msg(self):
        handshake = handshake_message(self.node_id, self.port)
        hm = handshake.serialize()
        logging.info('send handsake msg: %s' % handshake.json())
        self.send_msg(hm)

    def send_packet_transaction_msg(self):
        send_msg = packed_transaction_message()
        tx = Tx()
        signature = prv.sign(tx.get_digest())
        send_msg.signatures  = signature 
        send_msg.packed_trx = packed_trx

        logging.info('send handsake msg: %s' % send_msg)
        self.send_msg(send_msg.serialize())
 
    def handle_handshake_msg (self, data):
        recv_msg = handshake_message(self.node_id, self.port)
        recv_msg.parse(data) 
        logging.info('RECV handshake msg: %s' % recv_msg.json())

        self.peer.connected = True
        self.peer.head_num = recv_msg.head_num  
        self.peer.head_id = recv_msg.head_id
        self.peer.last_irreversible_block_num = recv_msg.last_irreversible_block_num
        self.peer.last_irreversible_block_id = recv_msg.last_irreversible_block_id

        if self.network_head_num <  recv_msg.head_num:  
            self.network_head_num =   recv_msg.head_num
        if self.network_last_irreversible_block_num < recv_msg.last_irreversible_block_num: 
            self.network_last_irreversible_block_num = recv_msg.last_irreversible_block_num  
            self.send_sync_request_msg()
        else:
            self.send_notice_msg()

    def handle_request_msg(self, data):
        recv_msg = request_message().parse(data) 
        logging.info('RECV request msg: %s' % recv_msg.json())

    def handle_sync_request_msg(self, data):
        recv_msg = sync_request_message().parse(data) 
        if recv_msg.start_block == 0 and recv_msg.end_block == 0:
            logging.debug('RECV cancel sync request msg: %s' % recv_msg.json())
        else:
            logging.debug('RECV sync request msg: %s' % recv_msg.json())
        assert recv_msg.start_block <= recv_msg.end_block
        for blknum in range(recv_msg.start_block, recv_msg.end_block, 1):
            blkhash = self.db.get_hash(blknum+1)
            blkdata = self.db.read_block(blknum)
            self.socket.send(blkdata)

    def handle_signed_block_msg(self, data):
        recv_msg = signed_block_message()
        recv_msg.parse(data) 
        logging.debug('RECV signed block msg: %s' % recv_msg.json())

        blknum = int.from_bytes(recv_msg.previous[0:4], byteorder='big') + 1
        if blknum < self.head_num:
            if self.db.blk_indb(blknum):
                blkdata = data[5:]
                self.db.save_blk(blknum, recv_msg.previous, blkdata)
                logging.debug('RECV old signed block msg')
            else:
                logging.warning('RECV duplicate signed block msg')
            return 

        blkdata = data[5:]
        self.db.save_blk(blknum, recv_msg.previous, blkdata)

        logging.debug('Received block %s #%d' % (recv_msg.previous.hex(), blknum))

        if self.head_num < self.network_last_irreversible_block_num:
           self.last_irreversible_block_num = blknum - 1  
           self.last_irreversible_block_id = recv_msg.previous 

        self.sync_height = blknum + 1
        if self.sync_height == self.request_end_height:
            self.head_num = blknum - 1 
            self.head_id = recv_msg.previous
            self.send_sync_request_msg()
            self.db.write_last_head(self.head_num)
            self.db.write_last_irr(self.last_irreversible_block_num)


    def handle_notice_msg(self, data):
        recv_msg = notice_message().parse(data) 
        logging.info('RECV notice msg: %s' % recv_msg.json())

        if self.network_head_num < recv_msg.known_blocks.pending:
            self.network_head_num = recv_msg.known_blocks.pending
        if self.network_last_irreversible_block_num < recv_msg.known_trx.pending:
            self.network_last_irreversible_block_num = recv_msg.known_trx.pending

    def handle_time_msg(self, data):
        recv_msg = time_message() 
        recv_msg = recv_msg.parse(data) 
        logging.debug('recv time msg: %s' % recv_msg.json())

        if recv_msg.xmt == 0:
           return                # invalid timestamp

        if recv_msg.xmt == self.xmt:
           return               # duplicate packet

        self.xmt = recv_msg.xmt
        self.rec = recv_msg.rec
        self.dst = recv_msg.dst

        if recv_msg.org == 0:
            self.send_time_msg()
            return

        self.offset = (float(self.rec - self.org) + float(recv_msg.xmt - self.dst)) / 2

        logging.debug('Clock offset is {}ns ({}us)'.format(self.offset, self.offset/1000))
        self.org = 0
        self.rec = 0 
 
    def handle_read(self, sock):
        """read data"""
        data = sock.recv(40960)
        if self.buf is not None:
           self.buf += data
           data = self.buf

        if len(data) > 0:
            data_len = len(data)
            msg_len = struct.unpack_from('<I', data[:4])[0] + 4
            while data_len >= msg_len:
                msgdata = data[:msg_len]
                msg_type = int(msgdata[4])
                if msg_type == HANDSHAKE_MESSAGE: 
                    logging.debug('Recv Handshake msg: %s:' % (binascii.hexlify(msgdata)))
                    self.handle_handshake_msg (msgdata)
                elif msg_type == CHAIN_SIZE_MESSAGE: 
                    logging.debug('Recv CHAIN_SIZE msg: %s:' % (binascii.hexlify(msgdata)))
                elif msg_type == GO_AWAY_MESSAGE: 
                    logging.debug('Recv GOAWAY msg: %s:' % (binascii.hexlify(msgdata)))
                    rs = msgdata[5]
                    if rs < len(reason):
                       logging.debug('Recv Goaway reason: %s:' % reason[rs])
                elif msg_type == TIME_MESSAGE: 
                    logging.debug('Recv TIME_MESSAGE msg: %s:' % (binascii.hexlify(msgdata)))
                    self.handle_time_msg(msgdata)
                elif msg_type == NOTICE_MESSAGE: 
                    logging.debug('Recv NOTICE msg: %s:' % (binascii.hexlify(msgdata)))
                    self.handle_notice_msg(msgdata)
                elif msg_type == REQUEST_MESSAGE: 
                    logging.debug('Recv REQUEST msg: %s:' % (binascii.hexlify(msgdata)))
                    self.handle_request_msg(msgdata)
                elif msg_type == SYNC_REQUEST_MESSAGE: 
                    logging.debug('Recv REQUEST msg: %s:' % (binascii.hexlify(msgdata)))
                    self.handle_sync_request_msg(msgdata)
                elif msg_type == SIGNED_BLOCK: 
                       logging.debug('Recv SIGNED_BLOCK msg: %s:' % (binascii.hexlify(msgdata)))
                       self.handle_signed_block_msg(msgdata)
                elif msg_type == PACKED_TRANSACTION: 
                    logging.debug('Recv PACKED_TRANSACTION msg: %s:' % (binascii.hexlify(msgdata)))
                else:
                    logging.error('Recv Unknown net msg: %s:' % (binascii.hexlify(msgdata)))

                data_len -= msg_len
                if data_len < 4:
                    break
                data = data[msg_len:]
                msg_len = struct.unpack_from('<I', data[:4])[0] + 4

            if data_len >0:
               self.buf = data
            elif data_len == 0:
               self.buf = None
            else:
               raise Exception('unknow handle exception')

            self.rxbuf.append(data)
            return data
                        
class Client(Node):
    def __init__(self, host, port, node_id=None, db=None):
        super().__init__(node_id, db)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rxbuf = collections.deque(maxlen=10000)
        self.running = False
        try:
            self.socket.connect( (host, port) )
            self.peer.connected = False
            self.peer.socket = self.socket
            self.peer.ip = host
            self.peer.port = port
            peers.append(self.peer)
            self.running = True
            logging.debug('connect to node %s:%s' % (host, port))
        except:
            self.running = False
            raise
            pass

    def handle_close(self):
        self.close()

    def send_msg(self, msg):
        self.socket.send(msg)

    def loop(self):
        while True:
          if not self.running:
            continue
          data = self.handle_read(self.socket)


class Server(Node):
    def __init__(self, ip=None, port=9999, node_id=None, db=None):
        super().__init__(node_id, db)

        #self.bind_ip = ip
        self.bind_ip = "0.0.0.0"
        self.port = port
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.bind_ip, int(self.port)))
        self.socket.listen(5)
        print ("server start run %s:%s" % (self.bind_ip, self.port))
        self.rxbuf = collections.deque(maxlen=4096)
        self.cur_conn = None

    def get_ip(self, ifname='enp0s31f6'):
        if sys.platform == 'win32' or sys.platform == 'cygwin':
            return socket.gethostbyname(socket.gethostname())
        mod_name = 'fcntl'
        mod_obj = __import__(mod_name)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(mod_obj.ioctl(s.fileno(),0x8915,  # SIOCGIFADDR
                      struct.pack('256s', ifname[:15].encode('unicode_escape'))
                      )[20:24])
 
    def handle_accept(self):
        pair = self.socket.accept()
        if pair is None:
            return
        else:
            sock, addr = pair
            self.cur_conn = (pair)
            print('Incoming connection from %s' % repr(addr))
            self.send_handshake_msg()

    def handle_expt():
        raise

    def handle_error():
        raise

    def handle_close(self):
        self.close()

    def handle_connect(self):
        return True

    def handle_write(self):
        self.send_time_msg()

    def send_msg(self, msg):
        self.cur_conn.send(msg)

    def loop(self):
        self.cur_conn, addr = self.socket.accept()
        logging.info('Incoming connection from %s' % repr(addr))
        self.send_handshake_msg()
        self.send_notice_msg()
        while True:
           self.handle_read(self.cur_conn)
